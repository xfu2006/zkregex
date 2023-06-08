/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/25/2022
	Revised: 07/29/2022: Add dis_matrix_to_qap
	Revised: 08/02/2022: Add dis_compute_h
	Revised: 10/24/2022: Add fast rand_inst function
	Revised: 03/06/2023: Add to_qap_witness_no_h()
*/

/// Distributed R1CS.
/// Basic idea: each node stores a NUMBER of constraints (can vary).
/// i.e., we distribute data by ROWs. This module provides
/// conversion from Distributed R1CS to and from serial R1CS.
/// It also provides functions to convert r1cs to QAP and generate
/// the QAP witness from a full variable assignment.
///
/// Performance: 1M:  (8 nodes on one computer).
/// from_serial: 0.7 sec, to_serial: 1.36 sec (but explodes up quickly) 

extern crate ark_ff;
extern crate ark_serialize;
extern crate ark_std;
extern crate ark_ec;
extern crate ark_poly;
extern crate mpi;

use self::ark_ff::{PrimeField};
use self::mpi::traits::*;
use self::mpi::topology::Communicator;
use self::ark_std::rand::Rng;
use self::ark_std::rand::rngs::StdRng;
use std::collections::HashMap;
use std::fs::File;
//use std::iter::FromIterator;


use r1cs::serial_r1cs::*;
use groth16::new_dis_qap::*;
use crate::profiler::config::*;
use poly::dis_vec::*;
//use poly::serial::*;
use poly::disfft::*;
use poly::common::*;
use tools::*;

use std::collections::HashSet;

/*
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;

use std::any::Any;
use std::rc::Rc;

use proto::*;
use poly::dis_poly::*;
//use poly::dis_key::*;
use poly::serial::*;
*/

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// distributed R1CS constraint system
/// ALL nodes has the IDENTICAL information of num_vars etc.
/// Each node has a share of constraints (e.g., if 
/// there are 100 constriants and 10 nodes, each node stores 10 constraints,
/// however, each node may stores a varied number of constraints).
/// the information is contained in vec_num_constraints.
/// The main node is 0 always (it seems no need to distribute to other nodes).
/// Most of data attributes are similar to serial R1CS
/// the "share" attribute stores the "share" of constraints
pub struct DisR1CS<F:PrimeField>{
	/// share of node of matrix A. 
	pub a_share: Vec<Vec<LinearTerm<F>>>,
	/// share of node of matrix B 
	pub b_share: Vec<Vec<LinearTerm<F>>>,
	/// share of node of matrix C 
	pub c_share: Vec<Vec<LinearTerm<F>>>,

	/// number of variables (NOT including constant 1 as var_0)
	pub num_vars: usize,
	/// number of constraints (TOTAL of the entire distributed R1CS)
	pub num_constraints: usize,
	/// the number of constraints at each node
	pub vec_num_constraints: Vec<usize>,
	/// number of public i/o vars. num_witness is num_vars - num_io
	pub num_io: usize,
	/// number of segments of witness inputs
	pub num_segs: usize,
	/// size of segments (sum of them should be num_witness = num_vars - num_io)
	pub seg_size: Vec<usize>,
	/// if constraints are evenly distributed
	pub even: bool
} 

impl <F:PrimeField> DisR1CS<F>{
	/// constructor
	pub fn new(
		a_share: Vec<Vec<LinearTerm<F>>>,
		b_share: Vec<Vec<LinearTerm<F>>>,
		c_share: Vec<Vec<LinearTerm<F>>>,
		num_vars: usize,
		num_constraints: usize,
		vec_num_constraints: Vec<usize>,
		num_io: usize,
		num_segs: usize,
		seg_size: Vec<usize>,
		b_even: bool) -> DisR1CS<F>{
		return DisR1CS{
			a_share: a_share,
			b_share: b_share,
			c_share: c_share,
			num_vars: num_vars,
			num_constraints: num_constraints,
			vec_num_constraints: vec_num_constraints,
			num_io: num_io,
			num_segs: num_segs,
			seg_size: seg_size,
			even: b_even,
		};
	}

	/// collect the var_idx for all the linear terms in the vec
	/// the info is sorted for each node, i.e., vec_set[i] 
	/// is a hashset of var_idx needed from node i.
	fn collect_for_vec_terms(terms: &Vec<Vec<LinearTerm<F>>>, vec_set: &mut Vec<HashSet<usize>>, num_vars: usize){
		let np = RUN_CONFIG.n_proc as usize;
		let me = RUN_CONFIG.my_rank as usize;
		let unit = (num_vars + 1)/np;
		let nlen = terms.len();
		for i in 0..nlen{
			let row = &terms[i];
			let rlen = row.len();
			for j in 0..rlen{ 
				let vidx = row[j].index;
				let node_id = if vidx>=unit*np {np-1} else {vidx/unit};
				if node_id != me{
					vec_set[node_id].insert(vidx);
				}
			}
		}
	}

	/// collect the var_idx needed from each node
	/// for itself, leave an empty vec
	fn collect_var_idx_needed(a_share: &Vec<Vec<LinearTerm<F>>>, b_share: &Vec<Vec<LinearTerm<F>>>, c_share: &Vec<Vec<LinearTerm<F>>>, num_vars: usize ) -> Vec<Vec<usize>>{
		let np = RUN_CONFIG.n_proc as usize;
		let mut vec_set = vec![HashSet::<usize>::new(); np];
		for i in 0..np{ vec_set[i] = HashSet::<usize>::new(); }
		Self::collect_for_vec_terms(a_share, &mut vec_set, num_vars);
		Self::collect_for_vec_terms(b_share, &mut vec_set, num_vars);
		Self::collect_for_vec_terms(c_share, &mut vec_set, num_vars);

		let mut vec_res = vec![vec![0usize; 1]; np];
		for i in 0..np{
			vec_res[i] = vec_set[i].clone().into_iter().collect();
		}
		return vec_res;
	}

	/// exchange the variables needed by all nodes
	/// this function should be called by each node
	/// it returns a hashmap of variable values for the
	/// EXTRA variables needed by each node
	fn exchange_var_data(a: &Vec<Vec<LinearTerm<F>>>, b: &Vec<Vec<LinearTerm<F>>>, c: &Vec<Vec<LinearTerm<F>>>, myvars: &Vec<F>, num_vars: usize) -> HashMap<usize, F>{
		let mut hs = HashMap::<usize, F>::new();
		let me = RUN_CONFIG.my_rank as usize;
		let np = RUN_CONFIG.n_proc as usize;
		let univ = &RUN_CONFIG.univ;

		//1. exchange the set of vars needed
		let v_needed = Self::collect_var_idx_needed(a, b, c, num_vars);
		let v_needed_by_peers = nonblock_broadcast(&v_needed, np as u64, 
			univ, 0usize);  

		//2. exchange the values needed
		let my_start = (num_vars+1)/np * me;
		let mut v_vals = vec![];
		for i in 0..np{
			let mut row = vec![];
			let need_row = &v_needed_by_peers[i];
			for j in 0..need_row.len(){
				let vidx = need_row[j] - my_start;
				let val = myvars[vidx]; 
				row.push(val);
			}
			v_vals.push(row);
		}
		let v_my_need = nonblock_broadcast(&v_vals, np as u64, univ, F::zero());

		//3. build up my need
		for i in 0..np{
			if i!=me{
				let row = &v_my_need[i];
				let idx_row = &v_needed[i];
				for j in 0..row.len(){
					let idx = idx_row[j];
					let val = row[j];
					hs.insert(idx, val);
				}
			}
		}
		
		return hs;
	}

	/// evaluate a matrix row using variable assignment
	/// Sum^n_{i=0} vars[row[i].var] * row[i].value
	/// the map contains the values of variables whose idx falls
	/// out of range of loal variable segment.
	pub fn eval(row: &Vec<LinearTerm<F>>, vars: &DisVec<F>, map: &HashMap<usize,F>)->F{
		//1. compute the local result
		assert!(vars.b_in_cluster, "call partition() first on vars!");
		let me = RUN_CONFIG.my_rank as usize;
		let mut sum = F::zero();
		let (me_start, me_end) = vars.get_share_bounds_usize(me);
		for term in row{
			let var_idx = term.index;
			let coef = term.value;
			let var_val = if var_idx>=me_start && var_idx<me_end{
				vars.partition[var_idx-me_start]
			}else{ *map.get(&var_idx).unwrap() };
			sum += var_val * coef;
		} 

		return sum;
	}

	/// eval with extra hashmap of vars not in partition
	pub fn dis_eval_matrix_2(mat: &Vec<Vec<LinearTerm<F>>>,
		num_cons: usize, vars: &DisVec<F>, extra_vars: &HashMap<usize,F>) 
	-> DisVec<F>{
		//1. get stats
		let n = mat.len(); //local partition of constraints size
		let mut vres = vec![F::zero(); n];
	
		//2. for number of constraintsvar chunks
		for i in 0..n{
			vres[i] = Self::eval(&mat[i], vars, extra_vars);
		}//end for chunk
	
		//3. build data and return
		let res = DisVec::<F>::new_from_each_node(0u64, 0u64, num_cons, vres);  
		RUN_CONFIG.better_barrier("dis_r1cs::matrix_eval");
		return res;
	}

	/// return true if the instance is valid
	/// this function has to be called at ALL NODES
	/// only return the valid result at MAIN NODE 0
	pub fn is_satisfied(&self, vars: &DisVec<F>)->bool{
		//0. collect and exchane data
		let extra_vars = Self::exchange_var_data(&self.a_share, &self.b_share, &self.c_share, &vars.partition, self.num_vars);

		//1. get the local result
		let me = RUN_CONFIG.my_rank as usize;
		let np = RUN_CONFIG.n_proc as usize;
		let mut bres = true;
		if vars.len!=self.num_vars+1{panic!("vars.len(): {}!=self.num_vars+1: {}", vars.len, self.num_vars+1);}
		let num_constraints = if me==np-1 {self.num_constraints/np + self.num_constraints%np} else {self.num_constraints/np};
		for i in 0..num_constraints{
			// compute sum_j vars[a[i][j].var] * a[i][j].value
			let sum_a = Self::eval(&self.a_share[i], &vars, &extra_vars);
			let sum_b = Self::eval(&self.b_share[i], &vars, &extra_vars);
			let sum_c = Self::eval(&self.c_share[i], &vars, &extra_vars);
			if sum_c != sum_a*sum_b{
				bres = false;
			}
		}

		//2. create a temp dis_vec of field
		let vec = if !bres {vec![F::from(1u64)]} else {vec![F::zero()]};
		let dis_vec = DisVec::<F>::new_from_each_node(0u64, 0u64, np, vec);
		let real_len = dis_vec.get_real_len(); 
		let bsat = real_len == 0; //no one response false
		//2. all nodes send result to MAIN node 0
		return bsat;
	}

	/// Generate a distributed R1CS instance and a distributed variable
	/// assignment. NOTE: the generated size must be less than 2^30
	/// for testing purpose.
	/// This function NEEDS TO BE called at all nodes, and all nodes
	/// get the correct instance of DisR1cs and DisVec.
	/// NOTE: the instance will follow locality (bLocality is set)
	pub fn rand_inst(seed: u128, num_vars: usize, num_constraints: usize, bsat: bool) -> (DisR1CS<F>, DisVec<F>){
		//return Self::slow_rand_inst(seed, num_vars, num_constraints, bsat);
		return Self::fast_rand_inst(seed, num_vars, num_constraints, bsat);
	}

	/// Generate a distributed R1CS instance and a distributed variable
	/// assignment. NOTE: the generated size must be less than 2^30
	/// for testing purpose.
	/// This function NEEDS TO BE called at all nodes, and all nodes
	/// get the correct instance of DisR1cs and DisVec.
	/// WARNING SLOW: essentially a wrapper of serial_r1cs::rand_inst
	/// running at all nodes and cut the shares at each node.
	pub fn slow_rand_inst(seed: u128, num_vars: usize, num_constraints: usize, bsat: bool) -> (DisR1CS<F>, DisVec<F>){
		//1. check input
		let limit: usize = 2*1024*1024*1024;
		if num_vars>limit || num_constraints>limit{
			panic!("rand_inst can't handle size >2G");
		}

		//2. generate a big serial random instance (SAME at all nodes)
		let (r1cs, vars) = R1CS::<F>::rand_inst(seed, num_vars, num_constraints, bsat);

		//3. generate a random vec_constraints
		let np = RUN_CONFIG.n_proc as usize;
		let me = RUN_CONFIG.my_rank as usize;
		let mut rng = gen_rng_from_seed(seed+100);
		let vec_num_constraints = rand_vec_num_constraints(&mut rng, num_constraints, np); 

		//4. get the current share of the current node
		let (start, end) = get_share(&vec_num_constraints, me);
		let a_share = r1cs.a[start..end].to_vec();
		let b_share = r1cs.b[start..end].to_vec();
		let c_share = r1cs.c[start..end].to_vec();

		//5. create the DisR1CS instance
		let dis_r1cs = DisR1CS::<F>::new(
			a_share, b_share, c_share, num_vars, num_constraints,
			vec_num_constraints, r1cs.num_io, r1cs.num_segs, 
			r1cs.seg_size.clone(), false);

		//6. create the DisVec of variable assignment 
		let dis_vars = DisVec::<F>::new_dis_vec(vars);
		RUN_CONFIG.better_barrier("DisR1CS rand_inst"); 
		return (dis_r1cs, dis_vars);
	}

	/// FAST: Generate a distributed R1CS instance and a distributed variable
	/// assignment. 
	/// This function NEEDS TO BE called at all nodes, and all nodes
	/// get the correct instance of DisR1cs and DisVec.
	///
	/// Basic idea: just generate A, B, C rows as usual (like serial R1CS)
	/// each node has the same number of columns, but are responsible
	/// for different rows
	pub fn fast_rand_inst(seed: u128, num_vars: usize, num_constraints_inp: usize, bsat: bool) -> (DisR1CS<F>, DisVec<F>){
		//1. generate a random vec_constraints
		let np = RUN_CONFIG.n_proc as usize;
		let me = RUN_CONFIG.my_rank as usize;
		let mut rng = gen_rng_from_seed(seed);
		let num_constraints = closest_pow2(num_constraints_inp);
		let vars_part_len = if me<np-1  {(num_vars+1)/np} else {(num_vars+1)/np + (num_vars+1)%np}; 
		let mut vars_part= vec![F::zero(); vars_part_len];
		for i in 0..vars_part_len{ vars_part[i] = F::rand(&mut rng); }
		if me==0 {vars_part[0] = F::from(1u64)};
		let dis_vars= DisVec::<F>::new_from_each_node(0u64, 0u64, num_vars+1, vars_part.clone());
		let seg = dis_vars.get_share_bounds_usize(me);

		//2. generate a,b,c shares - missing last item for C
		let mut a:Vec<Vec<LinearTerm<F>>> = vec![];
		let mut b:Vec<Vec<LinearTerm<F>>> = vec![];
		let mut c:Vec<Vec<LinearTerm<F>>> = vec![];
		let my_num_constraints = if me<np-1 {num_constraints/np} else
			{num_constraints/np + num_constraints%np};
		let offset = if my_num_constraints<4 {0} else {4};	
		for i in 0..my_num_constraints{//divide by rows between nodes
			//2.1 create random A, B, C
			let (row_a, row_b, row_c);
			if i<my_num_constraints-offset{//most of them are in range
				row_a = rand_row_worker::<F>(3, num_vars, &mut rng, seg, true);
				row_b = rand_row_worker::<F>(3, num_vars, &mut rng, seg, true);
				row_c = rand_row_worker::<F>(3, num_vars-1, &mut rng, seg, true);
			}else{
				row_a = rand_row::<F>(3, num_vars, &mut rng);
				row_b = rand_row::<F>(3, num_vars, &mut rng);
				row_c = rand_row::<F>(3, num_vars-1, &mut rng);
			}

			//2.2 add to matrix A, B, C
			a.push(row_a);
			b.push(row_b);
			c.push(row_c);
		}
		let extra_vars = Self::exchange_var_data(&a, &b, &c, &dis_vars.partition, num_vars);

		//3. modify each row_c
		for i in 0..my_num_constraints{//divide by rows between nodes
			//2.2. evaluate sumA, sumB, sumC
			let row_a = &a[i];
			let row_b = &b[i];
			let row_c = &c[i];
			let sum_a = Self::eval(row_a, &dis_vars, &extra_vars);
			let sum_b = Self::eval(row_b, &dis_vars, &extra_vars);
			let sum_c = Self::eval(row_c, &dis_vars, &extra_vars);

			//2.3 calculate the last value of  
			//let diff_val = sum_a * sum_b - sum_c +F::from(1u64);
			let diff_val = sum_a * sum_b - sum_c;
			let last_val = vars_part[vars_part_len-1];
			let c_coef = if bsat {diff_val / last_val} 
				else {diff_val/last_val + F::from(1u64)};			
			let c_term = LinearTerm::<F>{index: seg.0 + vars_part_len-1, value: c_coef};
			c[i].push(c_term);

		}

		let mut vec_num_constraints = vec![num_constraints/np; np];
		let vlen = vec_num_constraints.len();
		vec_num_constraints[vlen-1] += num_constraints%np;

		//3. assemble
		RUN_CONFIG.better_barrier("DisR1CS rand_inst"); 
		//let dis_r1cs = DisR1CS::<F>::new(a, b, c, num_vars, num_constraints, vec_num_constraints, 2, 3, vec![num_vars-6, 2, 2], true); 
		let dis_r1cs = DisR1CS::<F>::new(a, b, c, num_vars, num_constraints, vec_num_constraints, 2, 3, vec![num_vars-8, 2, 4], true); 
		return (dis_r1cs, dis_vars);
	}


	/// convert a serial r1cs instance to distributed R1CS.
	/// Evenly distribute the share
	/// Assumption: ALL nodes get the same sr1cs instance.
	pub fn from_serial(sr1cs: &R1CS<F>) -> DisR1CS<F>{
		//1. build the share (evenly distribute the constraints)
		let n = sr1cs.num_constraints;
		let np = RUN_CONFIG.n_proc as usize;
		let mut vec_num_constraints = vec![0usize; np];
		let mut a = 0;
		for i in 0..np{
			vec_num_constraints[i] = if i<np-1 {n/np} else {n - (np-1)*n/np};
			if i<RUN_CONFIG.my_rank as usize{
				a += vec_num_constraints[i];
			}
		}
		let b = a + vec_num_constraints[RUN_CONFIG.my_rank as usize];
		let a_share = sr1cs.a[a..b].to_vec();
		let b_share = sr1cs.b[a..b].to_vec();
		let c_share = sr1cs.c[a..b].to_vec();
			
		//2. build the obj
		let r1cs = Self::new(a_share, b_share, c_share, sr1cs.num_vars,
			sr1cs.num_constraints, vec_num_constraints,
			sr1cs.num_io, sr1cs.num_segs, 
			sr1cs.seg_size.clone(), true); //already evenly distributed
		RUN_CONFIG.better_barrier("from_serial");
		return r1cs;
	}

	/// evenly distribute the shares (re-send between peers)
	/// need to be called at each node
	/// sometimes need to round to new size (cloest power2)
	/// Performance: mainly communication cost: 1M: 2.5s
	pub fn make_even(&mut self, new_size: usize){
		if new_size<self.num_constraints {panic!("new_size too small");}
		let share_list = get_share_list(&self.vec_num_constraints);
		self.a_share = make_even_matrix(&self.a_share, &share_list, new_size);
		self.b_share = make_even_matrix(&self.b_share, &share_list, new_size);
		self.c_share = make_even_matrix(&self.c_share, &share_list, new_size);
		self.even = true;
		let np = RUN_CONFIG.n_proc as usize;
		self.num_constraints = new_size;
		let unit_size = self.num_constraints/np;
		for i in 0..np{
			self.vec_num_constraints[i] = if i<np-1 {unit_size} 
				else {self.num_constraints - unit_size * (np-1)};
		}
		RUN_CONFIG.better_barrier("DisR1CS make_even");
	}


	/// each node sends over a matrix, main processor collects
	/// all	and returns a LARGER matrix by merging all based on their
	/// id. Only the main processor returns the valid result; the others
	/// returns empty matrix.
	/// NOTE: barrier at the end (all nodes synch to end of func)
	fn merge_matrix(&self, share: &Vec<Vec<LinearTerm<F>>>) 
		-> Vec<Vec<LinearTerm<F>>>{
		if !self.even {panic!("merge_matrix: make it even first!");}
		//1. set up data
		let main_proc = 0i32;
		let np = RUN_CONFIG.n_proc as usize; 
		let world = RUN_CONFIG.univ.world();
		let me = RUN_CONFIG.my_rank as i32;
		let mut res = vec![vec![]; self.num_constraints];
		let mut vec_starts = vec![0usize; np];

		//2. send data
		if me!=0{
			let bytes = LinearTerm::<F>::matrix_to_bytes(share);
			world.process_at_rank(main_proc).send_with_tag(&bytes, me);
		}

		//3. receive data
		if me==0{
			for i in 0..np{
				if i<np-1{
					vec_starts[i+1]=vec_starts[i]+self.vec_num_constraints[i];
				}
			}
			for _i in 0..np-1{
				let r1 = world.any_process().receive_vec::<u8>();
				let src= r1.1.tag() as usize;
				let matrix = LinearTerm::<F>::matrix_from_bytes(&r1.0); 
				assert!(matrix.len()==self.vec_num_constraints[src], "ERROR num_constraints at node {}: {} != matrix.len(): {}", src, self.vec_num_constraints[src], matrix.len());
				for j in 0..matrix.len(){
					res[j+vec_starts[src]] = matrix[j].clone();
				}
			}
			//copying over its own share
			for i in 0..share.len(){
				res[i] = share[i].clone();
			}
		}
		RUN_CONFIG.better_barrier("merge matrix");
		return res;
	}

	/// ONLY return valid instance at node 0
	/// However, needs all nodes to work
	/// NOTE: might be slow, used for testing only!
	pub fn to_serial(&self) -> R1CS<F>{
		if !self.even {panic!("to_serial: make it even first!");}
		//1. each nodes send the share to node 0
		let a = self.merge_matrix(&self.a_share); 
		let b = self.merge_matrix(&self.b_share); 
		let c = self.merge_matrix(&self.c_share); 

		//2. node 0 receive and assembly
		let r1cs = R1CS::<F>::new(a, b, c, self.num_vars, self.num_constraints,
			self.num_io, self.num_segs, self.seg_size.clone()); 
		return r1cs;
	} 

	/// generating the corresponding DisQAP
	pub fn to_qap(&self, t_inp: &F) -> DisQAP<F>{
		assert!(self.even, "call make_even first");
		let np = RUN_CONFIG.n_proc as usize;
		let me = RUN_CONFIG.my_rank as usize;
		let unit_size = self.num_constraints/np;
		let me_start = unit_size * me;
		let t = t_inp.clone();
		let nvars = self.num_vars;
		let n = self.num_constraints; //global n 
		assert!(n.is_power_of_two(), "n: {} is not power of 2!", n);
		let a_t = dis_matrix_to_qap_poly_eval(&self.a_share,nvars,n,me_start,t);
		let b_t = dis_matrix_to_qap_poly_eval(&self.b_share,nvars,n,me_start,t);
		let c_t = dis_matrix_to_qap_poly_eval(&self.c_share,nvars,n,me_start,t);
		let degree = self.num_constraints - 2; //(global degree)
		//see groth'16 (degree of ht: n-2. But coefs needs 1 more element)

		let ht_part_len = if me<np-1 {(n-1)/np } else
			{(n-1)/np  + (n-1)%np};
		let mut ht_part  = vec![F::one(); ht_part_len]; 
		let ht_start = (n-1)/np * me;
		let mut power_of_t = t.pow(&[ht_start as u64]);
		for i in 0..ht_part.len() {
			ht_part[i] = power_of_t;
            power_of_t = power_of_t * t;
		}
		let ht= DisVec::<F>::new_from_each_node(0, 0, n-1, ht_part);
		let zt: F = t.pow(&[n as u64]) - F::one();	
	
		let qap = DisQAP::new(
			a_t,
			b_t,
			c_t,
			ht,
			zt, 
			t,
			self.num_io+1, //including constant 1
			self.num_vars+1, //including constant 1 (column 0)
			degree,
			self.num_segs,
			self.seg_size.clone()
		);
		return qap;
	}
	/// 2nd version which uses exchanges var
	/// so that we are not processing by chunks, but requesting
	/// ALL extra vars (not in partition) in one pass and eval all
	pub fn dis_compute_witness_h_2(
		num_vars: usize, num_cons: usize, 
		a: &Vec<Vec<LinearTerm<F>>>,
		b: &Vec<Vec<LinearTerm<F>>>,
		c: &Vec<Vec<LinearTerm<F>>>,
		vars: &DisVec<F>) -> DisVec<F>{
		//1. evaluate each matrix
		let b_perf = false;
		let b_mem = false;
		let mut timer = Timer::new();
		timer.start();
		let mut timer2 = Timer::new();
		timer2.start();
	
		let n = num_cons;
		assert!(n.is_power_of_two(), "ERR: num_cons is not power of 2");
		let extra_vars = Self::exchange_var_data(a,b,c,&vars.partition,num_vars);
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h Step 1: exchange_data, num_cons: {}, num_vars: {}, extra_vars: {}", num_cons, num_vars, extra_vars.keys().len()), &mut timer);}
		if b_mem{log_mem(LOG1, &format!("---- comp_wit_h Step 1"));}
	
		let mut sum_a = Self::dis_eval_matrix_2(a, n, vars, &extra_vars);
		let mut sum_b = Self::dis_eval_matrix_2(b, n, vars, &extra_vars);
		let mut sum_c = Self::dis_eval_matrix_2(c, n, vars, &extra_vars);
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h Step 2: eval_matrix A,B,C. Size: {}, Local: {}", n, a.len()), &mut timer);}
		if b_mem{log_mem(LOG1, &format!("---- comp_wit_h Step 2"));}
	
		//2. ifft to get polys
		let univ = &RUN_CONFIG.univ;
		distributed_dizk_ifft(&mut sum_a, univ); //in-place ifft
		distributed_dizk_ifft(&mut sum_b, univ);
		distributed_dizk_ifft(&mut sum_c, univ);
	
		//3. fft coset to evaluate on a differenet point
		let mut rng = gen_rng_from_seed(127937713u128); //HAS TO MAKE SURE ALL NODES
		//generates the same random number, can be improved later using hash of
		//prior comm info. to improve later.
		let r = F::rand(&mut rng);
		distributed_dizk_fft_coset(&mut sum_a, univ, r);
		distributed_dizk_fft_coset(&mut sum_b, univ, r);
		distributed_dizk_fft_coset(&mut sum_c, univ, r);
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h Step 3: FFT"), &mut timer);}
		if b_mem{log_mem(LOG1, &format!("---- comp_wit_h Step 3"));}
	
		//4. compute z(t) 
		let omega = F::get_root_of_unity(n as u64).unwrap();
		let t = omega * r; 	
		let t_n = t.pow(&[n as u64]); //this is essentially r^n as omega^n=1
		let z_t = t_n - F::from(1u64);
		let inv_z_t = z_t.inverse().unwrap();
	
		//5. quotient of h()
		let part_n = a.len(); 
		let mut val_h = vec![F::zero(); part_n];
		for i in 0..part_n{
			val_h[i] = (sum_a.partition[i] * sum_b.partition[i] - sum_c.partition[i]) * inv_z_t;
		}
		let mut dis_h = DisVec::<F>::new_from_each_node(0, 0, n, val_h); 
		RUN_CONFIG.better_barrier("construct dis_h"); 
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h Step 4: dis_h"), &mut timer);}
		if b_mem{log_mem(LOG1, &format!("---- comp_wit_h Step 4"));}
	
		distributed_dizk_ifft_coset(&mut dis_h, univ, r);
		dis_h.repartition(n-1);
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h Step 5: IFFT and build resultC"), &mut timer);}
		if b_mem{log_mem(LOG1, &format!("---- comp_wit_h Step 5"));}
		if b_perf{log_perf(LOG1, &format!("---- comp_wit_h v2 TOTAL"), &mut timer2);}
		return dis_h;
	}

	
	/// generating the corresponding QAP
	pub fn to_qap_witness(&self, vars: DisVec<F>) -> DisQAPWitness<F>{
		//let coefs_h = dis_compute_witness_h(
		let coefs_h = Self::dis_compute_witness_h_2(
			self.num_vars, self.num_constraints,
			&self.a_share, &self.b_share, &self.c_share, &vars);
		let qap_wit= DisQAPWitness::new(
			self.num_io+1, //num_inputs
			self.num_vars + 1, //num_vars
			self.num_constraints-2, //degree = n -2 (see groth'16)
			vars, //coefs_abc
			coefs_h
		);
		return qap_wit;	
	}

	/// generating the corresponding QAP by generating a fake coefs_h array
	/// used in ProveStage1 where coefs_h can be skipped
	pub fn to_qap_witness_no_h(&self, vars: DisVec<F>) -> DisQAPWitness<F>{
		//let coefs_h = dis_compute_witness_h(
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
		let n = self.num_constraints - 1;
		let my_part = if me==np-1 {n/np + n%np} else {n/np};
		let val_h = vec![F::zero();  my_part];
		let fake_coefs_h = DisVec::<F>::new_from_each_node(0, 0, n, val_h); 
		let qap_wit= DisQAPWitness::new(
			self.num_io+1, //num_inputs
			self.num_vars + 1, //num_vars
			self.num_constraints-2, //degree = n -2 (see groth'16)
			vars, //coefs_abc
			fake_coefs_h
		);
		return qap_wit;	
	}

	/// compile a distributed R1CS from each node and each node
	/// supplies a different local serial R1CS, but guaranteed to
	/// have the same number of segments
	/// NOTE: r1cs's ownership is passed to this function
	/// return DisR1CS and a variable map which describes
	/// for each node, the [start, size] of each segment (including i/o seg)
	/// vec_conns are the vectors of connector variables (always in even
	/// number), at this moment they are: (hashin, hashout, encryptin, encryptout, state0, statelast)
	/// RETURN DisR1cs, var_map (global) and vec_connectors for local node (debug use)
 pub fn from_serial_each_node(mut r1cs: R1CS::<F>, vec_conns: Vec<usize>,
		fd_log: &mut File) -> (Self, Vec<Vec<(usize,usize)>>,Vec<usize>){
		//1. compile the variable information
		let b_perf = false;
		let b_mem = false;
		let me = RUN_CONFIG.my_rank;
		let mut timer = Timer::new();
		timer.start();
		let seg_info = collect_seg_info(&r1cs);
		if b_perf {flog_perf(LOG1,&format!("collect seginfo"),
			&mut timer,fd_log);}
		if b_mem {flog_mem(LOG1, &format!("collect seginfo"), fd_log);}

		//2. generate the variable map (2d arr)
		let var_map = gen_var_map(&seg_info);

		//3. modify the variables given map
		let old_seginfo = &seg_info[me];
		let new_seg_info = &var_map[me];
		remap_var_ids::<F>(&mut r1cs.a, old_seginfo, new_seg_info);
		remap_var_ids::<F>(&mut r1cs.b, old_seginfo, new_seg_info);
		remap_var_ids::<F>(&mut r1cs.c, old_seginfo, new_seg_info);
		let mut vec_conn_global = vec![];
		for x in vec_conns {
			let newid = local_var_to_global(x, old_seginfo, &var_map[me]);
			vec_conn_global.push(newid);
		}


		//4. assemble result
		let (num_vars, num_io, num_segs, seg_info) = gen_summary(&var_map);
		let vec_num_constraints=collect_constraints_info(r1cs.num_constraints);
		let mut num_constraints = 0;
		for x in &vec_num_constraints {num_constraints += x;}
		let mut b_even = true;
		let n1 = &vec_num_constraints[0];
		for x in &vec_num_constraints {if x!=n1 {b_even = false;}}

		//NOTE: constructor needs column 1 excluded when counting num_vars
		let dr1cs = Self::new(r1cs.a, r1cs.b, r1cs.c, num_vars-1,
			num_constraints, vec_num_constraints,
			num_io-1, num_segs, seg_info, b_even);
		return (dr1cs, var_map, vec_conn_global );
	}

	/** Constructed Distributed Vec of variable values from local
		vars of each node
		var_map: for each node and for each segment: [start, size]
		it includes the num_io as well.
		For node>0: i/o does not include constant 1 column.
	*/
	pub fn vars_from_serial_each_node(vars: &Vec<F>, var_map: &Vec<Vec<(usize,usize)>>, nvars: usize, fd_log: &mut File)
	->DisVec<F>{
		let b_perf = false;
		let b_mem = false;
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
		let mut timer = Timer::new();
		timer.start();

		//1. collect the source map
		let mut vec2d = vec![vec![]; np];
		for dest in 0..np{
			let src_map = get_node_to_node_src_map(me, dest, var_map, nvars);
			let mut total = 0;
			for rec in &src_map {total += rec.1;};
			vec2d[dest] = vec![F::zero(); total];
			let mut idx = 0;
			for rec in &src_map{
				let (start, size) = *rec;
				for i in 0..size{
					vec2d[dest][idx] = vars[start+i];
					idx+=1;
				}
			}
		}
		if b_perf {flog_perf(LOG1, &format!("collect varmap"), 
			&mut timer, fd_log);}
		if b_mem{flog_mem(LOG1, &format!("collect varmap"), fd_log);}

		//2. broadcast
		let sample = F::zero();
		let vrecv = nonblock_broadcast(&vec2d, np as u64, 
			&RUN_CONFIG.univ, sample);
		if b_perf {flog_perf(LOG1, &format!("broadcast vars"), 
			&mut timer, fd_log);}
		if b_mem{flog_mem(LOG1, &format!("broadcast vars"), fd_log);}

		//3. retrieve the data and build by vec
		let part_len = if me<np-1 {nvars/np} else {nvars/np + nvars%np};
		let mut partition = vec![F::zero(); part_len];
		let mut copied = 0;
		for src in 0..np{
			let mut idx = 0;
			let dst_map = get_node_to_node_dst_map(src, me, var_map, nvars);
			for rec in &dst_map{
				let (start, size) = rec;
				for i in 0..*size{
					partition[start+i] = vrecv[src][idx];
					idx+=1;
					copied+=1;
				}
			}
		}
		assert!(copied==part_len, "copied: {} != part_len: {}", copied, part_len);
		if b_perf {flog_perf(LOG1, &format!("rebuild partition"), 
			&mut timer, fd_log);}
		if b_mem{flog_mem(LOG1, &format!("rebuild partition"), fd_log);}

		//4. return dis_vec
		let d_res = DisVec::<F>::new_from_each_node(0, 0, nvars, partition);
		return d_res; 
	}

}

// ---------------------------------------------------
// Utility function
// ---------------------------------------------------
/// distributed matrix to qap.
/// This is the distributed version of the matrix_to_qap_poly_eval
/// in serial_r1cs.rs (using Lagrange coef approach).
/// start_idx is the LOCATION of this matrix in a bigger distributed matrix
/// (e.g., a_share's location in the entire A matrix of the system).
/// nvars and ncons are the measure of number of variables and constraints
/// globally. This function needs to be called on ALL NODES,
/// and they cooperatively build a distributed vector of field elements
/// whose total size is nvars + 1 (due to the constat 1 column at index 0)
pub fn dis_matrix_to_qap_poly_eval<F:PrimeField>(
	matrix: &Vec<Vec<LinearTerm<F>>>, 
	nvars: usize, ncons: usize, start_idx: usize, t: F)
	-> DisVec<F>{
	//1. prep default result for each var
	let me = RUN_CONFIG.my_rank;
	let n = closest_pow2(ncons) as u64; 
	let mut res = HashMap::<usize,F>::new();
	let z_t = t.pow(&[n]) - F::from(1u64); //z(t)
	let omega = F::get_root_of_unity(n).unwrap();
	let mut omega_i = omega.pow(&[start_idx as u64]);
	let mut v = F::from(n).inverse().unwrap() * omega_i;

	//2. process each constraint 
	for i in 0..matrix.len() as usize{
		//2.1 compute the Lagrange coef l_i (actually it's l_{i+start_idx}
		let l_i = z_t * v * ((t - omega_i).inverse().unwrap());
		omega_i = omega_i * omega;
		v = v * omega; 

		//2.2. apply l_i to value of each term
		let row = &matrix[i];
		for item in row{//process each linear term
			let var_idx = item.index;
			if res.contains_key(&var_idx){
				res.insert(var_idx, 
					*res.get(&var_idx).unwrap() + l_i * item.value);
			}else{
				res.insert(var_idx, l_i * item.value);
			}	
		}
	} 

	//3. collection and build the vector to send for each node
	let mut vsend:Vec<Vec<LinearTerm<F>>> = vec![vec![]; RUN_CONFIG.n_proc as usize];
	let np = RUN_CONFIG.n_proc as usize;
	let unit_size = (nvars+1)/np;
	for (var_idx, val) in res{
		let node_id = if var_idx>=unit_size*np {np-1} else {var_idx/unit_size};
		let item = LinearTerm::new(var_idx, val);
		vsend[node_id].push(item);	
	}
	let sample = LinearTerm::new(0, F::zero());
	let received = nonblock_broadcast(&vsend, np as u64, &RUN_CONFIG.univ, sample);

	//4. process the received vector and prepare the disvec
	let my_num_vars = if RUN_CONFIG.my_rank<np-1
		{unit_size} else {nvars +1 - unit_size * (np-1)};
	let mut myvars = vec![F::zero(); my_num_vars];
	let col_start = me * unit_size; 
	for row in received{
		for item in row{
			let var_idx = item.index - col_start;
			myvars[var_idx] = myvars[var_idx] + item.value;
		}
	}

	//5. send and receive my shares to all nodes
	let dis_vec = DisVec::<F>::new_from_each_node(0u64, 0u64, nvars+1, myvars);
	RUN_CONFIG.better_barrier("matrix_to_qap");
	return dis_vec;
}

/// generate a random distribution of constriants
/// ganranteed: each node has at least one constraint
pub fn rand_vec_num_constraints(rng: &mut StdRng, 
	total: usize, np: usize)->Vec<usize>{
	if total<np {panic!("rand_vec_num_cons ERR: total:{}<np:{}!", total, np);} 
	let mut res = vec![1usize; np];
	let mut remaining = total - np;
	for i in 0..np{
		let v:u64= rng.gen::<u64>();
		let to_add = if i<np-1 {(v as usize)%remaining} else {remaining};
		remaining -= to_add;
		res[i] += to_add;
	}
	return res;
}

/// get the bound of i'th share
/// [begin,end): note the actual last index included is end-1
pub fn get_share(vec_num_constraints: &Vec<usize>, i: usize)->(usize, usize){
	let mut start = 0;
	for j in 0..i{
		start += vec_num_constraints[j];
	}
	let end = start + vec_num_constraints[i];
	return (start, end);
}

/// return a vectore of shares [start, end) for each node
pub fn get_share_list(vec_num_constraints: &Vec<usize>)->Vec<(usize, usize)>{
	let n = vec_num_constraints.len();
	let mut res = vec![(0,0); n];
	let mut start = 0;
	for i in 0..n{
		let end = start+vec_num_constraints[i];	
		res[i] = (start, end);
		start =end;
	}	
	return res;
}

/// get the intersection of the two ranges, e.g., 
/// [3,5) intersect [4,6) is [4, 5)
/// Note: 2nd element is actually not included.
/// the actual length of the resulting segment is res.1 - res.0
pub fn intersect(share1: &(usize, usize), share2: &(usize, usize)) -> (usize, usize){
	let start = if share1.0>share2.0 {share1.0} else {share2.0};
	let end = if share1.1<share2.1 {share1.1} else {share2.1};
	return (start, end);
}

/// This function shoudl be called on all nodes jointly.
/// Make the matrix evenly distributed over nodes
/// share_list has the CURRENT share of each node
/// The return of the SHARE for the caller node 
/// new_size must be greater than or equal to existing size.
/// If necessary, matrix will be padded with EMPTY rows.
fn make_even_matrix<F:PrimeField>(mat: &Vec<Vec<LinearTerm<F>>>, share_list: &Vec<(usize, usize)>, new_size: usize) -> Vec<Vec<LinearTerm<F>>>{
	//1. get stats
	let me = RUN_CONFIG.my_rank as usize;
	let np = RUN_CONFIG.n_proc as usize;
	let mut n = share_list[share_list.len()-1].1;
	if n>new_size {panic!("new_size: {} < n: {}", new_size, n);}
	n = new_size;	
	let unit_size = n/np;
	let my_share = share_list[me];

	//2. prep to send to each node
	let mut vsend = vec![vec![]; np];
	for i in 0..np{
		let target_i = if i<np-1 {(unit_size * i, unit_size * (i+1))}
			else {(unit_size * i,  n)};
		let iset = intersect(&my_share, &target_i);
		let subset_size = if iset.1>=iset.0 {iset.1 - iset.0} else {0};
		let share_to_send = if subset_size==0 {vec![]}
			else {mat[iset.0-my_share.0 .. iset.1-my_share.0].to_vec()};
		let bytes= LinearTerm::<F>::matrix_to_bytes(&share_to_send);
		vsend[i] = bytes;
	}

	//3. asynch send and receive
	let mut vrecv:Vec<Vec<Vec<LinearTerm<F>>>> = vec![vec![]; np as usize];
	mpi::request::scope(|scope|{
		let world = &RUN_CONFIG.univ.world();
		let mut requests = Vec::new();
		for i in 0..np{
			let msg = &(vsend[i as usize]);
			requests.push(
				world.process_at_rank(i as i32).
				immediate_send(scope, msg)
			);
		}
		for _pid in 0..np{
			let r1 = world.any_process().receive_vec::<u8>();
			let data = LinearTerm::<F>::matrix_from_bytes(&r1.0);
			let proc = r1.1.source_rank();
			vrecv[proc as usize] = data;
		}
		while let Some((_index, _status)) = 
			mpi::request::wait_any(&mut requests) { }
		RUN_CONFIG.better_barrier("DisR1CS make_even: nonblock_broadcast");
	});

	//3. re-assembly the data 
	let mysize = if me<np-1 {unit_size} else {n-unit_size * (np-1)};
	let mut res = vec![vec![]; mysize];
	let mut idx = 0;
	for i in 0..np{
		let mat_i = &vrecv[i];
		for j in 0..mat_i.len(){
			res[idx] = mat_i[j].clone();
			idx+=1;
		}
	}
	assert!(idx<=mysize, "make_even_matrix ERR: idx: {}>mysize: {}", 
		idx, mysize);
	return res;
}

/// ALL nodes should call this jointly.
/// Assuming: matrix is already EVENLY distributed
/// also assuming all LinearTerms in one row are sorted in
/// asciending order of variable index.
/// num_vars and num_cons are the number of variables and constraints
/// globally.
/// Performance: 1M: 0.5 sec.
pub fn dis_eval_matrix<F:PrimeField>(mat: &Vec<Vec<LinearTerm<F>>>,
	num_vars: usize, num_cons: usize, vars: &DisVec<F>) -> DisVec<F>{
	//1. get stats
	let mut chunk_size = RUN_CONFIG.max_vec_size;
	let chunks = if (num_vars+1)%chunk_size==0 {(num_vars+1)/chunk_size}
		else {(num_vars+1)/chunk_size + 1};
	if chunks==1 {chunk_size = num_vars + 1;} //to save mem
	let mut chunk = vec![F::zero(); chunk_size];
	let n = mat.len();
	let mut vidx = vec![0usize; n]; //currently index to process
	let mut vres = vec![F::zero(); n];

	//2. for number of var chunks
	for i in 0..chunks{
		//2.1 collect var assignments
		let start = i*chunk_size;
		let end = if i==chunks-1 {num_vars+1} else {(i+1)*chunk_size};
		vars.all_node_collect_chunk(&(start,end), &mut chunk);

		//2.2 evaluate all rows
		for j in 0..mat.len(){
			let row = &mat[j];
			for k in vidx[j]..row.len(){
				let term = &row[k];
				let var_idx = term.index;
				if var_idx<start {
					panic!("var_idx: {} < start: {}", var_idx, start);
				}else if var_idx>=end{
					break; //wait for next chunk 
				}else{
					vres[j] += chunk[var_idx-start] * term.value;
					vidx[j] += 1;
				}//end if	
			}//end for term
		}//end for row
	}//end for chunk

	//3. build data and return
	let res = DisVec::<F>::new_from_each_node(0u64, 0u64, num_cons, vres);  
	RUN_CONFIG.better_barrier("dis_r1cs::matrix_eval");
	return res;
}


/// Assume: num_constraints is already power of 2. 
/// MUST BE called at all nodes jointly.
/// Produce the h() polynomials' coef as shown in Groth'16
/// a,b,c are the SHARES of a,b,c matrix at each node.
/// vars is a distributed vector representing variable assignment.
/// return a Distributed Vector of coefficients of h(x)
///
/// Performance: 1M entries: 3.2 sec (3 times faster than serial version
/// on 8 node single physical computer).
/// 1M: 3.2 sec, 2M: 6.5 sec, 4M: 15 sec
/// NEW DATA: 1M: 6.4
pub fn dis_compute_witness_h<F:PrimeField>(
	num_vars: usize, num_cons: usize, 
	a: &Vec<Vec<LinearTerm<F>>>,
	b: &Vec<Vec<LinearTerm<F>>>,
	c: &Vec<Vec<LinearTerm<F>>>,
	vars: &DisVec<F>) -> DisVec<F>{
	//1. evaluate each matrix
	let n = num_cons;
	assert!(n.is_power_of_two(), "ERR: num_cons is not power of 2");

	let mut sum_a = dis_eval_matrix(a, num_vars, n, vars);
	let mut sum_b = dis_eval_matrix(b, num_vars, n, vars);
	let mut sum_c = dis_eval_matrix(c, num_vars, n, vars);

	//2. ifft to get polys
	let univ = &RUN_CONFIG.univ;
	distributed_dizk_ifft(&mut sum_a, univ); //in-place ifft
	distributed_dizk_ifft(&mut sum_b, univ);
	distributed_dizk_ifft(&mut sum_c, univ);

	//3. fft coset to evaluate on a differenet point
	let mut rng = gen_rng_from_seed(127937713u128); //HAS TO MAKE SURE ALL NODES
	//generates the same random number, can be improved later using hash of
	//prior comm info. to improve later.
	let r = F::rand(&mut rng);
	distributed_dizk_fft_coset(&mut sum_a, univ, r);
	distributed_dizk_fft_coset(&mut sum_b, univ, r);
	distributed_dizk_fft_coset(&mut sum_c, univ, r);

	//4. compute z(t) 
	let omega = F::get_root_of_unity(n as u64).unwrap();
	let t = omega * r; 	
	let t_n = t.pow(&[n as u64]); //this is essentially r^n as omega^n=1
	let z_t = t_n - F::from(1u64);
	let inv_z_t = z_t.inverse().unwrap();

	//5. quotient of h()
	let part_n = a.len(); 
	let mut val_h = vec![F::zero(); part_n];
	for i in 0..part_n{
		val_h[i] = (sum_a.partition[i] * sum_b.partition[i] - sum_c.partition[i]) * inv_z_t;
	}
	let mut dis_h = DisVec::<F>::new_from_each_node(0, 0, n, val_h); 
	RUN_CONFIG.better_barrier("construct dis_h"); 

	distributed_dizk_ifft_coset(&mut dis_h, univ, r);
	dis_h.repartition(n-1);
	return dis_h;
}


/// collect segment information from each local R1CS
/// needs to be called at EACH NODE. each node supplies a different r1cs
/// return: 2d array, for each node it has
/// [num_io, seg_0, seg_1, ... seg_n] 
/// this is merged by 1st node and broadcast to all
/// NOTE: num_io is adjusted by -1 for all nodes except 0 (for constant 1)
fn collect_seg_info<F:PrimeField>(r1cs: &R1CS<F>) -> Vec<Vec<usize>>{
	//1. each local builds expanded seg_info
	let me = RUN_CONFIG.my_rank;
	let main = 0usize;
	let np = RUN_CONFIG.n_proc;
	let mut new_seg_size = vec![0usize; r1cs.num_segs+1];
	new_seg_size[0] = if me==0 {r1cs.num_io} else {r1cs.num_io-1};
	for i in 0..r1cs.num_segs {new_seg_size[i+1] = r1cs.seg_size[i];}
	
	//2. all send to main node 0
	let vec2d = all_to_one_vec(me, main, &new_seg_size);
	let size = (r1cs.num_segs+1)*np;
	let vec1d = if me==main {vec2d_to_vec(&vec2d)} else {vec![0usize; size]};

	//3. main node brodcast all
	let vres1d = broadcast_small_arr(&vec1d, main);

	//4. all nodes convert from 1d array to 2d array
	let vecres = vec_to_vec2d(&vres1d, np);
	return vecres;
}

/// generate the variable map given the seg_info
/// seg_info: 2d array with each element of seg_size for all segs 
///   including num_io
/// var_map: 3d array. For each node there is an element of 2d array
/// of the form [(seg_0_start, seg_0_size), (seg_1_start, seg_1_size)...]
/// here seg_0 is the i/o section (with constant 1 excluded)
/// seg_1 is the ORIGINAL seg_0 in seg_info (aux_vars/witnesses)
fn gen_var_map(seg_info: &Vec<Vec<usize>>) -> Vec<Vec<(usize,usize)>>{
	//let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	assert!(seg_info.len()==np, "seg_info.len() != np!");

	//1. get the TOTAL size of all segs
	let num_segs = seg_info[0].len();
	let mut total_size = vec![0usize; num_segs];
	for seg in 0..num_segs{
		for node in 0..np{
			total_size[seg] += seg_info[node][seg];
		} 
	}
	

	//2. for each node calculates the start position of each seg
	let mut vres = vec![vec![(0usize,0usize); num_segs]; np];
	let mut cur_seg_start = 0;
	for seg in 0..num_segs{
		let mut cur_offset = 0;
		for node in 0..np{
			let me_start = cur_seg_start + cur_offset; //start
			let me_size  = seg_info[node][seg]; //size
			vres[node][seg] = (me_start, me_size);
			cur_offset += seg_info[node][seg];
		}
		cur_seg_start += total_size[seg];
		let last_node_seg = &vres[np-1][seg];
		assert!(last_node_seg.0 + last_node_seg.1 == cur_seg_start, "calc incorrect!");
	}

	return vres;	
}

/// map the local var(id) to global one in the entire DisR1cs
fn local_var_to_global(var: usize, seg_size_inp: &Vec<usize>, var_map: &Vec<(usize, usize)>)->usize{
	let seg_size = seg_size_inp.clone(); 
	let num_segs = seg_size.len();
	let me = RUN_CONFIG.my_rank;

	//1. search for the new rid
	let mut seg_id = num_segs + 1;
	let mut cur_seg_start = 0;
	let mut offset = 0; 
	let mut b_found = false;
	for i in 0..num_segs{
		let cur_size = seg_size[i];
		if var>=cur_seg_start && var<cur_seg_start+cur_size{
			seg_id = i;
			offset = var-cur_seg_start;
			b_found = true;
			break;
		}
		cur_seg_start += cur_size; 
	}
	assert!(b_found, "ERROR: not found var_id: {} for node: {}, seg_info: {:?}, cur_seg_start: {}", var, me, seg_size, cur_seg_start);

	//2. get the new_id
	let mut new_id;
	if seg_id>0{
		new_id = var_map[seg_id].0 + offset;
	}else{
		if me==0{	new_id = var_map[seg_id].0 + offset;}
		else {	
			//because dropped constant col 1, 
			//id 1 would be regarded as id "0" in the new mapped seg}
			new_id = var_map[seg_id].0 + offset -1;
		}
	}
	//3. adjust for constant 1 column for nodes >0
	if me>0{new_id -= 1;}
	return new_id;
} 

/// change the var IDs of all Linear terms
/// Given the old seg_size and new var_map change the var_ids
/// todo: use local_var_to_global (refactor later)
fn remap_var_ids<F:PrimeField>(a: &mut Vec<Vec<LinearTerm<F>>>, seg_size_inp: &Vec<usize>, var_map: &Vec<(usize,usize)>){
	let mut seg_size = seg_size_inp.clone(); 
	let num_segs = seg_size.len();
	let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	timer.start();
	
	//1. patch on the modified seg_size for node not 0 -> original seg_size
	if me>0 {seg_size[0] += 1;}
	for row in a{
		for mut term in row{
			let var = term.index;

			//1. search for the new rid
			let mut seg_id = num_segs + 1;
			let mut cur_seg_start = 0;
			let mut offset = 0; 
			let mut b_found = false;
			for i in 0..num_segs{
				let cur_size = seg_size[i];
				if var>=cur_seg_start && var<cur_seg_start+cur_size{
					seg_id = i;
					offset = var-cur_seg_start;
					b_found = true;
					break;
				}
				cur_seg_start += cur_size; 
			}
			assert!(b_found, "ERROR: not found var_id: {} for node: {}, seg_info: {:?}, cur_seg_start: {}", var, me, seg_size, cur_seg_start);

			//2. get the new_id
			let new_id;
			if seg_id>0{
				new_id = var_map[seg_id].0 + offset;
			}else{
				if me==0{	new_id = var_map[seg_id].0 + offset;}
				else {	
					//because dropped constant col 1, 
					//id 1 would be regarded as id "0" in the new mapped seg}
					new_id = var_map[seg_id].0 + offset -1;
				}
			}

			//3. change it
			term.index = new_id;
		}
	}
}

/// return num_vars, num_io, num_segs, seg_info
fn gen_summary(all_seg: &Vec<Vec<(usize,usize)>>)-> (usize, usize, usize, Vec<usize>){
	let np = RUN_CONFIG.n_proc;
	let num_segs = all_seg[0].len(); //including i/o
	let num_io = all_seg[0][1].0; //start_idx is the number of i/o
	let num_vars = all_seg[np-1][num_segs-1].0 + all_seg[np-1][num_segs-1].1;
	let mut seg_info = vec![0usize; num_segs-1]; //excluding i/o
	for seg in 1..num_segs{
		for node in 0..np{
			seg_info[seg-1] += all_seg[node][seg].1;
		}
	}
	let mut sum_wit = 0;
	for x in &seg_info {sum_wit += x;}
	assert!(sum_wit + num_io==num_vars, "sum_wit: {} + num_io: {} != num_vars: {} ", sum_wit, num_io, num_vars);
	return (num_vars, num_io, num_segs-1, seg_info.clone());
}

/// all reports the constraints to node 0 and 
/// then compile the vec_num_constraints and broadcast too all
/// All will receive and get the same return 
fn collect_constraints_info(num_cons: usize)->Vec<usize>{
	//1. every reports
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let main = 0;
	let vec_ret = all_to_one(me, main, num_cons as u64);

	//2. broadcast to all
	let mut vec2 = vec![0usize; np];
	for i in 0..np {vec2[i] = vec_ret[i] as usize;}
	let vec_res = broadcast_small_arr(&vec2, main);
	return vec_res;
}

/// generate the local segment information from global var_map
/// return vec[ (start, size) ] for each segment (including i/o)
/// column constat 1 is RECOVERED as column 0
fn global_varmap_to_local(node: usize, global_map: &Vec<(usize,usize)>) 
	-> Vec<(usize, usize)>{
	let num_segs = global_map.len();
	let mut vres = vec![(0usize, 0usize); num_segs];
	let mut var_idx = 0;
	for i in 0..num_segs{
		let (_, global_size) = global_map[i];
		let local_start = var_idx;
		//RECOVER column 0 as constant 1 for node>0 and segment 0 (i/o)
		let global_size = if node>0 && i==0 {global_size+1} else {global_size};
		vres[i] = (local_start, global_size);
		var_idx += global_size;
	}
	return vres;

}

/// map from the global (start,size) to the LOCAL partition form 
/// vec[ (start, size) ]
/// NOTE: the len() of vec matches number of segments (including I/O)
fn map_global_to_local(node: usize, regions: &Vec<(usize,usize)>, global_map: &Vec<(usize,usize)>)->Vec<(usize, usize)>{
	let num_segs = regions.len();
	assert!(num_segs==global_map.len(), "num_segs!=global_map.len()");
	let local_map = global_varmap_to_local(node, &global_map);
	let mut vres = vec![(0usize,0usize); num_segs];

	for seg in 0..num_segs{
		let (src_start, src_size) = regions[seg];
		if src_size==0{
			vres[seg] = (local_map[seg].0, 0usize);
		}else{
			let src_end = src_start + src_size;
			let (global_start, global_size) = global_map[seg];
			assert!(src_start>=global_start, "ERR: src_start<global_start");
			assert!(src_end<=global_start+global_size, 
				"ERR: src_end>global_start+size");
			let start_offset = src_start - global_start;
			let mut real_start = start_offset + local_map[seg].0;
			//coz column constant 1 is not in global map}
			if node>0 && seg==0 {real_start += 1;}
			vres[seg] = (real_start, src_size);
		}
	}

	return vres;
}

/// generate the GLOBAL segments of data that should be sent
/// from source node to destination node, in the form of GLOBAL INDEX
/// return an array has the same length as num_segments (i/o seg included)
/// each element has the form (start, size)
/// Basically these are the SUBLIST of each segment of the source code 
fn gen_dest_regions(src: usize, dest: usize, var_map: &Vec<Vec<(usize, usize)>>, nvars: usize) -> Vec<(usize, usize)>{
	let np = RUN_CONFIG.n_proc;
	//let me = RUN_CONFIG.my_rank;
	let (dest_start, dest_end) = get_share_start_end(dest as u64, np as u64, nvars as u64);
	let src_segs = &var_map[src];
	let num_segs = src_segs.len(); //including i/o and adjusted
	let mut dest_regions = vec![];


	for seg in 0..num_segs{
		let src_start = src_segs[seg].0;
		let src_end = src_segs[seg].1 + src_start;
		let (is, ie) = share_intersect( &(src_start, src_end), 
			&(dest_start,dest_end) );
		let act_size = ie-is;
		if act_size>0{
			dest_regions.push((is, act_size));
		}else{
			dest_regions.push((is, act_size));
		}
	}
	return dest_regions;
}


/// generate the segments of map to copy data for src->dest
/// that is: how to copy the data from the local partition of src
/// return 2d array and each element looks like (start, size)
/// the return has the size of segments (+i/o)
/// if for one segment, there is no data, size==0
fn get_node_to_node_src_map(src: usize, dest: usize, var_map: &Vec<Vec<(usize,usize)>>, nvars: usize) -> Vec<(usize, usize)>{
	let dest_regions = gen_dest_regions(src, dest, var_map, nvars);
	let vres = map_global_to_local(src, &dest_regions, &var_map[src]); 
	return vres;
}

/// generate the segments of map to copy data for src->dest
/// that is: how to copy the data INTO the local partition of dest 
/// return 2d array and each element looks like (start, size)
/// the return has the size of segments (+i/o)
/// if for one segment, there is no data, size==0
fn get_node_to_node_dst_map(src: usize, dest: usize, var_map: &Vec<Vec<(usize,usize)>>, nvars: usize) -> Vec<(usize, usize)>{
	let np = RUN_CONFIG.n_proc;
	let dest_regions = gen_dest_regions(src, dest, var_map, nvars);
	let (dest_start, dest_end) = get_share_start_end(dest as u64, np as u64, nvars as u64);
	let mut vres = dest_regions.clone();
	let num_segs = dest_regions.len();
	for seg in 0..num_segs{
		let start = dest_regions[seg].0;
		let size = dest_regions[seg].1;
		if size == 0{
			vres[seg] = (0usize, 0usize);
		}else{
			assert!(start>=dest_start && start+size<=dest_end, "ERROR: start: {}, size: {} not in range (dest_start: {}, dest_end: {}", start, size, dest_start, dest_end);
			vres[seg] = (start-dest_start, size);
		}
	}

	return vres;
}
