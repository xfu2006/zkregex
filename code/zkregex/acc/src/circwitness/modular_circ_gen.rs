/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 08/14/2022
	Completed: 08/19/2022
	Generating the circuit witness pack for a modulr circuit for ALL nodes.
	See main/src/main/java/cs/Employer/acc_driver/AccDriver for details.
*/

//use super::super::poly::common::*;
use super::super::poly::dis_vec::*;
extern crate ark_ff;
extern crate ark_ec;
extern crate ark_poly;
extern crate ark_std;
extern crate mpi;
use super::super::poly::dis_poly::*;
use super::super::poly::serial::*;
use self::ark_ff::{PrimeField};
//use self::ark_poly::{Polynomial};
//use crate::tools::*;
//use self::ark_poly::{DenseUVPolynomial,univariate::DensePolynomial, Polynomial};
use crate::profiler::config::*;
use crate::tools::*;
//use crate::jsnark_driver::new_r1cs_gen::*;
use std::collections::HashMap;
//use self::mpi::traits::*;
//use mpi::environment::*;
//use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
//use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};

/** generate the circuit pack FOR every node. 
Expecting dirpath has the following
"states.dat", "trans.dat", "arr_input.dat", "arr_bfail.dat", "arr_aligned.dat", "hash_in.dat", "r.dat" (randon nonces for evaluating polys: r, r_inv, z, r1, r2, r, r_inv)

Generates the following files for EACH node: will be named as
e.g., "State_0, Input_0" etc.
			"states.dat.node_...", "arr_input.dat", "trans.dat", 
"arr_aligned.dat", 
			"S_P", "S_GCD", "S_P_GCD", "S_PD_GCD", "S_S", "S_T", 
			"T_P", "T_GCD", "T_P_GCD", "T_PD_GCD", "T_S", "T_T", 
			"chunk_inputs",

Input: 
	s_size: should be matching the number of elements in arrInputAligned.
	s_np: should be matching the RUN_CONFING.n_proc!
	r is the input for evaluating polynomials
RETURN: 
	Vec<DisVec<F>> for: states.dat, arr_input.dat, arr_bfail.dat, arr_aligned.dat, trans.dat, chunked_inputs.dat
	Vec<DisVec<F>> for S_, and T_ (states and transitions)
	  [dp, p_d, gcd, dp_set_support, pd_gcd, s, t];

	HashMap for chunked_inputs contents

server_id is the server who owns the dirpath (launching server)
*/ 
pub fn gen_witness_for_modular_verifier<F:PrimeField>(server_id: usize, 
	dirpath: &str, 
	s_size: &str, s_np: &str, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), 
	b_write: bool)
	-> (Vec<DisVec<F>>,Vec<DisPoly<F>>,Vec<DisPoly<F>>,HashMap<String,Vec<F>>){
	let b_perf = false;
	let n:usize = s_size.parse::<usize>().unwrap();
	let np:usize = s_np.parse::<usize>().unwrap();
	if np!=RUN_CONFIG.n_proc{
		panic!("np: {} != RUNCONFIG.np: {}", np, RUN_CONFIG.n_proc);
	}
	let mut timer = Timer::new();
	timer.clear_start();
	transfer_dir_from_server(server_id, dirpath, netarch);
	if b_perf {log_perf(LOG1, "Witness Gen Step 1: Transfer Trace Data to all nodes.", &mut timer);}

	let r_arr = read_arr_fe_from::<F>(&format!("{}/r.dat", dirpath));
	let _not_used_r = r_arr[0];
	//let r_inv = r_arr[1];
	let z = r_arr[2];
	let r1 = r_arr[3];
	let r2 = r_arr[4];
	let key= r_arr[5];
	let r = r_arr[6]; //somehow wasted one element, keep it
	let r_inv = r_arr[7];
	
	//1. split the inputs for states.dat, .... 
	let mut vec_dvecs = vec![];
	let srcdata= [
		("states.dat", 2*n+np), 
		("arr_input.dat",2*n), 
		("arr_bfail.dat",2*n), 
		("arr_aligned.dat",n),
		("trans.dat", 2*n), 
	];
	for (fname, size) in srcdata{
		let dvec = split_inputs::<F>(dirpath, fname, size, true); //regardless of b_write should be true
		vec_dvecs.push(dvec);
	}
	if b_perf {log_perf(LOG1, "Witness Gen Step 2: Split Inputs.", &mut timer);}

	//2. build the evidence for states and transitions (gcd, bizout's etc)
	//NOTE: size need +1 for storing coefs (compared with degree)
	let mut chunk_inps:HashMap<String,Vec<F>> = create_chunked_inputs(dirpath, n, np, r);
	let vres1 = modular_gen_circ_witness_for_multiset_fullmode::<F>(dirpath, "states.dat", "S_", 2*n+np+1, &mut chunk_inps, r, b_write, netarch); 
	let	vres2 = modular_gen_circ_witness_for_multiset_fullmode::<F>(dirpath, "trans.dat", "T_", 2*n+1, &mut chunk_inps, r, b_write, netarch);
	if b_perf {
		log_perf(LOG1, "Witness Gen Step 3: Generate Poly Witness.", &mut timer);
	}

	//3. write the polynomail chunked inputs
	let dv_chunked_inputs = chunked_poly_inputs_to_dvec(dirpath, &chunk_inps, z, r1, r2, key, r, r_inv, b_write);	
	vec_dvecs.push(dv_chunked_inputs);
	if b_perf {log_perf(LOG1, "Witness Gen Step 3: Write Inputs to File.", &mut timer);}

	RUN_CONFIG.better_barrier("modular_gen_circ_serial");
	return (vec_dvecs, vres1, vres2, chunk_inps);
}

/// the shortcut version where we assume the GCDs and all polys
/// have already been loaded
pub fn gen_witness_for_modular_verifier_shortcut<F:PrimeField>(
	server_id: usize, dirpath: &str, 
	s_size: &str, s_np: &str, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), 
	b_write: bool)
	-> (Vec<DisVec<F>>,Vec<DisPoly<F>>,Vec<DisPoly<F>>,HashMap<String,Vec<F>>){
	let b_perf = false;
	let n:usize = s_size.parse::<usize>().unwrap();
	let np:usize = s_np.parse::<usize>().unwrap();
	if np!=RUN_CONFIG.n_proc{
		panic!("np: {} != RUNCONFIG.np: {}", np, RUN_CONFIG.n_proc);
	}
	let mut timer = Timer::new();
	timer.clear_start();
	transfer_dir_from_server(server_id, dirpath, netarch);
	if b_perf {log_perf(LOG1, "Witness Gen Step 1: Transfer Trace Data to all nodes.", &mut timer);}

	let b1st_node = is_1st_node_of_server_by_arch(netarch);
	if b1st_node{
		new_dir_if_not_exists(&format!("{}/witness", dirpath));
	}
	
	let r_arr = read_arr_fe_from::<F>(&format!("{}/r.dat", dirpath));
	let _not_used_r = r_arr[0];
	//let r_inv = r_arr[1];
	let z = r_arr[2];
	let r1 = r_arr[3];
	let r2 = r_arr[4];
	let key= r_arr[5];
	let r = r_arr[6]; //somehow wasted one element, keep it
	let r_inv = r_arr[7];
	
	//1. split the inputs for states.dat, .... 
	let mut vec_dvecs = vec![];
	let srcdata= [
		("states.dat", 2*n+np), 
		("arr_input.dat",2*n), 
		("arr_bfail.dat",2*n), 
		("arr_aligned.dat",n),
		("trans.dat", 2*n), 
	];
	for (fname, size) in srcdata{
		let dvec = split_inputs_shortcut::<F>(dirpath, fname, size, true); //regardless of b_write should be true
		vec_dvecs.push(dvec);
	}
	if b_perf {log_perf(LOG1, "Witness Gen Step 2: Split Inputs.", &mut timer);}

	//2. build the evidence for states and transitions (gcd, bizout's etc)
	//NOTE: size need +1 for storing coefs (compared with degree)
	let mut chunk_inps:HashMap<String,Vec<F>> = create_chunked_inputs(dirpath, n, np, r);
	let vres1 = modular_gen_circ_witness_for_multiset_fullmode_shortcut::<F>(dirpath, "states.dat", "S_", 2*n+np+1, &mut chunk_inps, r, b_write, netarch); 
	let	vres2 = modular_gen_circ_witness_for_multiset_fullmode_shortcut::<F>(dirpath, "trans.dat", "T_", 2*n+1, &mut chunk_inps, r, b_write, netarch);
	if b_perf {log_perf(LOG1, "Witness Gen Step 3: Generate Poly Witness.", &mut timer);}

	//3. write the polynomail chunked inputs
	let dv_chunked_inputs = chunked_poly_inputs_to_dvec(dirpath, &chunk_inps, z, r1, r2, key, r, r_inv, b_write);	
	vec_dvecs.push(dv_chunked_inputs);
	if b_perf {log_perf(LOG1, "Witness Gen Step 3: Write Inputs to File.", &mut timer);}

	RUN_CONFIG.better_barrier("modular_gen_circ_serial");
	return (vec_dvecs, vres1, vres2, chunk_inps);
}

/// update p_acc_states and p_acc_trans (svec and tvec are the
/// disvec of states and trans
pub fn update_chunked_inputs_on_p_acc<F:PrimeField>(chunk_inputs: &mut HashMap<String,Vec<F>>, r: &F, svec: &DisVec<F>, tvec: &DisVec<F>) {
	let mut vec = svec.eval_chunk_binacc(&r);
	let mut vec2 = vec![F::zero()];
	vec2.append(&mut vec);
	chunk_inputs.insert("p_acc_states".to_string(), vec2);

	let mut vec3 = tvec.eval_chunk_binacc(r);
	let mut vec4 = vec![F::zero()];
	vec4.append(&mut vec3);
	chunk_inputs.insert("p_acc_trans".to_string(), vec4);
}

/// read common data first
/// n: input length, np: numer of processors, r: used as sample point for poly
pub fn create_chunked_inputs<F:PrimeField>(dirpath: &str, n: usize, np: usize, r: F) -> HashMap<String,Vec<F>>{
	let mut chunk_inps:HashMap<String,Vec<F>> = HashMap::new();
	let hash_in = read_arr_fe_from::<F>(&format!("{}/hash_in.dat", dirpath));
	chunk_inps.insert("hash_in".to_string(), hash_in);
	let encrypt_in= read_arr_fe_from::<F>(&format!("{}/encrypt_in.dat", dirpath));
	chunk_inps.insert("encrypt_in".to_string(), encrypt_in);
	let vec_acc_states = gen_bin_acc(dirpath, "states.dat", 2*n+np, &r);

	chunk_inps.insert("p_acc_states".to_string(), vec_acc_states);
	let vec_acc_trans= gen_bin_acc(dirpath, "trans.dat", 2*n, &r);
	chunk_inps.insert("p_acc_trans".to_string(), vec_acc_trans);
	return chunk_inps;
}

/** given the file name.node_xxx, for each node reads the arr, let it 
be [a0,...,an]. Compute (r-a0)....(r-an) for each node. Then multiply
them up.  Return a vector of size np+1. The first element is 0.
The last element is the produce of (r-a_i) for all segments combined.
See DisVec::eval_chunk_binacc.
*/
fn gen_bin_acc<F:PrimeField>(dirpath:&str, fname:&str, size:usize, r: &F) -> Vec<F>{
	let ds = DisVec::<F>::read_each_node_from_file(&format!("{}/witness/{}", dirpath, fname), size); 
	let mut vec= ds.eval_chunk_binacc(&r);
	let mut vec2 = vec![F::zero()];
	vec2.append(&mut vec);
	return vec2;	
}

/** CONVERTED chunked inputs to dis_poly,
	if b_write enalbed:
	write the chunked inputs to file chunked_inputs.data.node_xx 
	The input format  (43 elements). SHOULD BE CALLED AT ALL NODES.
	EACH NODE writes in parallel.
 		z, r1, r2, key, r, r_inv
        hash_in, p_acc_states_in, p_acc_trans_in, 
        v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, vs_s, v_s_t_in,
        v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, vs_s_in, v_t_t_in, encrypt_in
        hash_out, p_acc_states, p_acc_trans
        v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, vs_s, v_s_t,
        v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, vs_s, v_t_t,
		encrypt_out, v_st (product of v_s_p_gcd * v_t_p_gcd)
  Return a DisVec<F> object where each node has 43 elements.
  b_write determines if to write to file
*/
pub fn chunked_poly_inputs_to_dvec<F:PrimeField>(dirpath: &str, chunk_inputs: &HashMap<String,Vec<F>>, z: F, r1: F, r2: F, key: F, r: F, r_inv: F, b_write: bool)->DisVec<F>{
	//1. build a HUGE DisVec. Each chunk will have 43 elements
	//NOTE: only node 0 will build the correct one and then it will 
	//distribute to all NODES.
	let mut res_all = vec![];
	let keys = vec![
		"hash_in", "p_acc_states", "p_acc_trans",
		"v_s_p", "v_s_pd", "v_s_gcd", "v_s_p_gcd", "v_s_pd_gcd", "v_s_s", "v_s_t",
		"v_t_p", "v_t_pd", "v_t_gcd", "v_t_p_gcd", "v_t_pd_gcd", "v_t_s", "v_t_t", "encrypt_in"
	];
	let key_len = keys.len();
	let np = RUN_CONFIG.n_proc;
	for i in 0..np{
		let mut vec = vec![z.clone(), r1.clone(), r2.clone(), key.clone(), r.clone(), r_inv.clone()];
		//1. do the 1st half (.._in)
		for id in 0..key_len{
			let key = &keys[id].to_string();
			let data = &chunk_inputs[key];
			vec.push(data[i]);
		}
		//2. do the 2st half (.._out)
		for id in 0..key_len{
			let key = &keys[id].to_string();
			let data = &chunk_inputs[key];
			vec.push(data[i+1]);
		}
		let v_st = chunk_inputs["v_s_p_gcd"][i+1] * chunk_inputs["v_t_p_gcd"][i+1];
		vec.push(v_st);
		assert!(vec.len()==43, "vec.len()!=43");
		res_all.append(&mut vec);
	}

	//2. build the DISVEC
	check_binacc(chunk_inputs);
	let exp_size = 43*np;
	assert!(res_all.len()==exp_size, "ERR: res_all.len()!=exp_size");
	let mut dv_all = DisVec::<F>::new_dis_vec_with_id(0, 0, exp_size, res_all);
	dv_all.repartition(exp_size);
	if b_write{
		let fname = format!("{}/witness/chunk_inputs.dat", dirpath);
		dv_all.write_to_each_node(&fname);
	}
	return dv_all;

}

/// check if bin-acc eval is the same as polynomial eval
fn check_binacc<F:PrimeField>(chunk_inputs: &HashMap<String,Vec<F>>){
	if RUN_CONFIG.my_rank!=0 {return;}
	let vec_v_s_p = &chunk_inputs["v_s_p"];
	let v_s_p = vec_v_s_p[vec_v_s_p.len()-1];
	let vec_v_t_p = &chunk_inputs["v_t_p"];
	let v_t_p = vec_v_t_p[vec_v_t_p.len()-1];
	let vec_p_acc_trans = &chunk_inputs["p_acc_trans"];
	let p_acc_trans = vec_p_acc_trans[vec_p_acc_trans.len()-1];
	let vec_p_acc_states = &chunk_inputs["p_acc_states"];
	let p_acc_states = vec_p_acc_states[vec_p_acc_states.len()-1];
	let vec_v_s_pd = &chunk_inputs["v_s_pd"];
	let v_s_pd = vec_v_s_pd[vec_v_s_pd.len()-1];
	let vec_v_s_pd2 = &chunk_inputs["v_s_pd2"];
	let v_s_pd2 = vec_v_s_pd2[vec_v_s_pd2.len()-1];
	let vec_v_t_pd = &chunk_inputs["v_t_pd"];
	let v_t_pd = vec_v_t_pd[vec_v_t_pd.len()-1];
	let vec_v_t_pd2 = &chunk_inputs["v_t_pd2"];
	let v_t_pd2 = vec_v_t_pd2[vec_v_t_pd2.len()-1];

	assert!(v_s_p==p_acc_states, "v_s_p: {} != p_acc_states: {}", v_s_p, p_acc_states);
	assert!(v_t_p==p_acc_trans, "v_t_p: {} != p_acc_trans: {}", v_t_p, p_acc_trans);
	assert!(v_s_pd==v_s_pd2, "v_s_pd: {} != v_s_pd2: {}", v_s_pd, v_s_pd2);
	assert!(v_t_pd==v_t_pd2, "v_t_pd: {} != v_t_pd2: {}", v_t_pd, v_t_pd2);
	//println!(" ***** check_binacc passed !!! ******");	
}

/** Check the evidence pack, check if it is true of not.
ONLY perform assertion on main node 0, but this functions needs to be
called at ALL NODES */
pub fn check_poly_evidence<F:PrimeField>(p: &DisPoly<F>, pd: &DisPoly<F>, 
	gcd:&DisPoly<F>, p_gcd:&DisPoly<F>, pd_gcd:&DisPoly<F>, 
	s:&DisPoly<F>, t:&DisPoly<F>){  
	let me = RUN_CONFIG.my_rank;

	//1. eval on random points
	let mut rng = gen_rng();
	let r = F::rand(&mut rng);
	let v_p = p.eval(&r);
	let v_pd = pd.eval(&r);
	let v_gcd = gcd.eval(&r);
	let v_p_gcd = p_gcd.eval(&r);
	let v_pd_gcd = pd_gcd.eval(&r);
	let v_s = s.eval(&r);
	let v_t = t.eval(&r);

	let one = F::one();
	if me==0{
		assert!(v_p== v_p_gcd*v_gcd, "FAILS: p = gcd * p_gcd");
		assert!(v_pd==v_pd_gcd*v_gcd, "FAILS: pd = gcd * pd_gcd");
		let lhs = v_s * v_p_gcd + v_t * v_pd_gcd;
		assert!(lhs ==one,
			"FAILS: p_gcd * s + pd_gcd*t: =1. LHS: {}", &lhs);
	}
	//can't check p and p', improve later
}

/** read input file and split into each node evenly. Write into corresponding file. e.g., given "states.dat", write node 0's data into "states.dat.node_0".
b_write controls whether to write.
Return the corresponding distributed vector read from the file.
n is the TOTAL LEN of the vector.
*/
pub fn split_inputs<F:PrimeField>(srcpath: &str, fname: &str, n: usize, b_write: bool)->DisVec<F>{
	let mut arr:Vec<F>=vec![];
	if RUN_CONFIG.my_rank==0 as usize{
		arr = read_arr_fe_from::<F>(&format!("{}/{}", srcpath, fname));
		if n!=arr.len() {panic!("array size: {} not matching n: {}", arr.len(), n);}
	}
	//id 0 and main processor 0 does not matter.
	let mut darr = DisVec::new_dis_vec_with_id(0, 0, n, arr);
	darr.to_partitions(&RUN_CONFIG.univ);
	//let me = RUN_CONFIG.my_rank;
	new_dir_if_not_exists(&format!("{}/witness", srcpath));
	if b_write{
		let destfile = format!("{}/witness/{}", srcpath, fname);
		darr.write_to_each_node(&destfile);
	}
	return darr;
}

/// shortcut version of split_input. with assupmtion that ALL nodes
/// have access to the file
pub fn split_inputs_shortcut<F:PrimeField>(srcpath: &str, fname: &str, n: usize, b_write: bool)->DisVec<F>{
	//OLD APPROACH ----------------
// 	let mut arr:Vec<F>=vec![];
// 	if RUN_CONFIG.my_rank==0 as usize{
// 		arr = read_arr_fe_from::<F>(&format!("{}/{}", srcpath, fname));
// 		if n!=arr.len() {panic!("array size: {} not matching n: {}", arr.len(), n);}
// 	}
// 	//id 0 and main processor 0 does not matter.
// 	let mut darr = DisVec::new_dis_vec_with_id(0, 0, n, arr);
// 	darr.to_partitions(&RUN_CONFIG.univ);
// 	log_perf(LOG1, &format!(" -- split_input OLD: load: {}", fname), &mut timer);
	//OLD APPROACH ---------------- ABOVE

	//NEW APPORACH
	let fpath = format!("{}/{}", srcpath, fname);
	let mut darr2= DisVec::<F>::new_from_each_node_from_file(0, 0, &fpath);
	darr2.repartition(n);
	
	//let me = RUN_CONFIG.my_rank;
	if b_write{
		let destfile = format!("{}/witness/{}", srcpath, fname);
		darr2.write_to_each_node(&destfile);
	}
	return darr2;
}


/** fname refers to either the state file or trans file (states.dat or
trans.dat). prefix is one of the two optios: "S_" or "T_",
thus resulting in file names such as S_P etc.
For details of naming convention check main/java/..../acc_driver/AccDriver.java
The function returns P_GCD (the polynomial STANDARD SET, i.e., set-support,
for encoding the bilinear acc)
	Note: input n: the size of all polynomials (dvec size: degree+1)
	r: is used for evaluating the chunk
	b_write: whether to write the data into disk
RETURN: return all arrWitness as an array (for each local node)
*/
pub fn modular_gen_circ_witness_for_multiset<F:PrimeField>(dirpath: &str, fname: &str, prefix: &str, n: usize, chunk_inputs: &mut HashMap<String,Vec<F>>, r: F, b_write: bool, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>)) -> Vec<DisPoly<F>>{
	return modular_gen_circ_witness_for_multiset_fullmode::<F>(dirpath, fname, prefix, n, chunk_inputs, r, b_write, netarch); //full_mode
}

/** Return a Vec of DisVec<F> cooresponindg to:
	vec![dp, p_d, gcd, dp_set_support, pd_gcd, s, t];
	It inserts entry into chunk_inputs
*/
pub fn modular_gen_circ_witness_for_multiset_fullmode_toremove<F:PrimeField>(dirpath: &str, fname: &str, prefix: &str, n: usize, chunk_inputs: &mut HashMap<String,Vec<F>>, r: F, b_write: bool, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>))->Vec<DisPoly<F>>{
	//0. read data and generate the set data
	//println!("DEBUG USE 100: modular_gen_circ_witness_for_multiset: n: {}", n);
	let b_perf = false;
	let b_test = false;

	let mut timer = Timer::new();
	timer.start();
	if b_perf {log(LOG1, &format!("##### DEBUG USE 100 ######: r is {}", &r));}
	let mainproc = 0u64;
	let srcfile = &format!("{}/{}", dirpath, fname);
	let fname_gen = &format!("generated_set_{}.dat", fname);
	let srcfile2 = &format!("{}/{}", dirpath, fname_gen);
	//let np = RUN_CONFIG.n_proc;
	if RUN_CONFIG.my_rank==mainproc as usize{
		let total = read_1st_line_as_u64(srcfile);
		let multi_set:Vec<u64> = read_arr_u64_from(srcfile, 1, total as usize);
		let set_support = get_set_u64(&multi_set);
		write_arr_with_size(&set_support, srcfile2); 
	}
	RUN_CONFIG.better_barrier("modular_gen_circ_multi_set1");

	let mut dp_set_support = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, 0, &format!("{}/{}", dirpath, fname_gen), netarch);	
	if b_perf{ log_perf(LOG1, &format!("-- Gen Set for {}: degree: {}. ", prefix, dp_set_support.dvec.len), &mut timer);}
	
	//1. build the DisPoly from the roots
	let mut dp = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, mainproc, &format!("{}/{}", dirpath, fname), netarch);	
	dp.repartition(n);
	let fname = format!("{}/witness/{}P", dirpath, prefix);
	if b_write {dp.write_coefs_to_file(&fname);}
	if b_perf {log_perf(LOG1, &format!("-- Gen P: degree: {}. ", dp_set_support.dvec.len), &mut timer);}
	
	//3. construct derive, but don't write it as the circuit can generate
	//itself
	let mut p_d = dp.get_derivative();
	p_d.repartition(n);
	if b_write { 
		p_d.write_coefs_to_file(&format!("{}/witness/{}PD", dirpath, prefix));
	}
	dp_set_support.repartition(n);
	if b_perf {log_perf(LOG1, &format!("-- Gen Derivative: degree: {}. ", p_d.dvec.len), &mut timer);}

	//4. generate the gcd
	let (mut gcd, r0) = DisPoly::<F>::divide_with_q_and_r(&mut dp, &mut dp_set_support);
	dp_set_support.repartition(n);
	if b_test {assert!(r0.is_zero(), "r0 is not zero");}
	//let (gcd, _s, _t) = feea(&p, &p_d); SOMEHOW feea has but does not
	//work for cases that two inputs are NOT co-prime
	gcd.repartition(n);
	if b_write {
		gcd.write_coefs_to_file(&format!("{}/witness/{}GCD", dirpath, prefix));
	}
	if b_perf {log_perf(LOG1, &format!("-- Gen GCD via div: degree: {}. ", gcd.dvec.len), &mut timer);}

	//5. calculate the p/gcd and pd/gcd
	let mut p_gcd = dp_set_support.clone();
	let (mut pd_gcd, r_2) = DisPoly::<F>::divide_with_q_and_r(&mut p_d, &mut gcd);

	if b_test {assert!(r_2.is_zero(), "r2 is not zero!");}
	pd_gcd.repartition(n);
	if b_write{
		pd_gcd.write_coefs_to_file(&format!("{}/witness/{}PD_GCD", dirpath, prefix));
	}
	if b_perf {log_perf(LOG1, &format!("-- Gen P-GCD via div: degree: {}. ", p_gcd.dvec.len), &mut timer);}

	//6. generate the bizou efficients s and t s.t. s*p_gcd + t*pd_gcd = 1
	let (gcdprime, mut s, mut t) = DisPoly::<F>::feea(&mut p_gcd, &mut pd_gcd);
	let pone = get_poly::<F>(vec![F::from(1u64)]);
	let p_gcd_prime = gcdprime.to_serial();
	if RUN_CONFIG.my_rank==0 && b_test {//ONLY node 0 has correct value
		assert!(p_gcd_prime==pone, "p_gcd and pd_gcd not co-prime");
	}
	s.repartition(n);
	if b_write{
		s.write_coefs_to_file(&format!("{}/witness/{}S", dirpath, prefix));
	}
	t.repartition(n);
	if b_write{
		t.write_coefs_to_file(&format!("{}/witness/{}T", dirpath, prefix));
	}
	dp_set_support.repartition(n);
	if b_write{
		dp_set_support.write_coefs_to_file(&format!("{}/witness/{}P_GCD", dirpath, prefix));
	}
	if b_perf {log_perf(LOG1, &format!("-- Gen Bizout Coefs via GCD: degree: {}. ", s.dvec.len), &mut timer);}

	if b_test {check_poly_evidence(&dp, &p_d, &gcd, &p_gcd, &pd_gcd, &s, &t);}

	//7. evaluate each polynomial and collect the chunk inputs
/*
	let prefix = prefix.to_lowercase();
	dp.repartition(n); //needed for chunk correctly working!
	let vpd = dp.compute_chunked_derivative(&r);
	chunk_inputs.insert(format!("v_{}pd", prefix), vpd);
	gcd.repartition(n); //needed for chunk to work
	let arr_data = vec![
		(dp, format!("v_{}p", prefix)),
		(p_d, format!("v_{}pd2", prefix)), //alternative for verification
		(gcd, format!("v_{}gcd", prefix)),
		(dp_set_support, format!("v_{}p_gcd", prefix)),
		(pd_gcd, format!("v_{}pd_gcd", prefix)),
		(s, format!("v_{}s", prefix)),
		(t, format!("v_{}t", prefix)),
	];	
	for (mut dpoly, fname) in arr_data{
		if dpoly.dvec.len!=n{
			dpoly.repartition(n);
		}
		let mut data = dpoly.eval_chunks(&r); //only node 0 has the right value
		let mut data2 = vec![F::zero()]; 	
		data2.append(&mut data);
		assert!(data2.len()==np+1, "data.len(): {} != np+1: {}. For: {}", data2.len(), np+1, fname);
		chunk_inputs.insert(fname, data2);
	}
	if b_perf{log_perf(LOG1, &format!("Evaluate Polys"), &mut timer);}
	*/
	let mut res = vec![dp, p_d, gcd, dp_set_support, pd_gcd, s, t];
	update_chunk_inputs(prefix, &mut res, n, chunk_inputs, r);
	RUN_CONFIG.better_barrier("modular_gen_circ_multi_set3");
	return res;
}

fn poly_stats<F:PrimeField>(prefix: &str, poly: &DisPoly<F>) -> String{
	return format!("{}: degree: {}, real_deg: {}, real_set: {}", prefix, poly.dvec.len, poly.dvec.real_len, poly.dvec.real_len_set);
}

/// shortcut mode of modular_gen_circ_witness_for_multiset
/// read the polynomials which are already generated by preprocess_gcd
pub fn modular_gen_circ_witness_for_multiset_fullmode_shortcut<F:PrimeField>(dirpath: &str, _fname: &str, prefix: &str, n: usize, chunk_inputs: &mut HashMap<String,Vec<F>>, r: F, b_write: bool, _netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>))->Vec<DisPoly<F>>{
	let b_perf = false;
	let b_test = false;
	let mut timer = Timer::new();
	let me = RUN_CONFIG.my_rank;
	timer.start();

	if b_perf {log(LOG1,&format!("===== Modular Gen Circ: {} ====",prefix));}
	if b_test {log(LOG1, &format!("-- ModCircGen: r is {}", &r));}

	let vsrc = vec![
		"P", "PD", "GCD", "P_GCD", "PD_GCD", "S", "T"
	];
	let mut vpoly = vec![];
	for i in 0..vsrc.len(){
		let fpath = format!("{}/{}serial_{}.dat", dirpath, prefix, vsrc[i]);	
		//--- OLD approach. 
		// let coefs = read_arr_fe_from::<F>(&fpath);
		// let dvec= DisVec::<F>::new_dis_vec_with_id(0, 0, 
		//	   coefs.len(), coefs);
		// let dpoly = DisPoly::<F>{id:0, dvec: dvec, 
		//    is_zero: false, is_one: false};
		//let dvec2= DisVec::<F>::new_from_each_node_from_file(0, 0, &fpath);
		let dvec2= DisVec::<F>::new_from_each_node_from_file_and_repartition_to(0, 0, &fpath, n);
		let dpoly2 = DisPoly::<F>{id:0, dvec:dvec2, 
			is_zero:false, is_one: false};
		vpoly.push(dpoly2);
	}
	if b_perf{ log_perf(LOG1, &format!("-- ShortcutWitGen: Step 1: Load All Polys for {}. P: {}, PD_GCD: {}",prefix, &vpoly[0].dvec.len, &vpoly[3].dvec.len), &mut timer);}

	if b_test{
		let mut p_gcd = vpoly[3].clone();
		let mut pd_gcd = vpoly[4].clone();
		let mut s= vpoly[5].clone();
		let mut t= vpoly[6].clone();
		let one = get_poly::<F>(vec![F::from(1u64)]);
		let res = DisPoly::<F>::add(
			&mut DisPoly::<F>::mul(&mut s, &mut p_gcd),
			&mut DisPoly::<F>::mul(&mut t, &mut pd_gcd)
		);
		let sres = res.to_serial();
		if me==0{
			assert!(sres==one, "failed GCD test");
		}	
		if b_perf{ log_perf(LOG1, &format!("-- ShortcutWitGen: Test GCD of Polys for {}. P: {}, PD_GCD: {}",prefix, &vpoly[0].dvec.len, &vpoly[3].dvec.len), &mut timer);}
	}



	//8. write all polynomials
	let vfiles = vec![
		("dp", format!("{}/witness/{}P", dirpath, prefix), n),
		("p_d", format!("{}/witness/{}PD", dirpath, prefix), n),
		("gcd", format!("{}/witness/{}GCD", dirpath, prefix), n),
		("p_gcd", format!("{}/witness/{}P_GCD", dirpath, prefix), n),
		("pd_gcd", format!("{}/witness/{}PD_GCD", dirpath, prefix), n),
		("s", format!("{}/witness/{}S", dirpath, prefix), n),
		("t", format!("{}/witness/{}T", dirpath, prefix), n)
	];
	for i in 0..vfiles.len(){
		let (_poly_name, fpath, new_n) = &vfiles[i];
		let poly = &mut vpoly[i];
		if poly.dvec.len!=*new_n || !poly.dvec.b_in_cluster{
			println!("REMOVE LATER 104: *** repartition: {} from {} -> {}", vfiles[i].0, poly.dvec.len, new_n); 
			poly.repartition(*new_n);
		}
		if b_write{ poly.dvec.write_to_each_node(fpath);}
	}
	if b_perf {log_perf(LOG1, &format!("-- Shortcut WitGen: Step 2: Repartition and Write ALL polynomials. Degree: {}", n), &mut timer);}

	update_chunk_inputs(prefix, &mut vpoly, n, chunk_inputs, r);
	RUN_CONFIG.better_barrier("wait for all modular_gen_witness");
	if b_perf {log_perf(LOG1, &format!("-- Shoftcut WitGen: Step 3: Update_chunk_inputs"), &mut timer);}

	return vpoly;

}

pub fn modular_gen_circ_witness_for_multiset_fullmode<F:PrimeField>(dirpath: &str, fname: &str, prefix: &str, n: usize, chunk_inputs: &mut HashMap<String,Vec<F>>, r: F, b_write: bool, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>))->Vec<DisPoly<F>>{
	let b_perf = false;
	let b_test = false;
	let mut timer = Timer::new();
	let me = RUN_CONFIG.my_rank;
	timer.start();

	//1. main node read the generated set of states and transitions
	if b_perf {log(LOG1, &format!("====== Modular Gen Circ: {} ======", prefix));}
	if b_test {log(LOG1, &format!("-- ModCircGen: r is {}", &r));}
	let mainproc = 0u64;
	let srcfile = &format!("{}/{}", dirpath, fname);
	let fname_gen = &format!("generated_set_{}.dat", fname);
	let srcfile2 = &format!("{}/{}", dirpath, fname_gen);
	if RUN_CONFIG.my_rank==mainproc as usize{
		let total = read_1st_line_as_u64(srcfile);
		let multi_set:Vec<u64> = read_arr_u64_from(srcfile, 1, total as usize);
		let set_support = get_set_u64(&multi_set);
		write_arr_with_size(&set_support, srcfile2); 
	}
	RUN_CONFIG.better_barrier("modular_gen_circ_multi_set1");

	let mut dp_set_support = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, 0, &format!("{}/{}", dirpath, fname_gen), netarch);	
	if b_perf{ log_perf(LOG1, &poly_stats(&format!("-- Gen Set for {}",prefix), &dp_set_support), &mut timer);}
	
	//1. build the DisPoly from the roots
	let mut dp = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, mainproc, &format!("{}/{}", dirpath, fname), netarch);	
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen P", &dp), &mut timer);}
	
	//3. construct derive, but don't write it as the circuit can generate
	//itself
	let mut p_d = dp.get_derivative();
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen PD", &p_d), &mut timer);}

	//4. generate the gcd
	let (mut gcd, r0) = DisPoly::<F>::divide_with_q_and_r(&mut dp, &mut dp_set_support);
	gcd.dvec.set_real_len();
	if b_test {assert!(r0.is_zero(), "r0 is not zero");}
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen GCD via div", &gcd), &mut timer);}

	//5. calculate the p/gcd and pd/gcd
	let mut p_gcd = dp_set_support.clone();
	p_gcd.repartition_to_real_len();
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen P-GCD by clone", &p_gcd), &mut timer);}

	let (mut pd_gcd, r_2) = DisPoly::<F>::divide_with_q_and_r(&mut p_d, 
		&mut gcd);
	pd_gcd.repartition_to_real_len();
	if b_test {assert!(r_2.is_zero(), "r2 is not zero!");}
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen PD-GCD via div", &pd_gcd), &mut timer);}

	//6. generate the bizou efficients s and t s.t. s*p_gcd + t*pd_gcd = 1
	let (mut gcdprime, s, t) = DisPoly::<F>::feea(&mut p_gcd, &mut pd_gcd);
	let pone = get_poly::<F>(vec![F::from(1u64)]);
	if b_test{
		if !gcdprime.dvec.b_in_cluster {gcdprime.to_partitions();}
		let p_gcd_prime = gcdprime.to_serial();
		if me==0{assert!(p_gcd_prime==pone, "p_gcd and pd_gcd not co-prime");}
	}
	if b_perf {log_perf(LOG1, &poly_stats("-- Gen Bizout Coefs by GCD", &s), 
		&mut timer);}
	if b_test {check_poly_evidence(&dp, &p_d, &gcd, &p_gcd, &pd_gcd, &s, &t);}


	//8. write all polynomials
	let mut res = vec![dp, p_d, gcd, dp_set_support, pd_gcd, s, t];
	let vfiles = vec![
		("dp", format!("{}/witness/{}P", dirpath, prefix), n),
		("p_d", format!("{}/witness/{}PD", dirpath, prefix), n),
		("gcd", format!("{}/witness/{}GCD", dirpath, prefix), n),
		("p_gcd", format!("{}/witness/{}P_GCD", dirpath, prefix), n),
		("pd_gcd", format!("{}/witness/{}PD_GCD", dirpath, prefix), n),
		("s", format!("{}/witness/{}S", dirpath, prefix), n),
		("t", format!("{}/witness/{}T", dirpath, prefix), n)
	];
	for i in 0..vfiles.len(){
		let (_poly_name, fpath, new_n) = &vfiles[i];
		let poly = &mut res[i];
		if poly.dvec.len!=*new_n || !poly.dvec.b_in_cluster{ 
			poly.repartition(*new_n);
		}
		if b_write{ poly.dvec.write_to_each_node(fpath);}
	}
	if b_perf {log_perf(LOG1, &format!("-- Write ALL polynomials. Degree: {}", n), &mut timer);}

	update_chunk_inputs(prefix, &mut res, n, chunk_inputs, r);
	if b_perf {log_perf(LOG1, &format!("-- Update_chunk_inputs"), &mut timer);}
	RUN_CONFIG.better_barrier("wait for all modular_gen_witness");
	return res;
}

/** shortcut mode, which we load the polynomials from the existing files
and re-evaluate all points */
pub fn update_chunk_inputs<F:PrimeField>(prefix: &str, ap: &mut Vec<DisPoly<F>>, n: usize, chunk_inputs: &mut HashMap<String,Vec<F>>, r: F){
	let b_perf = false;
	//let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let mut timer = Timer::new();
	timer.start();

	//1. load the polynomials (instead of creating them)
	//log(LOG1, &format!("##### REMOE LATER 102 #####: r is {}", &r));
	if ap[0].dvec.len!=n{ ap[0].repartition(n); }
	let vpd = ap[0].compute_chunked_derivative(&r);
	if b_perf {log_perf(LOG1, "Compute Chunked Derivative", &mut timer);}

	//2. evaluate each polynomial and collect the chunk inputs
	let prefix = prefix.to_lowercase();
	chunk_inputs.insert(format!("v_{}pd", prefix), vpd);
	let arr_data = vec![
		(format!("v_{}p", prefix)),
		(format!("v_{}pd2", prefix)), //alternative for verification
		(format!("v_{}gcd", prefix)),
		(format!("v_{}p_gcd", prefix)),
		(format!("v_{}pd_gcd", prefix)),
		(format!("v_{}s", prefix)),
		(format!("v_{}t", prefix)),
	];	
	for i in 0..arr_data.len(){
		let dpoly = &mut ap[i];
		let fname = &arr_data[i];
		if dpoly.dvec.len!=n{
			dpoly.repartition(n);
		}
		let mut data = dpoly.eval_chunks(&r); //only node 0 has the right value
		let mut data2 = vec![F::zero()]; 	
		data2.append(&mut data);
		assert!(data2.len()==np+1, "data.len(): {} != np+1: {}. For: {}", data2.len(), np+1, fname);
		chunk_inputs.insert(fname.clone(), data2);
	}
	if b_perf {log_perf(LOG1, &format!("Compute Poly Evals"), &mut timer);}
	RUN_CONFIG.better_barrier("modular_gen_circ_multi_set3");
}

/// collect the witness at EACH NODE (will be the same as
/// the slower approach using java JSnark to collect)
/// vec_disvec, spolys, tpolys, and chunk_inputs are the result of
/// gen_witness_for_modular_verifier
/// np: number of processors, total_len the total_len of the ENTIRE file input
/// this function ismainly modled after AccDriver.collect_modular_verifier_witness_for_node
pub fn collect_witness<F:PrimeField>(
	vec_disvec: &Vec<DisVec<F>>,
	spolys: &Vec<DisPoly<F>>, 
	tpolys: &Vec<DisPoly<F>>, 
	total_len: usize, np: usize) -> Vec<F>{
	//1. calculate the length
	let b_debug = false;
	let me = RUN_CONFIG.my_rank;
	let n = if me<np-1 {total_len/np} else {total_len%np + total_len/np}; 
	let raw_fnames = vec![
			"states.dat", "arr_input.dat", "arr_bfail.dat", "arr_aligned.dat",
			"S_P", "S_GCD", "S_P_GCD", "S_PD_GCD", "S_S", "S_T", 
			"T_P", "T_GCD", "T_P_GCD", "T_PD_GCD", "T_S", "T_T", 
			"chunk_inputs.dat",
	];
	let total_s_size = 2*total_len + np + 1;
	let total_t_size = 2*total_len + 1;
	let s_size = if me<np-1 {total_s_size/np} else {total_s_size/np + total_s_size%np};
	let t_size = if me<np-1 {total_t_size/np} else {total_t_size/np + total_t_size%np};

	//2. construct size array and src
	let arr_size = vec![ 
			2*n+1, 2*n, 2*n, n,
			s_size, s_size, s_size, s_size, s_size, s_size,
			t_size, t_size, t_size, t_size, t_size, t_size,
			43	
	];
	let (sp, tp) = (spolys, tpolys);
	let arr_src = vec![
		&vec_disvec[0], &vec_disvec[1], &vec_disvec[2], &vec_disvec[3],
		&sp[0].dvec, &sp[2].dvec, &sp[3].dvec, &sp[4].dvec, &sp[5].dvec, &sp[6].dvec, //skipping p_d
		&tp[0].dvec, &tp[2].dvec, &tp[3].dvec, &tp[4].dvec, &tp[5].dvec, &tp[6].dvec, //skipping p_d,
		&vec_disvec[5], //chunked_inputs
	]; 	

	//3. concat all
	let mut res: Vec<F> = vec![];
	assert!(arr_size.len()==arr_src.len(), "arr_size.len != arr_src.len");
	for i in 0..arr_size.len(){
		let part = &arr_src[i].partition;
		assert!(part.len() == arr_size[i], "part.len(): {} !=arr_size: {}. For: {}", part.len(), arr_size[i], raw_fnames[i]); 
		res.extend(part);
	}

	if b_debug {write_arr_fe_to_with_zero(&res, &format!("../jsnark/JsnarkCircuitBuilder/circuits/11223344/{}/wit2.dump", me));}
	return res;
}

