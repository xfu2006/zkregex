/** 
	Copyright Dr. CorrAuthor

	Author: Author4 
	All Rights Reserved.
	Created: 07/18/2022
*/

/* ****************************************************************
	Distributed QAP (Quadratic Arithmetic Programs)
	Note: variable naming convention uses that of DIZK
**************************************************************** */

/// distributed quadratic arithmetic program
extern crate ark_ff;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;
extern crate mpi;


use self::ark_ff::{FftField};
use self::mpi::traits::*;
use self::mpi::topology::Communicator;


use groth16::serial_qap::*;
use crate::profiler::config::*;

/*
use self::ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;

use std::any::Any;
use std::rc::Rc;

use proto::*;
use poly::dis_poly::*;
//use poly::dis_key::*;
use poly::serial::*;
use tools::*;
*/

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;


/// distributed QAP system
/// ALL nodes has the IDENTICAL information of num_vars etc.
/// Each node has a share of constraints (e.g., if
/// there are 100 constriants and 10 nodes, each node stores 10 constraints,
/// however, each node may stores a varied number of constraints).
/// the information is contained in vec_num_constraints.
/// The main node is 0 always (it seems no need to distribute to other nodes).
/// Most of data attributes are similar to serial R1CS
/// the "share" attribute stores the "share" of constraints
pub struct DisQAP<F:FftField>{
	/// Share of node of vector at
	pub at_share: Vec<F>,

	/// Share of node of vector bt
	pub bt_share: Vec<F>,

	/// Share of node of vector ct
	pub ct_share: Vec<F>,

	/// Correpsonds to {t^0, t^1, ..., t^n-2} in Groth'16
	/// where self.degree = n-2
	pub ht: Vec<F>,

	/// Corresponds to t(X) at t in Groth'16
	/// i.e. t(X) = \prod_i (x-omega^i) where omega is the root of unity
	pub zt: F,

	/// random point t
	pub t: F,

	/// Full vector length
	pub vec_size: usize,

	/// Vector of share sizes
	pub vec_num_constraints: Vec<usize>,

	/// number of public I/O inputs
	pub num_inputs: usize,

	/// number of variables
	pub num_vars: usize,

	/// degree of h(X) in Groth'16
	pub degree: usize,

	// *** the following are our paper specific additional data structures ***
	/// number of segments of witness inputs. The last one is non-committed, all previous are committed, see the paper about committed witness.
	pub num_segs: usize,

	/// size of segments (sum of them should be num_witness = num_vars - num_io)
	pub seg_size: Vec<usize>,
}

impl <F:FftField> DisQAP<F>{
	/// constructor
	pub fn new(
		at_share: Vec<F>,
		bt_share: Vec<F>,
		ct_share: Vec<F>,
		ht: Vec<F>,
		zt: F,
		t: F,

		vec_size: usize,
		vec_num_constraints: Vec<usize>,
		num_inputs: usize,
		num_vars: usize,
		degree: usize,

		num_segs: usize,
		seg_size: Vec<usize>,) -> DisQAP<F>{
		return DisQAP{
			at_share: at_share,
			bt_share: bt_share,
			ct_share: ct_share,
			ht: ht,
			zt: zt,
			t: t,
			vec_size: vec_size,
			vec_num_constraints: vec_num_constraints,
			num_inputs: num_inputs,
			num_vars: num_vars,
			degree: degree,
			num_segs: num_segs,
			seg_size: seg_size,
		};
	}


	/// convert a serial QAP instance to distributed QAP.
	/// Evenly distribute the share
	/// Assumption: ALL nodes get the same sqap instance.
	pub fn from_serial(sqap: &QAP<F>) -> DisQAP<F>{
		//1. build the share (evenly distribute the constraints)
		let n = sqap.at.len();
		let np = RUN_CONFIG.n_proc as usize;
		let mut vec_num_constraints = vec![0usize; np];
		let mut start_index = 0;
		let normal_share = n/np;
		for i in 0..np{
			vec_num_constraints[i] = if i<np-1 {normal_share} else {n - (np-1)*normal_share};
			if i<RUN_CONFIG.my_rank as usize{
				start_index += vec_num_constraints[i];
			}
		}
		let end_index = start_index + vec_num_constraints[RUN_CONFIG.my_rank as usize];
		let at_share = sqap.at[start_index..end_index].to_vec();
		let bt_share = sqap.bt[start_index..end_index].to_vec();
		let ct_share = sqap.ct[start_index..end_index].to_vec();

		//2. build the obj
		let qap = Self::new(at_share, bt_share, ct_share, sqap.ht.clone(),
							sqap.zt, sqap.t, n, vec_num_constraints,
							sqap.num_inputs, sqap.num_vars,
							sqap.degree, sqap.num_segs, sqap.seg_size.clone(),);
		RUN_CONFIG.better_barrier("from_serial");
		return qap;
	}

	/// each node sends over a vector, main processor collects
	/// all	and returns a LARGER vector by merging all based on their
	/// id. Only the main processor returns the valid result; the others
	/// returns empty vector.
	/// NOTE: barrier at the end (all nodes synch to end of func)
	fn merge_vector(&self, share: &Vec<F>)
					-> Vec<F>{
		//1. set up data
		let main_proc = 0i32;
		let np = RUN_CONFIG.n_proc as usize;
		let world = RUN_CONFIG.univ.world();
		let me = RUN_CONFIG.my_rank as i32;
		let mut res = vec![F::zero(); self.vec_size];
		let mut vec_starts = vec![0usize; np];

		//2. send data
		if me!=0{
			let bytes = DisQAP::<F>::vector_to_bytes(share);
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
				let vector = DisQAP::<F>::vector_from_bytes(&r1.0);
				assert!(vector.len()==self.vec_num_constraints[src], "ERROR num_constraints at node {}: {} != matrix.len(): {}", src, self.vec_num_constraints[src], vector.len());
				for j in 0..vector.len(){
					res[j+vec_starts[src]] = vector[j].clone();
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
	pub fn to_serial(&self) -> QAP<F>{
		//1. each nodes send the share to node 0
		let at = self.merge_vector(&self.at_share);
		let bt = self.merge_vector(&self.bt_share);
		let ct = self.merge_vector(&self.ct_share);

		//2. node 0 receive and assembly
		let qap = QAP::<F>::new(at, bt, ct, self.ht.clone(),
								self.zt, self.t, self.num_inputs, self.num_vars,
								self.degree, self.num_segs,
								self.seg_size.clone(),);
		return qap;
	}

	pub fn vector_to_bytes(share: &Vec<F>) -> Vec<u8>{
		let size = F::zero().serialized_size();
		let bytes = share.len() * size;
		let mut b=vec![0u8; bytes];

		let mut p=0usize;
		for element in share {
			let mut b2 = vec![];
			F::serialize(&element, &mut b2).unwrap();

			for j in 0..b2.len(){
				b[p + j] = b2[j];
			}
			p= p+ size;
		}
		return b;
	}

	pub fn vector_from_bytes(b: &Vec<u8>) -> Vec<F> {
		let size = F::zero().serialized_size();
		let vec_size=b.len()/ size;
		let mut share =vec![F::zero(); vec_size];
		let mut p=0usize;

		for i in 0..vec_size{
			let b2 = &b[p..p+ size];
			let value = F::deserialize(b2).unwrap();
			share[i]=value;
			p+= size;
		}
		return share;
	}
}

