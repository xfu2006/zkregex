/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 10/18/2022
	Completed: 10/19/2022

	This file distributed version of the prover and verifier keys of modified
	groth'16
*/

/// Distributed version of Prover and Verifier Keys
///
/// Ref: Groth'16: J. Groth, "On the Size of Pairing-Based Non-Interactive
/// Arguments", EUROCRYPT16. https://eprint.iacr.org/2016/260.pdf
/// Ref2: DIZK: H. Wu et al, "DIZK: Distributed Zero Knowledge Proof system",
/// https://www.usenix.org/conference/usenixsecurity18/presentation/wu
/// NOTE: our variable naming convention simulates the source code of DIZK
/// The serial QAP is used for functional testing of distributed QAP.
/// We used most of the variation notations from DIZK
///
/// The keys are enhanced with more elements from our modified
/// scheme (see zkregex paper)
///
extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;
extern crate mpi;

use self::ark_ff::{Field,Zero,UniformRand};
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
//use r1cs::serial_r1cs::ark_std::rand::rngs::StdRng;
use tools::*;
use poly::dis_key::*;
//use poly::dis_vec::*;
use poly::group_dis_vec::*;
use groth16::new_dis_qap::*;
use profiler::config::*;
use groth16::common::*;
use groth16::serial_prove_key::*;
use self::mpi::traits::*;
//use self::mpi::environment::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// distributed prover key 
#[derive(Clone)]
pub struct DisProverKey<PE:PairingEngine>{
	/// g^alpha in G1
	pub alpha_g1: PE::G1Affine, 
	/// g^beta in G1
	pub beta_g1: PE::G1Affine, 
	/// g^beta in G2
	pub beta_g2: PE::G2Affine, 
	/// g^delta in G1 (for each segment)
	pub delta_g1: Vec<PE::G1Affine>, 
	/// g^delta in G2 (for each segment)
	pub delta_g2: Vec<PE::G2Affine>, 
	/// g^{\frac{beta u_i(x) + alpha v_i(x) + w_i(x)}{\delta}} in G1
	/// for each segment (UNLIKE serial version - just ONE DisVec
	///   invalid entries are g^0)
	pub delta_abc_g1: GroupDisVec<PE::G1Affine>,
	/// g^{u_i(x)} in groth'16 paper
	pub query_a: GroupDisVec<PE::G1Affine>,
	/// g^{v_i(x)} in groth'16 paper over Group G2
	pub query_b: GroupDisVec<PE::G2Affine>,
	/// g^{v_i(x)} in groth'16 paper over group G1
	pub query_b1: GroupDisVec<PE::G1Affine>,
	/// g^{(x^i t(x))/last_delta} for each i groth'16 paper
	pub query_h: GroupDisVec<PE::G1Affine>,
}

impl <PE:PairingEngine>DisProverKey<PE>{
	/// return the delta_abc_g1 of key_id at segment_id 
	/// at EACH NODE!
	pub fn get_g1_key(&self, seg_id: usize, key_id: usize, qap: &DisQAP<PE::Fr>)-> PE::G1Affine{
		//1. all compute who is going to get the key
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
		let seg_bounds = get_bounds(qap.num_inputs, &qap.seg_size);
		let (seg_start, _seg_end) = seg_bounds[seg_id];
		let real_idx = seg_start + key_id;
		let mut idx_root = np;
		for i in 0..np{
			let (me_start, me_end) = qap.at.get_share_bounds_usize(i);
			if real_idx>=me_start && real_idx<me_end{
				idx_root = i;
				break;
			}
		};
		assert!(idx_root!=np, "can't find who has the seg_id!");
		let (me_start, _me_end) = qap.at.get_share_bounds_usize(me);
		let idx = if idx_root==me {real_idx-me_start} else {0};
		let val = self.delta_abc_g1.partition[idx];
		let mut vu8 = to_vecu8(&vec![val]);	
		let world = RUN_CONFIG.univ.world();
		world.process_at_rank(idx_root as i32).broadcast_into(&mut vu8);
		let sample = self.delta_g1[0];
		let vec_ret = from_vecu8(&vu8, sample);
		let res = vec_ret[0];
		return res;
	}
	/// return a dummy version
	pub fn get_dummy()->Self{
		let g1dummy = PE::G1Affine::prime_subgroup_generator();
		let g2dummy = PE::G2Affine::prime_subgroup_generator();
		let gddummy = GroupDisVec::<PE::G1Affine>::new_dis_vec_with_id(0,0,0,vec![]); 
		let gddummy2 = GroupDisVec::<PE::G2Affine>::new_dis_vec_with_id(0,0,0,vec![]); 
		let ins = Self{
			alpha_g1: g1dummy,
			beta_g1: g1dummy.clone(),
			beta_g2: g2dummy.clone(),
			delta_g1: vec![],
			delta_g2: vec![],
			delta_abc_g1: gddummy.clone(),
			query_a: gddummy.clone(),
			query_b: gddummy2.clone(),		
			query_b1: gddummy.clone(),
			query_h: gddummy.clone(),
		};
		return ins;

	}
}

/// similar to DisVec::get_share_bounds_usize [start, end) for each
pub fn get_bounds(start: usize, seg_size: &Vec<usize>) -> Vec<(usize, usize)>{
	let mut ret = vec![(0,0); seg_size.len()];
	let mut start_pos = start;
	for i in 0..seg_size.len(){
		let size = seg_size[i];
		ret[i] = (start_pos, start_pos + size);
		start_pos += size;	
	}
	return ret;
}

/// generate the Distributed prover and (common) verifier keys
/// For the non-disvec version it's generating the SAME DATA
/// on all nodes
pub fn dis_setup<PE:PairingEngine>(seed: u128, qap: &DisQAP<PE::Fr>, key: &DisKey<PE>) ->
	(DisProverKey<PE>, VerifierKey<PE>) where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. generate the random values. TO BE IMPROVED LATER (synch
	//rand generation from all nodes)
	let mut rng = gen_rng_from_seed(seed);
	let alpha = PE::Fr::rand(&mut rng);
	let beta = PE::Fr::rand(&mut rng);
	let gamma = PE::Fr::rand(&mut rng);
	let init_delta = PE::Fr::rand(&mut rng);
	let inverse_gamma = gamma.inverse().unwrap();
	let g1 = key.g.into_affine();
	let g1_proj = key.g;
	let g2 = key.g_g2;
	let g2_proj = key.g_g2.into_projective();
	let mut delta = vec![init_delta; qap.num_segs];
	let mut inverse_delta = vec![init_delta; qap.num_segs];
	for i in 0..qap.num_segs{
		delta[i] = PE::Fr::rand(&mut rng);
		inverse_delta[i] = delta[i].inverse().unwrap();
	} 

	//2. compute (beta*u_i(x) + alpha*v_i(x) + w_i(x))/gamma
	//as num_inputs is usually VERY SMALL. It's cheaper to
	//conver it to serial first.
	let mut gamma_abc = vec![PE::Fr::zero(); qap.num_inputs];
	let at = qap.at.sublist_at_each(qap.num_inputs);
	let bt = qap.bt.sublist_at_each(qap.num_inputs);
	let ct = qap.ct.sublist_at_each(qap.num_inputs);
	for i in 0..qap.num_inputs{
		let vsum = beta*at[i]+alpha*bt[i]+ct[i];
		gamma_abc[i] = vsum*inverse_gamma;
	}

	//3. compute (beta*u_j(x) + alapha*v_j(x) + w_j(x))/delta_i
	//for each segment, in parallel and in one pass. All segmenets
	//delta_abc_i will live in ONE DisVec! [in contrast to serial version]
	//entries out of range will be set to 0. applies to EACH node
	assert!(qap.at.b_in_cluster, "make sure qap.q partitioned!");
	let me = RUN_CONFIG.my_rank;
	let size = qap.at.partition.len();
	let mut delta_abc_part = vec![PE::Fr::zero(); size]; 
	let (me_start, me_end) = qap.at.get_share_bounds_usize(me);
	let seg_bounds = get_bounds(qap.num_inputs, &qap.seg_size);
	for seg_id in 0..seg_bounds.len(){
		let (seg_start, seg_end) = seg_bounds[seg_id];
		let max_start = if me_start>seg_start {me_start} else {seg_start};
		let min_end = if me_end < seg_end {me_end} else {seg_end};
		if min_end>max_start{//there is intersection
			let inv_delta = inverse_delta[seg_id];
			for i in max_start..min_end{
				let idx = i - me_start;
				delta_abc_part[idx] = (beta * qap.at.partition[idx] + alpha*qap.bt.partition[idx] + qap.ct.partition[idx]) * inv_delta;
			}//end for: each idx
		}
	}//end for: try each segment


	let mut gamma_abc_part = vec![PE::Fr::zero(); size]; 
	let (seg_start, seg_end) = (0usize, qap.num_inputs);
	let max_start = if me_start>seg_start {me_start} else {seg_start};
	let min_end = if me_end < seg_end {me_end} else {seg_end};
	if min_end>max_start{//there is intersection
		for i in max_start..min_end{
			let idx = i - me_start;
				gamma_abc_part[idx] = (beta * qap.at.partition[idx] + alpha*qap.bt.partition[idx] + qap.ct.partition[idx]) * inverse_gamma;
			}//end for: each idx
	}
	



	//4. generating raised powers
	let a_id = qap.at.id;
	let a_main = qap.at.main_processor as u64;
	let a_len = qap.at.len;
	let alpha_g1 = g1.mul(alpha).into_affine();
	let beta_g1 = g1.mul(beta).into_affine();
	let beta_g2 = g2.mul(beta).into_affine();
	let gamma_g2 = g2.mul(gamma).into_affine();
	let mut delta_g1 = vec![g1; qap.num_segs];
	let mut delta_g2 = vec![g2; qap.num_segs];
	for i in 0..qap.num_segs{
		delta_g1[i] = g1.mul(delta[i]).into_affine();
		delta_g2[i] = g2.mul(delta[i]).into_affine();
	}

	//5. generating the query_h
	let inv_deltaz= inverse_delta[qap.num_segs-1] * qap.zt;
	let mut new_ht_part = qap.ht.partition.clone();
	let new_ht_len = new_ht_part.len();
	for i in 0..new_ht_len{
		new_ht_part[i] = new_ht_part[i] * inv_deltaz;
	}
	let query_h_part = msm_g1::<PE>(g1_proj, &new_ht_part);

	let query_a_part = msm_g1::<PE>(g1_proj, &qap.at.partition);
	let query_b_part = msm_g2::<PE>(g2_proj, &qap.bt.partition);
	let query_b1_part = msm_g1::<PE>(g1_proj, &qap.bt.partition);
	let	delta_abc_g1_part = msm_g1::<PE>(g1_proj, &delta_abc_part);
	let gamma_abc_g1_part = msm_g1::<PE>(g1_proj, &gamma_abc_part);
	let query_a = GroupDisVec::<PE::G1Affine>::new_from_each_node(a_id, a_main, a_len, query_a_part);
	let query_b1 = GroupDisVec::<PE::G1Affine>::new_from_each_node(a_id, a_main, a_len, query_b1_part);
	let delta_abc_g1= GroupDisVec::<PE::G1Affine>::new_from_each_node(a_id, a_main, a_len, delta_abc_g1_part);
	let gamma_abc_g1= GroupDisVec::<PE::G1Affine>::new_from_each_node(a_id, a_main, a_len, gamma_abc_g1_part);
	let query_b = GroupDisVec::<PE::G2Affine>::new_from_each_node(a_id, a_main, a_len, query_b_part);
	let query_h= GroupDisVec::<PE::G1Affine>::new_from_each_node(a_id, a_main, qap.degree+1, query_h_part);
	RUN_CONFIG.better_barrier("wait for gamma_abc_g1");
	let gamma_abc_g1_real = gamma_abc_g1.sublist_at_each(qap.num_inputs);

	//6. assembly the keys
	let dpk = DisProverKey::<PE>{
		alpha_g1: alpha_g1.clone(),
		beta_g1: beta_g1,
		beta_g2: beta_g2.clone(),
		delta_g1: delta_g1,
		delta_g2: delta_g2.clone(),
		delta_abc_g1: delta_abc_g1,
		query_a: query_a,
		query_b: query_b,
		query_b1: query_b1,
		query_h: query_h
	};

	let svk = VerifierKey{
		alpha_g1: alpha_g1,
		beta_g2: beta_g2,
		alpha_g1_beta_g2: PE::pairing(alpha_g1, beta_g2),
		gamma_g2: gamma_g2,
		delta_g2: delta_g2,
		gamma_abc_g1: gamma_abc_g1_real,
	};
	
	return (dpk, svk);	
}

