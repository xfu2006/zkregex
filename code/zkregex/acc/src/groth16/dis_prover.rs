/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 10/19/2022
	Completed: 10/21/2022
	Revised: 03/06/2023 [add comments to prove_stage1: no need for coefs_h]

	prove and verify function
*/

/// Distributed version of Prover/Verifier
///
/// Ref: Groth'16: J. Groth, "On the Size of Pairing-Based Non-Interactive
/// Arguments", EUROCRYPT16. https://eprint.iacr.org/2016/260.pdf
/// Ref2: DIZK: H. Wu et al, "DIZK: Distributed Zero Knowledge Proof system",
/// https://www.usenix.org/conference/usenixsecurity18/presentation/wu
/// NOTE: our variable naming convention simulates the source code of DIZK
/// The serial QAP is used for functional testing of distributed QAP.
///
/// We used most of the variation notations from DIZK and its arch design.
/// The revised part is: The proof is split into two halves, using
/// the 2-stage Groth'16 scheme in our zk-regex paper.
///
/// Performance: 4096k: 80 sec setup, 60 sec of prove time (this is
/// 3 times faster than serial version)

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;
extern crate mpi;

use self::ark_ff::{Zero,UniformRand};
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use tools::*;
use poly::common::*;
use self::mpi::traits::*;
//use self::mpi::environment::*;
//use groth16::serial_qap::*;
//use groth16::serial_prove_key::*;
use groth16::dis_prove_key::*;
use groth16::new_dis_qap::*;
use groth16::common::*;
use groth16::serial_prover::*;
use profiler::config::*;
use poly::group_dis_vec::*;
use poly::dis_vec::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;


#[derive(Clone)]
pub struct DisProver<PE:PairingEngine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// r in Groth'16 scheme
	pub r: PE::Fr,
	/// s in Groth'16 scheme
	pub s: PE::Fr,
	/// r_i in modified scheme in our paper
	pub r_i: Vec<PE::Fr>,
	/// segment size
	pub seg_size: Vec<usize>
}

impl <PE:PairingEngine> DisProver<PE> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// constructor
	pub fn new(num_segs: usize, seed: u128, seg_size: Vec<usize>) 
		-> DisProver<PE>{
		let mut rng = gen_rng_from_seed(seed);
		let r = PE::Fr::rand(&mut rng);
		let s = PE::Fr::rand(&mut rng);
		let mut r_i = vec![PE::Fr::zero(); num_segs];
		for i in 0..num_segs{
			r_i[i] = PE::Fr::rand(&mut rng);	
		}
		let sp = DisProver::<PE>{
			r:r, s:s, r_i: r_i, seg_size: seg_size
		};

		return sp;
	}

	/// stage 1 proof
	/// for each segment i computes
	/// [(beta u_j(x) + alpha v_j(x) + w_j(x)]/delta_i + ri*delta_k
	/// for each j in the segment
	/// NOTE: only node 1 returns valid result
	/// NOTE: this part does NOT use coefs_h, so coefs_h in qap witness
	///    can be MISSING at this moment for saving computing cost
	/// u is the upper limit of the number of C_i to compute from 0 to u-1
	pub fn prove_stage1(&self, key: &DisProverKey<PE>,
		qw: &DisQAPWitness<PE::Fr>, u: usize)
		-> ProofPart1<PE>{
		let b_perf = false;
		let mut timer = Timer::new();
		let mut timer2 = Timer::new();
		timer.start();
		timer2.start();

		let num_segs = self.seg_size.len();
		let delta_k = key.delta_g1[num_segs-1];
		let all_seg_bounds = get_bounds(qw.num_inputs, &self.seg_size);
		//NOTE: we skip the LAST segment (at least)!
		assert!(u<all_seg_bounds.len(), "u must be < all_seg_bounds.len()");
		let seg_info = all_seg_bounds[0..u].to_vec();
		let mut total_size = 0;
		for x in &seg_info {total_size += x.1 - x.0;}
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 Step1: prep. size: {}", total_size), &mut timer);}

		let mut arr_c = dis_vmsm_g1::<PE>(&key.delta_abc_g1, 
			&qw.coefs_abc, &seg_info);
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 Step2: vmsm. size: {}", total_size), &mut timer);}

		for i in 0..u{
			let part2 = delta_k.mul(self.r_i[i]);
			arr_c[i] = arr_c[i] + part2.into_affine();
		}
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 Step3: add del_k*r_i."), &mut timer);}

		let io = qw.coefs_abc.sublist_at_each(qw.num_inputs);
		let io_len = io.len();
		let p1 = ProofPart1::<PE>{arr_c: arr_c, io: io};
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 Step4: take i/o size: {}", &io_len), &mut timer);}

		RUN_CONFIG.better_barrier("wait for all");
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 Step5: synchronize"), &mut timer);}
		if b_perf {log_perf(LOG1, &format!("-- prove_stage1 TOTAL"), &mut timer2);}

		return p1;
	}

	/// stage 2 proof: produce [A]_1, [B]_2, and [C_k]_1
	/// read zkregex paper for details
	pub fn prove_stage2(&self, key: &DisProverKey<PE>, qw: &DisQAPWitness<PE::Fr>, u: usize) -> ProofPart2<PE>{
		let b_perf = false;
		let mut timer = Timer::new();
		let mut timer2 = Timer::new();
		timer.start();
		timer2.start();

		//1. compute A
		let num_segs = self.seg_size.len();
		let one_seg = vec![(0, qw.coefs_abc.len)];
		//let evaluation_a = vmsm_g1::<PE>(&key.query_a, &qw.coefs_abc); 
		let evaluation_a = dis_vmsm_g1::<PE>(&key.query_a, 
			&qw.coefs_abc,&one_seg)[0];
		let delta_k = key.delta_g1[num_segs-1];
		let a = key.alpha_g1 + evaluation_a + delta_k.mul(self.r).into_affine();
		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 Step1: compute A"), &mut timer);}

		//2. compute B
		let evaluation_b=dis_vmsm_g2::<PE>(&key.query_b,
			&qw.coefs_abc,&one_seg)[0]; 		
		let delta_k_g2 = key.delta_g2[num_segs-1];
		let b = key.beta_g2 + evaluation_b + 
			delta_k_g2.mul(self.s).into_affine();
		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 Step2: compute B2"), &mut timer);}

		let evaluation_b1=dis_vmsm_g1::<PE>(&key.query_b1,
			&qw.coefs_abc,&one_seg)[0]; 
		let b_1 = key.beta_g1+evaluation_b1+delta_k.mul(self.s).into_affine();
		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 Step3: compute B1"), &mut timer);}

		//3. compute C_u to C_{k-1}
		let num_segs = self.seg_size.len();
		let arr_c = vec![1u32; num_segs-u-1]; //just dummy for self-test
		let delta_k = key.delta_g1[num_segs-1];
		let all_seg_bounds = get_bounds(qw.num_inputs, &self.seg_size);
		//NOTE: we skip the LAST segment (at least)!
		assert!(u<all_seg_bounds.len(), "u must be < all_seg_bounds.len()");
		let seg_info = all_seg_bounds[u..num_segs-1].to_vec();
		assert!(seg_info.len()==arr_c.len(), "seg_info.size: {} != arr_c.size: {}", seg_info.len(), arr_c.len());

		let mut arr_c = dis_vmsm_g1::<PE>(&key.delta_abc_g1, 
			&qw.coefs_abc, &seg_info);


		for i in 0..arr_c.len(){
			let idx = u + i;
			let part2 = delta_k.mul(self.r_i[idx]);
			arr_c[i] = arr_c[i] + part2.into_affine();
		}

		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 Step3: compute arr_c"), &mut timer);}


		//4. compute C_k (last one)
		let seg_info = all_seg_bounds[0..num_segs].to_vec();
		let zero = PE::Fr::zero();
		let last_seg = seg_info[num_segs-1];
		let part1= dis_vmsm_g1::<PE>(&key.delta_abc_g1, 
			&qw.coefs_abc,&vec![last_seg])[0];
		let part2 = a.mul(self.s).into_affine() + b_1.mul(self.r).into_affine();

		let minus_rs = PE::Fr::zero() - self.r * self.s;
		let part3 = delta_k.mul(minus_rs);
		let mut part4 = key.delta_g1[0].mul(zero - self.r_i[0]);
		for i in 1..num_segs-1{
			let item = key.delta_g1[i].mul(zero - self.r_i[i]);
			part4 = part4 + item;
		}
		let part5 = dis_vmsm_g1::<PE>(&key.query_h, &qw.coefs_h, &one_seg)[0];
		let c_k = part1 + part2 + part3.into_affine() + part4.into_affine() + part5;
		let io = qw.coefs_abc.sublist_at_each(qw.num_inputs);

		let p2 = ProofPart2::<PE>{a:a, b:b, arr_c: arr_c, last_c: c_k, io: io};
		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 Step4: compute Ck"), &mut timer);}
		if b_perf {log_perf(LOG1, &format!("-- prove_stage2 TOTAL"), &mut timer2);}
		return p2;
	}
}

// ----------------------- UTILITY FUNCTIONS BELOW ---------------
/** compute the variable msm for the given segments, 
and seg_info contains the [start,end) of each segment
For example: given base of 1000 elements and exp of 1000 elements
and given segs [(5,10), (200,205)] it computes the 
	base[5]^exp[5] * ... base[9]^exp[9]
and base[200]^exp[200] * ... * base[204]^exp[204]
	All nodes are invoved in computing.
	ONLY the main node of base.main_processor returns the CORRECT RESULT.
*/
pub fn dis_vmsm_g1<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg_info: &Vec<(usize,usize)>) 
	-> Vec<PE::G1Affine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//let me = RUN_CONFIG.my_rank;
	let res2 = dis_vmsm_g1_new::<PE>(base, exp, seg_info);
	return res2;
}


pub fn dis_vmsm_g1_old<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg_info: &Vec<(usize,usize)>) 
	-> Vec<PE::G1Affine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = false;
	let mut timer = Timer::new();
	timer.start();
	let mut timer2 = Timer::new();
	timer2.start();
	let me = RUN_CONFIG.my_rank;
	let main_id = base.main_processor; 
	let (me_start, me_end) = exp.get_share_bounds_usize(me);
	let g0 = base.partition[0].mul(PE::Fr::zero()).into_affine();
	let num_segs = seg_info.len();
	let mut arr_c = vec![g0; num_segs]; //to return
	let world = RUN_CONFIG.univ.world();
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 OLD segments: {:?}", seg_info ), &mut timer);}

	//1. compute local results first
	for i in 0..num_segs{
		let (seg_start, seg_end) = seg_info[i];
		let max_start = if me_start>seg_start {me_start} else {seg_start};
		let min_end = if me_end < seg_end {me_end} else {seg_end};
		if max_start<=min_end{
			let seg_size = min_end - max_start;
			let idx_start = max_start - me_start;
			let idx_end = idx_start + seg_size;
			let seg_base= base.partition[idx_start..idx_end].to_vec();
			let seg_exp = exp.partition[idx_start..idx_end].to_vec(); 
			arr_c[i]= vmsm_g1::<PE>(&seg_base, &seg_exp); 
			if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 OLD local: segment: {}, size: {}", i, min_end-max_start), &mut timer);}
		}else{
			if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 OLD local: SKIP segment: {}, size: {}", i, seg_end-seg_start), &mut timer);}
		}
	}
	if me!=main_id{//send to main node
		let vec_bytes = to_vecu8::<PE::G1Affine>(&arr_c);
		//println!("DEBUG USE 1001: {} -> {}: {} bytes", me, main_id, vec_bytes.len());
		let root_process = world.process_at_rank(main_id as i32);
		root_process.send_with_tag(&vec_bytes, me as i32);
	}else{//collect all results
		let np = RUN_CONFIG.n_proc as usize;
		for _i in 0..np-1{
			let r1 = world.any_process().receive_vec::<u8>();
			let vbytes = &r1.0;
			let v = from_vecu8::<PE::G1Affine>(vbytes, g0);
			for j in 0..v.len(){
				arr_c[j] = arr_c[j] + v[j];
			}
		}
	}
	RUN_CONFIG.better_barrier("dis_vmsm_g1");
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 OLD: assemble result"), &mut timer);}
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 OLD TOTAL:"), &mut timer2);}
	return arr_c;
}

/// produce the variable MSM for the segment
/// if segment is TOO SMALL or VERY CLOSE to the entire size, 
/// use the SLOW approach
/// otherwise calls the FAST approach which slice out the base and exp
/// for the segment.
pub fn dis_vmsm_g1_seg_old<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg: (usize,usize)) -> PE::G1Affine where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	return dis_vmsm_g1_seg_slow::<PE>(base, exp, seg);
}

pub fn dis_vmsm_g1_seg_new<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg: (usize,usize)) -> PE::G1Affine where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let total_size = base.len;
	let seg_size = seg.1-seg.0;
	if seg_size<total_size/5 || seg_size>total_size/5*4{
		return dis_vmsm_g1_seg_slow::<PE>(base, exp, seg);
	}else{
		return dis_vmsm_g1_seg_fast::<PE>(base, exp, seg);
	}
}
/// compute the dis_vmsm_g1 for partition, could be SLOW if
/// the segment is not too small and not too big (will incur cost of entire
///  base size)
pub fn dis_vmsm_g1_seg_slow<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg: (usize,usize)) -> PE::G1Affine where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = false;
	let mut timer = Timer::new();
	let mut timer2 = Timer::new();
	timer.start();
	timer2.start();

	//1. process the LOCAL partition if it is in range
	let me = RUN_CONFIG.my_rank;
	let main_id = base.main_processor; 
	let (me_start, me_end) = exp.get_share_bounds_usize(me);
	let (seg_start, seg_end) = (seg.0, seg.1);
	let max_start = if me_start>seg_start {me_start} else {seg_start};
	let min_end = if me_end < seg_end {me_end} else {seg_end};
	let g0 = base.partition[0].mul(PE::Fr::zero()).into_affine();
	let mut res = vec![g0; 1];

	if max_start<=min_end{
		let seg_size = min_end - max_start;
		let idx_start = max_start - me_start;
		let idx_end = idx_start + seg_size;
		let seg_base= base.partition[idx_start..idx_end].to_vec();
		let seg_exp = exp.partition[idx_start..idx_end].to_vec(); 
		res[0] = vmsm_g1::<PE>(&seg_base, &seg_exp); 
	}
	let part_size = if max_start<min_end {min_end-max_start} else {0};
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_slow Step 1: compute local: size: {}", part_size), &mut timer);}

	//2. send and combine results
	let res2d = all_to_one_vec(me, main_id, &res);
	if me==main_id{ 
		res[0] = g0.clone();
		for rec in &res2d{ res[0] = res[0] + rec[0]; } 
	}
	RUN_CONFIG.better_barrier("dis_vmsm_g1_slow");
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_slow Step 2: assemble result"), &mut timer);}
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_slow TOTAL"), &mut timer2);}
	return res[0];
}

/// assume the size is approriate
/// will subsec of the two given list for the seg
/// then run var_msm
pub fn dis_vmsm_g1_seg_fast<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg: (usize,usize)) -> PE::G1Affine where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. get the sublist
	assert!(base.len==exp.len, "base.len!=exp.len");
	let b_perf = false;
	let mut timer = Timer::new();
	timer.start();
	let mut timer2= Timer::new();
	timer2.start();

	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let main = base.main_processor; 
	let base1 = base.subvec(seg.0, seg.1);
	let exp1 = exp.subvec(seg.0, seg.1);
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_fast Step1: sublist size: {}", seg.1-seg.0), &mut timer);}

	//2. get the local result 
	let res = vmsm_g1::<PE>(&base1.partition, &exp1.partition);
	let vres = vec![res];
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_fast Step2: local vmsm: size: {}", (seg.1-seg.0)/np), &mut timer);}
	
	//3. collect
	let res2d = all_to_one_vec(me, main, &vres);
	let mut sum = base.partition[0].mul(PE::Fr::zero()).into_affine();
	if me==main{ 
		for rec in &res2d{ 
			sum = sum + rec[0];
		} 
	}
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_fast Step3 assemble results: np: {}", np), &mut timer);}
	RUN_CONFIG.better_barrier("dis_vmsm_g1_seg_new");
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1_seg_fast TOTAL"), &mut timer2);}
	return sum;
	
}



pub fn dis_vmsm_g1_new<PE:PairingEngine>(base: &GroupDisVec<PE::G1Affine>, 
	exp: &DisVec<PE::Fr>, seg_info: &Vec<(usize,usize)>) 
	-> Vec<PE::G1Affine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = false;
	let mut timer = Timer::new();
	timer.start();
	let g0 = base.partition[0].mul(PE::Fr::zero()).into_affine();
	let num_segs = seg_info.len();
	let mut arr_c = vec![g0; num_segs]; //to return
	if b_perf {log_perf(LOG1, &format!("\n---- dis_vmsm_g1 NEW: segments: {:?}", seg_info ), &mut timer);}

	//1. compute local results first
	for i in 0..num_segs{
		arr_c[i] = dis_vmsm_g1_seg_new::<PE>(base, exp, seg_info[i].clone());
	}
	RUN_CONFIG.better_barrier("dis_vmsm_g1");
	if b_perf {log_perf(LOG1, &format!("---- dis_vmsm_g1 NEW: TOTAL"), &mut timer);}
	return arr_c;
}
/** the G2Affine version. could be better refactored */
pub fn dis_vmsm_g2<PE:PairingEngine>(base: &GroupDisVec<PE::G2Affine>, 
	exp: &DisVec<PE::Fr>, seg_info: &Vec<(usize,usize)>) 
	-> Vec<PE::G2Affine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let me = RUN_CONFIG.my_rank;
	let main_id = base.main_processor; 
	let (me_start, me_end) = exp.get_share_bounds_usize(me);
	let g0 = base.partition[0].mul(PE::Fr::zero()).into_affine();
	let num_segs = seg_info.len();
	let mut arr_c = vec![g0; num_segs]; //to return
	let world = RUN_CONFIG.univ.world();

	//1. compute local results first
	for i in 0..num_segs{
		let (seg_start, seg_end) = seg_info[i];
		let max_start = if me_start>seg_start {me_start} else {seg_start};
		let min_end = if me_end < seg_end {me_end} else {seg_end};
		if max_start<=min_end{
			let seg_size = min_end - max_start;
			let idx_start = max_start - me_start;
			let idx_end = idx_start + seg_size;
			let seg_base= base.partition[idx_start..idx_end].to_vec();
			let seg_exp = exp.partition[idx_start..idx_end].to_vec(); 
			arr_c[i]= vmsm_g2::<PE>(&seg_base, &seg_exp); 
		}
	}
	if me!=main_id{//send to main node
		let vec_bytes = to_vecu8::<PE::G2Affine>(&arr_c);
		let root_process = world.process_at_rank(main_id as i32);
		root_process.send_with_tag(&vec_bytes, me as i32);
	}else{//collect all results
		let np = RUN_CONFIG.n_proc as usize;
		for _i in 0..np-1{
			let r1 = world.any_process().receive_vec::<u8>();
			let v = from_vecu8::<PE::G2Affine>(&r1.0, g0);
			for j in 0..v.len(){
				arr_c[j] = arr_c[j] + v[j];
			}
		}
	}
	RUN_CONFIG.better_barrier("dis_vmsm_g1");
	//println!("DEBUG USE 1003: dis_vmsm_g1 done");
	return arr_c;
}
