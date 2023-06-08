/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created 10/15/2022
	Completed: 10/17/2022

	prove and verify function
*/

/// Serial version of Prover/Verifier
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
/// Performance (1node:) 2048k: 139s setup time, 102s prover time, 3ms 
/// verification time. 4096k: 263s setup, 189s prover, 3ms verify

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use self::ark_ff::{Zero,UniformRand};
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use tools::*;
//use poly::dis_key::*;
use groth16::serial_qap::*;
use groth16::serial_prove_key::*;
use groth16::common::*;
use profiler::config::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// QAPWitness struct
#[derive(Clone)]
pub struct ProofPart1<PE:PairingEngine>{
	/// all segments excluding last one
	pub arr_c:  Vec<PE::G1Affine>,
	/// i/o values
	pub io: Vec<PE::Fr>
}
impl <PE:PairingEngine> ProofPart1<PE>{
	pub fn dump(&self, prefix: &str){
		let me = RUN_CONFIG.my_rank;
		if me!=0 {return;}
		println!("====== {} ProofPart1 ======", prefix);
		for i in 0..self.arr_c.len(){
			println!("arr_c[{}]: {}", i, self.arr_c[i]);
		}
		for i in 0..self.io.len(){
			println!("io[{}]: {}", i, self.io[i]);
		}
		
	}
}

#[derive(Clone)]
pub struct ProofPart2<PE:PairingEngine>{
	///A
	pub a: PE::G1Affine,
	///B
	pub b: PE::G2Affine,
	/// all the REST excluding last one and excluding those in ProofPart1
	pub arr_c:  Vec<PE::G1Affine>,
	/// C for last segment
	pub last_c:  PE::G1Affine,
	/// i/o values
	pub io: Vec<PE::Fr>
}

impl <PE:PairingEngine> ProofPart2<PE>{
	pub fn dump(&self, prefix: &str){
		let me = RUN_CONFIG.my_rank;
		if me!=0 {return;}
		println!("====== {} ProofPart2 ======", prefix);
		println!("a: {}", self.a);
		println!("b: {}", self.b);
		println!("last_c: {}", self.last_c);
		for i in 0..self.io.len(){
			println!("io[{}]: {}", i, self.io[i]);
		}
		
	}
}

#[derive(Clone)]
pub struct SerialProver<PE:PairingEngine> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// r in Groth'16 scheme
	pub r: PE::Fr,
	/// s in Groth'16 scheme
	pub s: PE::Fr,
	/// r_i in modified scheme in our paper
	pub r_i: Vec<PE::Fr>,
}

impl <PE:PairingEngine> SerialProver<PE> where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// constructor
	pub fn new(num_segs: usize, seed: u128) -> SerialProver<PE>{
		let mut rng = gen_rng_from_seed(seed);
		let r = PE::Fr::rand(&mut rng);
		let s = PE::Fr::rand(&mut rng);
		let mut r_i = vec![PE::Fr::zero(); num_segs];
		for i in 0..num_segs{
			r_i[i] = PE::Fr::rand(&mut rng);	
		}
		let sp = SerialProver::<PE>{
			r:r, s:s, r_i: r_i
		};

		return sp;
	}

	

	/// stage 1 proof
	/// for each segment i computes
	/// [(beta u_j(x) + alpha v_j(x) + w_j(x)]/delta_i + ri*delta_k
	/// for each j in the segment
	pub fn prove_stage1(&self, key: &SerialProverKey<PE>,
		qw: &QAPWitness<PE::Fr>)
		-> ProofPart1<PE>{
		let num_segs = key.delta_abc_g1.len();
		let mut arr_c = vec![key.alpha_g1; num_segs-1];
		let mut start_pos = qw.num_inputs;
		let delta_k = key.delta_g1[num_segs-1];
		for i in 0..num_segs-1{
			let seg_size = key.delta_abc_g1[i].len(); 
			let abc = qw.coefs_abc[start_pos..start_pos+seg_size].to_vec();
			assert!(abc.len()==seg_size, "abc.len != seg_size");
			let part1 = vmsm_g1::<PE>(&key.delta_abc_g1[i], &abc); 
			let part2 = delta_k.mul(self.r_i[i]);
			arr_c[i] = part1 + part2.into_affine();
			start_pos += seg_size;
		}
		let io = qw.coefs_abc[0..qw.num_inputs].to_vec();
		let p1 = ProofPart1::<PE>{arr_c: arr_c, io: io};
		return p1;
	}

	/// stage 2 proof: produce [A]_1, [B]_2, and [C_k]_1
	/// read zkregex paper for details
	pub fn prove_stage2(&self, key: &SerialProverKey<PE>, qw: &QAPWitness<PE::Fr>) -> ProofPart2<PE>{
		//1. compute A
		let num_segs = key.delta_abc_g1.len();
		let evaluation_a = vmsm_g1::<PE>(&key.query_a, &qw.coefs_abc); 
		let delta_k = key.delta_g1[num_segs-1];
		let a = key.alpha_g1 + evaluation_a + delta_k.mul(self.r).into_affine();

		//2. compute B
		let evaluation_b = vmsm_g2::<PE>(&key.query_b, &qw.coefs_abc); 
		let delta_k_g2 = key.delta_g2[num_segs-1];
		let b = key.beta_g2 + evaluation_b + 
			delta_k_g2.mul(self.s).into_affine();
		let evaluation_b1 = vmsm_g1::<PE>(&key.query_b1, &qw.coefs_abc); 
		let b_1 = key.beta_g1 + evaluation_b1 + 
			delta_k.mul(self.s).into_affine();


		//3. compute C_k (last one)
		let zero = PE::Fr::zero();
		let start_pos = qw.num_vars- key.delta_abc_g1[num_segs-1].len();
		let seg_size = key.delta_abc_g1[num_segs-1].len(); 
		let abc = qw.coefs_abc[start_pos..start_pos+seg_size].to_vec();
		let part1 = vmsm_g1::<PE>(&key.delta_abc_g1[num_segs-1], &abc); 
		let part2 = a.mul(self.s).into_affine() + b_1.mul(self.r).into_affine();


		let minus_rs = PE::Fr::zero() - self.r * self.s;
		let part3 = delta_k.mul(minus_rs);
		let mut part4 = key.delta_g1[0].mul(zero - self.r_i[0]);
		for i in 1..num_segs-1{
			let item = key.delta_g1[i].mul(zero - self.r_i[i]);
			part4 = part4 + item;
		}
		let part5 = vmsm_g1::<PE>(&key.query_h, &qw.coefs_h);
		let c_k = part1 + part2 + part3.into_affine() + part4.into_affine() + part5;
		assert!(abc.len()==seg_size, "abc.len != seg_size");
		let io = qw.coefs_abc[0..qw.num_inputs].to_vec();
		let p2 = ProofPart2::<PE>{a:a, b:b, arr_c: vec![], last_c: c_k, io: io};
		return p2;
	}
}





