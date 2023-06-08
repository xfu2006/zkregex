/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/11/2022
	Completed: 07/15/2022
*/

/// This module defines the KZG protocol (single key version - without
/// the knowledge extraction (which needs scaled key). Only soundness offered.
/// Ref: Kate, Zavericja amd Goldberg ASIACRYPT'10
/// https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf
///
/// Idea: given prover key {g^{alpha^0}, ..., g^{alpha^n}}.
/// Given a polynomial p(x). Its KZG commitment is g^{p(alpha)}.
/// The prover wants to prove that at point r, the value of
/// of p(r) is a claimed value p_r.
/// Proof: the prover generates w(x) = (p(x)-p_r)/(x-r)
/// The proof is W = g^w(\alpha). 
/// Verification: e(g^p(alpha)/g^p_r, h) = e(W, h^alpha/h^r)
///
/// Performance: 16k: 1.5 sec, 1M: 143 sec (prover); verify: 2-4ms
/// 8 nodes on computer.

/* 
NOTE: temporarily all dis_poly involved MUST have id 0 to ensure
main processor is 0. This can be relaxed after we have replaced
the dummy implementation of DisPoly mul,div,sub etc.
*/
extern crate ark_ff;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use self::ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
use self::ark_ff::{Zero};
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
use crate::profiler::config::*;

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// --------------------------------------------------- 
//  Data Structures: KZG Claim, Proof, and Input
// --------------------------------------------------- 
#[derive(Clone)]
pub struct KZGInput<E:PairingEngine>{
	/// the polynomail to prove
	pub p: DisPoly<E::Fr>,	
	/// the random nonce for p(r)
	pub r: E::Fr 
}

#[derive(Clone)]
pub struct KZGProof<E: PairingEngine>{
	/// the proof such that e(w, g^(alpha-r)) = e(kzg, g)
	pub w: E::G1Affine
}

/// The claim is that secret polynomial p(x) hidden behind the
/// the kzg commitment evalutes to p_r at point r.
#[derive(Clone)]
pub struct KZGClaim<E: PairingEngine>{
	/// the kzg commitment of some polynomial p(x), i.e., g^{p(alpha)}
	pub kzg: E::G1Affine,
	/// the random nonce
	pub r: E::Fr,
	/// the claimed value of p(r)
	pub p_r: E::Fr
}

/// The KZG protocol contains a prover key: {g^{alpha^0}, ..., g^{alpha^n}}.
/// the verification key is g^{alpha}.
/// Capacity n is set up when the KZG protocol is constructed using new()
#[derive(Clone)]
pub struct KZG<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}}
	pub key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for KZGInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for KZGProof<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.w, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let w = E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = KZGProof::<E>{w: w};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (w: {:?})", prefix, self.w);
	} 

}

impl <E:PairingEngine> Proof for KZGProof<E> {
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.w = res.w.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&KZGProof::<E> = other.as_any().
			downcast_ref::<KZGProof<E>>().unwrap();
		return self.w==obj.w;
	}
}

impl <E:PairingEngine> ProtoObj for KZGClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		E::Fr::serialize(&self.p_r, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let kzg_val = E::G1Affine::deserialize(&mut v2).unwrap();		
		let r_val = E::Fr::deserialize(&mut v2).unwrap();		
		let p_r_val = E::Fr::deserialize(&mut v2).unwrap();		
		let res = KZGClaim::<E>{
			kzg: kzg_val,
			r: r_val,
			p_r: p_r_val
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (kzg: {:?}, r: {:?}, p_r: {:?})", prefix, self.kzg, 
			self.r, self.p_r);
	} 

}

impl <E:PairingEngine> Claim for KZGClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg  = res.kzg;
		self.r = res.r;
		self.p_r = res.p_r;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&KZGClaim::<E> = obj.as_any().
			downcast_ref::<KZGClaim<E>>().unwrap();
		return self.kzg==other.kzg && self.r==other.r && self.p_r==other.p_r;
	}
}

impl <E:PairingEngine> Protocol<E> for KZG <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "KZG";
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let mut t1 = Timer::new();
		t1.start();
		let kinp:&mut KZGInput::<E> = inp.as_any_mut().
			downcast_mut::<KZGInput<E>>().unwrap();
		//1. compute the W polynomial
		let mut dp = kinp.p.clone();
		let val = kinp.p.eval(&kinp.r);
		let pval = get_poly::<E::Fr>(vec![val]);
		let mut dpval = DisPoly::<E::Fr>::from_serial(0, &pval, &pval.degree()+1);
		let mut dp1 = DisPoly::<E::Fr>::sub(&mut dp, &mut dpval);

		let zero = E::Fr::zero();
		let neg_r = zero - kinp.r;
		//p2(x) = (x-r)
		let p2= get_poly::<E::Fr>(vec![neg_r, E::Fr::from(1u64)]); 
		let mut dp2 = DisPoly::<E::Fr>::from_serial(0, &p2, &p2.degree()+1);
		let (mut dq, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(&mut dp1, &mut dp2);	
		let bzero = dr.is_zero();
		if RUN_CONFIG.my_rank==0{//only check at main processor 0
			assert!(bzero, "KZG::prove() ERR: remainder of step1 != 0!");
		}
		t1.stop();

		//2. evaluate the W polynomial (takes about 10 times more)
		let mut t2 = Timer::new();
		dq.to_partitions();
		t2.start();
		let wval = self.key.gen_kzg(&mut dq)[0]; //g^{w(alpha)}
		let kprf = KZGProof::<E>{w: wval};
		t2.stop();
		return Box::new(kprf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut KZGInput::<E> = inp.as_any_mut().
			downcast_mut::<KZGInput<E>>().unwrap();
		//1. compute the W polynomial
		let val = kinp.p.eval(&kinp.r);
		let kzg = self.key.gen_kzg(&mut kinp.p)[0];
		let claim = KZGClaim::<E>{
			kzg: kzg,
			r: kinp.r,
			p_r: val
		};
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let kzg_claim:&KZGClaim::<E> = claim.as_any().
			downcast_ref::<KZGClaim<E>>().unwrap();
		let kzg_proof:&KZGProof::<E> = proof.as_any().
			downcast_ref::<KZGProof<E>>().unwrap();

		//2. check e(kzg/g^p(r), g) = e(w, g^(alpha)/g^r)
		// g^{p(alpha) - p_r}
		let q_kzg_pr = kzg_claim.kzg.into_projective() - &self.key.g.into_affine().mul(kzg_claim.p_r);
		// g^{alpha - r}
		let g2_alpha_r = self.key.g_alpha_g2.into_projective() - &self.key.g_g2.mul(kzg_claim.r);
		let gt_left = E::pairing(q_kzg_pr, self.key.g_g2);
		let gt_right = E::pairing(kzg_proof.w, g2_alpha_r);
		// e(g^{p(alpha-p_r)}, g) == e(g^W, g^{alpha-r})
		return gt_left == gt_right;
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("KZG::rand_inst ERR: make n < key.n-16!");}
		
		let mut rng = gen_rng_from_seed(seed);
		let kzg = KZG::<E>::new(key); 		
		let r = E::Fr::rand(&mut rng);
		let p = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp = DisPoly::<E::Fr>::from_serial(0, &p, &p.degree()+1);
		dp.to_partitions();
		let mut inp: KZGInput<E> = KZGInput{p: dp, r: r};  
		let prf = kzg.prove(&mut inp);
		let mut claim = kzg.claim(&mut inp);
		if b_set_err { //introduce an error for unit testing
			let kclaim:&KZGClaim::<E> = claim.as_any().
				downcast_ref::<KZGClaim<E>>().unwrap();
			let new_r = r + E::Fr::from(1u64);
			let bad_claim: KZGClaim<E> = KZGClaim{
				kzg: kclaim.kzg.clone(),
				r: new_r, 
				p_r: kclaim.p_r.clone()
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(kzg), Box::new(inp), claim, prf);
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let kzg_proto = KZG{ key: key};
		return kzg_proto;
	}
}

