/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/15/2022
	Completed: 07/15/2022
*/

/// This module defines the subset protocol (non-zk version)
///
/// Given the KZG commitment to two polynomials: superset(x) and subset(x)
/// Prove that the subset is indeed a subset of the superset.
/// It is assumed that superset(x) can be defined as
/// superset(x) = (x-a_1)....(x_a_n)
/// Similarly is subset(x) defined. Both sets can be multi-set (i.e.,
/// one element can appear multiple times).
///
/// Proof idea: simply calculate w(x) = superset(x)/subset(x)
/// Then show that e(g^superset(alpha), h) = e(g^w(alpha), h^subset(alpha))
/// In practice: the subset(x) polynomial is MUCH smaller than 
/// the w(x), so better put g^w(alpha) in group G1.
///
/// Performance: 16k: 2.7 sec, 1M: 178 sec (prover); verify: 2-4ms
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
//use self::ark_ff::{Zero};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
//use self::ark_ff::UniformRand;
use std::any::Any;

use proto::*;
use poly::dis_poly::*;
//use poly::dis_key::*;
//use poly::serial::*;
use tools::*;
use crate::profiler::config::*;

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// --------------------------------------------------- 
//  Data Structures: Claim, Proof, and Input
// --------------------------------------------------- 
#[derive(Clone)]
pub struct SubsetInput<E:PairingEngine>{
	/// the superset polynomail 
	pub p_superset: DisPoly<E::Fr>,	
	/// the subset polynomail 
	pub p_subset: DisPoly<E::Fr>,	
}

#[derive(Clone)]
pub struct SubsetProof<E: PairingEngine>{
	/// the proof such that e(w, g^subset(alpha)) = e(superset(alpha), g)
	pub w: E::G1Affine
}

/// The claim is that secret polynomial superset(x) hidden behind the
/// kzg_superset is indeed the superset of the polynomial behind the
/// kzg_subset
#[derive(Clone)]
pub struct SubsetClaim<E: PairingEngine>{
	/// the kzg commitment of some superset(x)
	pub kzg_superset: E::G1Affine,
	/// the kzg commitment of some superset(x) over group G2
	pub kzg_subset: E::G2Affine,
}

/// The Subset protocol contains a prover key: {g^{alpha^0}, ..., g^{alpha^n}}.
/// The key also needs to contain the same series over group G2.
#[derive(Clone)]
pub struct Subset<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}} on both G1 and G2
	pub key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for SubsetInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for SubsetProof<E> {
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
		let res = SubsetProof::<E>{w: w};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (w: {:?})", prefix, self.w);
	} 
}

impl <E:PairingEngine> Proof for SubsetProof<E> {
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.w = res.w.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&SubsetProof::<E> = other.as_any().
			downcast_ref::<SubsetProof<E>>().unwrap();
		return self.w==obj.w;
	}
}

impl <E:PairingEngine> ProtoObj for SubsetClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg_superset, &mut b1).unwrap();
		E::G2Affine::serialize(&self.kzg_subset, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let kzg_superset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let kzg_subset = E::G2Affine::deserialize(&mut v2).unwrap();		
		let res = SubsetClaim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (kzg_superset: {:?}, kzg_subset: {:?})", 
			prefix, self.kzg_superset, self.kzg_subset);
	} 
}

impl <E:PairingEngine> Claim for SubsetClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg_superset  = res.kzg_superset;
		self.kzg_subset  = res.kzg_subset;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&SubsetClaim::<E> = obj.as_any().
			downcast_ref::<SubsetClaim<E>>().unwrap();
		return self.kzg_superset==other.kzg_superset && 
			self.kzg_subset==other.kzg_subset;
	}
}

impl <E:PairingEngine> Protocol<E> for Subset <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "Subset";
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//let mut t1 = Timer::new();
		//t1.start();
		let sinp:&SubsetInput::<E> = inp.as_any_mut().
			downcast_mut::<SubsetInput<E>>().unwrap();
		//1. compute the W polynomial
		let mut p_superset = sinp.p_superset.clone();
		let mut p_subset = sinp.p_subset.clone();
		let (mut dq, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(
			&mut p_superset, &mut p_subset);
		let bzero = dr.is_zero();
		if RUN_CONFIG.my_rank==0{//only check at main processor 0
			assert!(bzero, "Subset::prove() ERR: remainder of step1 != 0!");
		}
		//t1.stop();

		//2. evaluate the W polynomial (takes about 10 times more)
		//let mut t2 = Timer::new();
		//t2.start();
		dq.to_partitions();
		let wval = self.key.gen_kzg(&mut dq)[0]; //g^{w(alpha)}
		let kprf = SubsetProof::<E>{w: wval};
		//t2.stop();
		return Box::new(kprf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let sinp:&mut SubsetInput::<E> = inp.as_any_mut().
			downcast_mut::<SubsetInput<E>>().unwrap();
		//1. compute the W polynomial
		let kzg_superset = self.key.gen_kzg(&mut sinp.p_superset)[0];
		let kzg_subset = self.key.gen_kzg_g2(&mut sinp.p_subset)[0];
		let claim = SubsetClaim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
		};
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let s_claim:&SubsetClaim::<E> = claim.as_any().
			downcast_ref::<SubsetClaim<E>>().unwrap();
		let s_proof:&SubsetProof::<E> = proof.as_any().
			downcast_ref::<SubsetProof<E>>().unwrap();

		//2. check e(kzg_superset, g) = e(w, kgz_subset)
		let gt_left = E::pairing(s_claim.kzg_superset, self.key.g_g2);
		let gt_right = E::pairing(s_proof.w, s_claim.kzg_subset);
		return gt_left == gt_right;
	}

	/// generate a random instance. n is the degree of subset polynomial,
	/// the dgree of superset polynomial is 2n.
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key:Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("Subset::rand_inst() error: make n<key.n-16!");}

		//1. get two random polynomials
		let n = n/2;		 //make it half.
		let mut rng = gen_rng_from_seed(seed);
		let proto = Subset::<E>::new(key); 		 //factory instance
		let p_factor= DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_factor= DisPoly::<E::Fr>::from_serial(0, &p_factor, &p_factor.degree()+1);
		let p_subset = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_subset = DisPoly::<E::Fr>::from_serial(0, &p_subset, &p_subset.degree()+1);
		let mut dp_superset = DisPoly::<E::Fr>::mul(&mut dp_factor, &mut dp_subset);
		dp_subset.to_partitions();
		dp_superset.to_partitions(); 

		//2. builds SubsetInput 
		let mut inp: SubsetInput<E> = SubsetInput{
			p_superset: dp_superset, p_subset: dp_subset};  
		let prf = proto.prove(&mut inp);
		let mut claim = proto.claim(&mut inp);

		//3. introduce error if asked
		if b_set_err { 
			let kclaim:&SubsetClaim::<E> = claim.as_any().
				downcast_ref::<SubsetClaim<E>>().unwrap();
			let new_kzg_subset = kclaim.kzg_subset.mul(2u32).into_affine();
			let bad_claim: SubsetClaim<E> = SubsetClaim{
				kzg_superset: kclaim.kzg_superset.clone(),
				kzg_subset: new_kzg_subset
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let proto = Subset{ key: key};
		return proto;
	}
}

