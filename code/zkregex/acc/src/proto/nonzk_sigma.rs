
/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/15/2022
	Completed: 07/15/2022
*/

/// This module defines the nonzk-Sigma protocol. This protocol can be applied
/// to the case for software distribution (where contents) can be visible
/// to verifier, but people desire fast and short proof.
///
/// The basic idea is to combine the subset and kzg proof. Given that
/// the anti-virus has already published the KZG of the AC-DFA. 
/// The prover (software developer) releases a KZG of the state and
/// transition set of running her executable over the AC-DFA.
/// The proof then has 2 parts: (1) the transition/set produced
/// by traversing AC-DFA is a subset of the anti-virus released 
/// super-set; (2) the polynomial corresponds to the one committed
/// in the circuit. 
///
/// Performance: 1M: prover time 201 sec, verify 10ms
/// 8 nodes on one computer

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
use self::ark_poly::{Polynomial};
//use self::ark_ff::{Zero};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;
use std::any::Any;
use std::rc::Rc;

use proto::*;
use proto::subset::*;
use proto::kzg::*;
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
pub struct NonzkSigmaInput<E:PairingEngine>{
	/// the superset polynomail 
	pub p_superset: DisPoly<E::Fr>,	
	/// the subset polynomail 
	pub p_subset: DisPoly<E::Fr>,	
	/// the r for evaluating p_subset
	pub r: E::Fr,
}

#[derive(Clone)]
pub struct NonzkSigmaProof<E: PairingEngine>{
	/// the proof to shta that p_subset is a factor of p_superset
	pub prf_subset: SubsetProof<E>,
	/// proof that p_subset evaluates to p_r at r
	pub prf_kzg: KZGProof<E>,
	/// g^{p_subset(alpha)} at G2
	pub kzg_subset_g2: E::G2Affine,
}

/// The claim has two parts: (1) subset relation between superset and
/// subset poly behind kzgs; (2) the subset polynomial evaluates to p_r
/// at point r.
#[derive(Clone)]
pub struct NonzkSigmaClaim<E: PairingEngine>{
	/// the kzg commitment of some superset(x)
	pub kzg_superset: E::G1Affine,
	/// the kzg commitment of some superset(x) 
	pub kzg_subset: E::G1Affine,
	/// the random point r
	pub r: E::Fr,
	/// the value of p_subset(r)
	pub p_r: E::Fr,
}

#[derive(Clone)]
pub struct NonzkSigma<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}} on both G1 and G2
	pub key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for NonzkSigmaInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for NonzkSigmaProof<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1 = self.prf_subset.to_bytes();
		let mut b2 = self.prf_kzg.to_bytes();
		let mut b3 = vec![];
		E::G2Affine::serialize(&self.kzg_subset_g2, &mut b3).unwrap();
		b1.append(&mut b2);
		b1.append(&mut b3);
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		// This approach is wasting on speed though. should have
		// used reader interface. refactor later.
		let prf_subset = SubsetProof::<E>::static_from_bytes(v);
		let size1 = prf_subset.to_bytes().len();
		let v2 = v[size1..].to_vec();
		let prf_kzg = KZGProof::<E>::static_from_bytes(&v2);
		let size2 = prf_kzg.to_bytes().len();
		let mut v3 = &v2[size2..];
		let kzg_subset_g2 = E::G2Affine::deserialize(&mut v3).unwrap();		
		let res = NonzkSigmaProof::<E>{
			prf_subset: *prf_subset,
			prf_kzg: *prf_kzg,
			kzg_subset_g2: kzg_subset_g2 
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		print!("{} NonzkSigmaProof: (", prefix);
		self.prf_subset.dump("prf_subset: ");
		self.prf_kzg.dump("prf_kzg: ");
		println!("kzg_subset_g2: {} )", self.kzg_subset_g2);
	} 
}

impl <E:PairingEngine> Proof for NonzkSigmaProof<E> {
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.prf_subset = res.prf_subset.clone();
		self.prf_kzg= res.prf_kzg.clone();
		self.kzg_subset_g2= res.kzg_subset_g2.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&NonzkSigmaProof::<E> = other.as_any().
			downcast_ref::<NonzkSigmaProof<E>>().unwrap();
		return self.prf_subset.equals(&obj.prf_subset) &&
			self.prf_kzg.equals(&obj.prf_kzg) &&
			self.kzg_subset_g2 == obj.kzg_subset_g2;
	}
}


impl <E:PairingEngine> ProtoObj for NonzkSigmaClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg_superset, &mut b1).unwrap();
		E::G1Affine::serialize(&self.kzg_subset, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		E::Fr::serialize(&self.p_r, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let kzg_superset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let kzg_subset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let r = E::Fr::deserialize(&mut v2).unwrap();		
		let p_r = E::Fr::deserialize(&mut v2).unwrap();		
		let res = NonzkSigmaClaim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
			r: r, 
			p_r: p_r
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (kzg_superset: {:?}, kzg_subset: {:?}, r: {:?}, p_r{:?})", 
			prefix, self.kzg_superset, self.kzg_subset, self.r, self.p_r);
	} 
}

impl <E:PairingEngine> Claim for NonzkSigmaClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg_superset  = res.kzg_superset;
		self.kzg_subset  = res.kzg_subset;
		self.r = res.r;
		self.p_r = res.p_r;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&NonzkSigmaClaim::<E> = obj.as_any().
			downcast_ref::<NonzkSigmaClaim<E>>().unwrap();
		return self.kzg_superset==other.kzg_superset && 
			self.kzg_subset==other.kzg_subset &&
			self.r ==other.r && 
			self.p_r ==other.p_r;
	}
}

impl <E:PairingEngine> Protocol<E> for NonzkSigma <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "NonzkSigma";
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let sinp:&mut NonzkSigmaInput::<E> = inp.as_any_mut().
			downcast_mut::<NonzkSigmaInput<E>>().unwrap();
		//1. compute the prf_subset
		let mut subset_input = SubsetInput::<E>{
			p_superset: sinp.p_superset.clone(),
			p_subset: sinp.p_subset.clone()
		};
		let key2 = self.key.clone();
		let key3 = self.key.clone();
		let proto_subset = Subset::new(key2);
		let prf_subset = proto_subset.prove(&mut subset_input).as_any().
			downcast_ref::<SubsetProof<E>>().unwrap().clone();
		
		//2. compute the prf_kzg
		let mut kzg_input = KZGInput::<E>{
			p: sinp.p_subset.clone(),
			r: sinp.r.clone() 
		};
		let proto_kzg = KZG::new(key3);
		let prf_kzg= proto_kzg.prove(&mut kzg_input).as_any().
			downcast_ref::<KZGProof<E>>().unwrap().clone();

		//3. compute the kzg_subset_g2
		let kzg_subset_g2 = self.key.gen_kzg_g2(&mut sinp.p_subset)[0]; 
		let prf = NonzkSigmaProof::<E>{
			prf_subset: prf_subset,
			prf_kzg: prf_kzg,
			kzg_subset_g2: kzg_subset_g2	
		};
		return Box::new(prf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let sinp:&mut NonzkSigmaInput::<E> = inp.as_any_mut().
			downcast_mut::<NonzkSigmaInput<E>>().unwrap();
		//1. compute the W polynomial
		let kzg_superset = self.key.gen_kzg(&mut sinp.p_superset)[0];
		let kzg_subset = self.key.gen_kzg(&mut sinp.p_subset)[0];
		let p_r = sinp.p_subset.eval(&sinp.r);
		let claim = NonzkSigmaClaim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
			r: sinp.r,
			p_r: p_r,
		};
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let n_claim:&NonzkSigmaClaim::<E> = claim.as_any().
			downcast_ref::<NonzkSigmaClaim<E>>().unwrap();
		let n_proof:&NonzkSigmaProof::<E> = proof.as_any().
			downcast_ref::<NonzkSigmaProof<E>>().unwrap();

		//1. check the validity of two subproofs
		let key2 = self.key.clone();
		let key3 = self.key.clone();
		let proto_subset = Subset::new(key2);
		let sclaim = SubsetClaim::<E>{
			kzg_superset: n_claim.kzg_superset,
			kzg_subset: n_proof.kzg_subset_g2
		};
		let b1 = proto_subset.verify(&sclaim, &n_proof.prf_subset);
		if !b1 {return false;}

		let proto_kzg= KZG::new(key3);
		let kclaim = KZGClaim::<E>{
			kzg: n_claim.kzg_subset,
			r: n_claim.r,
			p_r: n_claim.p_r
		};
		let b2 = proto_kzg.verify(&kclaim, &n_proof.prf_kzg);
		if !b2 {return false;}

		//3. check e(g, kzg_subset_g2) = e(kzg_subset, g)
		let gt_right= E::pairing(self.key.g, n_proof.kzg_subset_g2);
		let gt_left= E::pairing(n_claim.kzg_subset, self.key.g_g2);
		return gt_left == gt_right;
	}

	/// generate a random instance. n is the degree of subset polynomial,
	/// the dgree of superset polynomial is 2n.
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}

		//1. get two random polynomials	
		let n2 = n/2-2;	 
		let mut rng = gen_rng_from_seed(seed);
		let proto = NonzkSigma::<E>::new(key); 		 //factory instance
		let set1 = rand_arr_field_ele::<E::Fr>(n2, seed); 
		let set2 = rand_arr_field_ele::<E::Fr>(n2, seed+21771); 
		let p_factor= DisPoly::<E::Fr>::binacc_poly(&set1);
		let mut dp_factor= DisPoly::<E::Fr>::from_serial(0, &p_factor, &p_factor.degree()+1);
		let p_subset= DisPoly::<E::Fr>::binacc_poly(&set2);
		let mut dp_subset = DisPoly::<E::Fr>::from_serial(0, &p_subset, &p_subset.degree()+1);
		let mut dp_superset = DisPoly::<E::Fr>::mul(&mut dp_factor, &mut dp_subset);
		dp_subset.to_partitions();
		dp_superset.to_partitions(); 
		let r = E::Fr::rand(&mut rng);

		//2. builds NonzkSigmaInput 
		let mut inp: NonzkSigmaInput<E> = NonzkSigmaInput{
			p_superset: dp_superset, 
			p_subset: dp_subset,
			r: r
		};  
		let prf = proto.prove(&mut inp);
		let mut claim = proto.claim(&mut inp);

		//3. introduce error if asked
		if b_set_err { 
			let kclaim:&NonzkSigmaClaim::<E> = claim.as_any().
				downcast_ref::<NonzkSigmaClaim<E>>().unwrap();
			let new_kzg_subset = kclaim.kzg_subset.mul(2u32).into_affine();
			let bad_claim: NonzkSigmaClaim<E> = NonzkSigmaClaim{
				kzg_superset: kclaim.kzg_superset.clone(),
				kzg_subset: new_kzg_subset,
				r: kclaim.r,
				p_r: kclaim.p_r
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	fn new(key: Rc<DisKey<E>>) -> Self{
		let proto = NonzkSigma{ key: key};
		return proto;
	}
}

