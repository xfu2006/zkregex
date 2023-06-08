/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/22/2022
	Completed: 07/23/2022
*/

///This module defines the zero knowledge polynomial proof (see paper draft
/// pi_poly protocol. 
///
/// Claim: given C_q(x) and C_r where C_q(x) = g^{q(x)} h^{r) and
/// C_r = g^r h^r_2, prove that 
/// (1) the prover knows the q(x) behind C_q(x) and
/// (2) the random nonce r used in C_q(x) is the exponent on g_1 in C_r 
/// Assumption: C_q(x) and C_r can be both regarded as Pedersen Commitment,
/// Thus, the pairwise DLOG between {g,h} is unknown.
///
/// Proof Idea:
/// (1) Prover samples r_3 and generates Cq' = g^{\beta q(alpha)} h^{r_3}
///		Generates t = (h^\beta)^r h^{-r_3}
///		Verifier verifies: valdiity of Cq' using pairing (knowledge extraction
///			proof of KZG, i.e.
///			e(C_q(x), h^beta) = e(Cq' * t, h)
/// (2) Prover proves that t has the same exponent of r with C_r
///   by running the zk_same protocol
///
/// Performance: 32k key: 4sec proof time, 4ms (3 ms for 2 pairing and 1 ms
/// for zk_same proof).

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
use proto::zk_same::*;
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
//  Data Structures: ZkPoly Claim, Proof, and Input
// --------------------------------------------------- 

#[derive(Clone)]
pub struct ZkPolyInput<E:PairingEngine>{
	/// the polynomail to prove
	pub q: DisPoly<E::Fr>,	
	/// the random nonce for C_q = g^{q(alpha} h^r
	pub r: E::Fr,
	/// the randon nonce for C_r = g^r h^{r2} 
	pub r2: E:: Fr
}

#[derive(Clone)]
pub struct ZkPolyProof<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// C_q2 is the C_q' in doc. Which is: g^{\beta q(\alpha)} h^r3
	pub c_q2: E::G1Affine,
	/// t: the balancing term. Which is: (h^\beta)^r h^{-r3}
	pub t: E::G1Affine,
	/// the prf_same instance
	pub prf_same: ZkSameProof<E::G1Affine> 
}

/// The prover knows the q(x) behind c_q and the r behind c_r and
/// the r is used as random nonce in c_q
#[derive(Clone)]
pub struct ZkPolyClaim<E: PairingEngine>{
	/// the extended KZG commitment of q(x), i.e., g^{q(\alpha)} h^r
	pub c_q: E::G1Affine,
	/// the Pedersen commitment of r, i.e., g^r h^{r2}
	pub c_r: E::G1Affine,
}

/// The ZkPoly protocol contains a prover key: {g^{alpha^0}, ..., g^{alpha^n},
/// and the scaled series g^{beta alpha^0}, ..., g^{beta alpha^n}}, and
/// a second generator h.
/// Capacity n is set up when the ZkPoly protocol is constructed using new()
#[derive(Clone)]
pub struct ZkPoly<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>
{
	/// Prover key 
	pub key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for ZkPolyInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkPolyProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_q2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.t, &mut b1).unwrap();
		let mut b2 = self.prf_same.to_bytes();
		b1.append(&mut b2);
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let start_pos= E::G1Affine::zero().serialized_size()*2;
		let v3 = &v[start_pos..].to_vec();
		let mut v2 = &v[..];
		let c_q2 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let t = E::G1Affine::deserialize(&mut v2).unwrap();		
		let prf_same = ZkSameProof::<E::G1Affine>::static_from_bytes(&mut v3.to_vec());
		let res = ZkPolyProof::<E>{c_q2: c_q2, t: t, prf_same: *prf_same};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkPolyPrf(c_q2: {:?}, t: {:?}, ", 
			prefix, self.c_q2, self.t);
		self.prf_same.dump(" ");
		print!(") \n");
	} 
}

impl <E:PairingEngine> Proof for ZkPolyProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_q2 = res.c_q2.clone();
		self.t= res.t.clone();
		self.prf_same = res.prf_same.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkPolyProof::<E> = other.as_any().
			downcast_ref::<ZkPolyProof<E>>().unwrap();
		return self.c_q2==obj.c_q2 && self.t==obj.t 
			&& self.prf_same.equals(&obj.prf_same);
	}
}

impl <E:PairingEngine> ProtoObj for ZkPolyClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_q, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_r, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c_q= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_r= E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkPolyClaim::<E>{c_q: c_q, c_r: c_r};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkPolyClaim: c_q: {:?}, c_r: {:?})", prefix, 
			self.c_q, self.c_r);
	} 
}

impl <E:PairingEngine> Claim for ZkPolyClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_q= res.c_q;
		self.c_r= res.c_r;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkPolyClaim::<E> = obj.as_any().
			downcast_ref::<ZkPolyClaim<E>>().unwrap();
		return self.c_q==other.c_q && self.c_r==other.c_r;
	}
}

impl <E:PairingEngine> Protocol<E> for ZkPoly <E>  where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// return the name
	fn name(&self)->&str{
		return "ZkPoly";
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let mut t1 = Timer::new();
		t1.start();

		//0. downcast input
		let kinp:&mut ZkPolyInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkPolyInput<E>>().unwrap();

		//1. compute the c_q2 
		let mut dq = kinp.q.clone();
		dq.to_partitions();
		let mut rng = gen_rng();
		let r3 = E::Fr::rand(&mut rng);
		let gq = self.key.gen_kzg_beta(&mut dq)[0]; //g^{beta q(alpha)}
		let hr = self.key.h.mul(r3).into_affine();
		let c_q2 = gq + hr; 

		//2. compute t
		let zero = E::Fr::zero();
		let neg_r3 = zero - r3;
		let t = self.key.h_beta.mul(kinp.r) + self.key.h.mul(neg_r3);

		//3. construct the prf_same
		let exps = vec![
			vec![kinp.r, kinp.r2], //C_r
			vec![kinp.r, neg_r3], //t
		];
		let mut zksame_input = ZkSameInput::<E::G1Affine>{ exps: exps };
		let bases = vec![
			vec![self.key.g.into_affine(), self.key.h],
			vec![self.key.h_beta, self.key.h]
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let zksame_prf = zksame.prove(&mut zksame_input).as_any().
			downcast_ref::<ZkSameProof<E::G1Affine>>().unwrap().clone(); 

		//3. return proof
		let kprf = ZkPolyProof::<E>{
			c_q2: c_q2, 
			t: t.into_affine(), 
			prf_same: zksame_prf
		};
		return Box::new(kprf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkPolyInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkPolyInput<E>>().unwrap();
		let c_q = self.key.gen_kzg(&mut kinp.q)[0] + 
			self.key.h.mul(kinp.r).into_affine();
		let c_r = self.key.g.into_affine().mul(kinp.r) 
			+ self.key.h.mul(kinp.r2);
		let claim = ZkPolyClaim::<E>{ c_q: c_q, c_r: c_r.into_affine() };
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//1. type casting
		let p_claim:&ZkPolyClaim::<E> = claim.as_any().
			downcast_ref::<ZkPolyClaim<E>>().unwrap();
		let p_proof:&ZkPolyProof::<E> = proof.as_any().
			downcast_ref::<ZkPolyProof<E>>().unwrap();
		let bases = vec![
			vec![self.key.g.into_affine(), self.key.h],
			vec![self.key.h_beta, self.key.h]
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());

		//2. check equation of pairing e(Cq, h^beta) = e(Cq', h) t1
		if RUN_CONFIG.my_rank!=0 {return true;} //only check on main node
		let lhs = E::pairing(p_claim.c_q, self.key.h_beta_g2);
		let rhs = E::pairing(p_proof.c_q2 + p_proof.t, self.key.h_g2);
		if lhs!=rhs {
			return false;
		}

		//3. check the prf_same instance 
		let y = vec![p_claim.c_r, p_proof.t];
		let zksame_claim = ZkSameClaim::<E::G1Affine>{y: y}; 
		let bres = zksame.verify(&zksame_claim, &p_proof.prf_same); 
		if !bres{
			return false;
		}
		return true; //passed
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkPoly::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let mut rng = gen_rng_from_seed(seed);
		let zkpoly = ZkPoly::<E>::new(key); 		
		let r = E::Fr::rand(&mut rng);
		let r2 = E::Fr::rand(&mut rng);
		let p = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp = DisPoly::<E::Fr>::from_serial(0, &p, &p.degree()+1);
		dp.to_partitions();

		//2. generate the input and then claim and proof
		let mut inp: ZkPolyInput<E> = ZkPolyInput{q: dp, r: r, r2: r2};  
		let prf = zkpoly.prove(&mut inp);
		let mut claim = zkpoly.claim(&mut inp);
		if b_set_err { //introduce an error for unit testing
			let kclaim:&ZkPolyClaim::<E> = claim.as_any().
				downcast_ref::<ZkPolyClaim<E>>().unwrap();
			let new_c_r = kclaim.c_r + E::G1Affine::rand(&mut rng);
			let bad_claim: ZkPolyClaim<E> = ZkPolyClaim{
				c_q: kclaim.c_q.clone(),
				c_r: new_c_r,
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(zkpoly), Box::new(inp), claim, prf);
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let zp_proto = ZkPoly{key: key};
		return zp_proto;
	}

}


impl <E:PairingEngine> ZkPoly <E>  where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// If g^q(alpha) is already given, the proof
	/// can be generated faster.
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	/// gq_beta: g^q(alpha)*beta, r and r2 are as defined in ZkPolyInput
	/// r: used for C_q = g^{q(alpha)} h^r
	/// r2: used for C_r = g^r h^{r2}
	pub fn shortcut_prove(&self, gq_beta: E::G1Affine, r: E::Fr, r2: E::Fr) 
	-> Box<dyn Proof> {
		let mut t1 = Timer::new();
		t1.start();

		//1. compute the c_q2 
		let mut rng = gen_rng();
		let r3 = E::Fr::rand(&mut rng);
		let hr = self.key.h.mul(r3).into_affine();
		let c_q2 = gq_beta + hr; 

		//2. compute t
		let zero = E::Fr::zero();
		let neg_r3 = zero - r3;
		let t = self.key.h_beta.mul(r) + self.key.h.mul(neg_r3);

		//3. construct the prf_same
		let exps = vec![
			vec![r, r2], //C_r
			vec![r, neg_r3], //t
		];
		let mut zksame_input = ZkSameInput::<E::G1Affine>{ exps: exps };
		let bases = vec![
			vec![self.key.g.into_affine(), self.key.h],
			vec![self.key.h_beta, self.key.h]
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let zksame_prf = zksame.prove(&mut zksame_input).as_any().
			downcast_ref::<ZkSameProof<E::G1Affine>>().unwrap().clone(); 

		//3. return proof
		let kprf = ZkPolyProof::<E>{
			c_q2: c_q2, 
			t: t.into_affine(), 
			prf_same: zksame_prf
		};
		return Box::new(kprf);
	}

	/// generate the claim (similarly the shortcut way)
	/// NOTE only return valid result in main processor 0
	pub fn shoftcut_claim(&self, gq: E::G1Affine, r: E::Fr, r2: E::Fr) 
	-> Box<dyn Claim> {
		let c_q = gq + self.key.h.mul(r).into_affine();
		let c_r = self.key.g.into_affine().mul(r) 
			+ self.key.h.mul(r2);
		let claim = ZkPolyClaim::<E>{ c_q: c_q, c_r: c_r.into_affine() };
		return Box::new(claim);
	}

}
