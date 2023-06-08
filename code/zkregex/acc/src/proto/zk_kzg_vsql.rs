/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 09/19/2022
*/

/// This module defines the blindeval KZG_VSQL protocol (see paper)
/// by adapting the zero knowledge VSQL (multi-variate polynomial commitment
/// scheme). See https://eprint.iacr.org/2017/1146.pdf
/// Basic idea: covert the CommitValue protocol of multi-variate polynomial
/// to univariate polynomial
///
/// Claim: given C_p1 = g^{p(\alpha} h^{rf}, t, C_y = g^{p(t)} h^{ry}
/// Claim that p(t) evalutes to y, which hides behind C_y. 
/// Here: h is g^{s_2} in vSQL. The following are various mapping
/// from vSQL paper to our code
///    vSQL             dis_key.rs 
///  -------------------------------------------
///     C_p1 			Comm_f1
///		s_1				alpha
///		alpha			beta
///     s_2             s_2
///     g^s_2           h
///     beta            theta
///     g^{s_2}^beta    h_theta
///
/// Proof Idea: Let w(x) = (p(x)-p(r))/(x-r).
/// prover samples ry, and r1 and builds:
/// 	C1 = g^w(alpha) h^r1 and C1b = g^{beta*w(alpha)} h^{beta*r1}
///    	C2 = g^{rf-ry - r1(alpha-t)} , C2b = C2^beta
/// Verifier verifies: 
///		(1) e(C_y, g^theta) = e(C_y2, g)
///		(2) e(C_p1/C_y, g) = e(C2, h) e(C1, g^alpha/g^t)
///		(3) e(C1, g^beta) = e(C1b, g)
///		(4) e(C2, g^beta) = e(C2b, g)
///
/// Performance: ????????
/// TEPM DATA TO REMOVE: 
/// 32k: 10 sec (prover), verification: 13 ms (8 nodes) can 
/// cut to 6 ms (1 node on 1 computer). .Size: 660 bytes
/// Rough estimate (needs fix):
/// prf_same: 4 group + 9 field; prf_poly: 2 group + 2 group + 4 field
/// main_proof: 3 group -> 11 group + 13 field      

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
//  Data Structures: zk_kzg Claim, Proof, and Input
// --------------------------------------------------- 
#[derive(Clone)]
pub struct ZkKzgVsqlInput<E:PairingEngine>{
	/// the polynomail to prove
	pub p: DisPoly<E::Fr>,	
	/// random nonce for C_p = g^{p(alpha)} h^rf
	pub rf: E::Fr,
	/// random nonce for C_y = g^{p(t)} h^{ry}
	pub ry: E::Fr,
	/// random nonce for C1 = g^w(alpha) h^r1
	pub r1: E::Fr,
	/// the random challenge t for p(t)
	pub t: E::Fr,
}

#[derive(Clone)]
pub struct ZkKzgVsqlProof<E: PairingEngine>{
	/// c1 = g^w(alpha h^r1
	pub c1: E::G1Affine,
	/// c1b = g^{w(alpha*beta} h^{r1*beta}
	pub c1b: E::G1Affine,

	/// c2 = g^{rf-ry-r1(alpha-t)}
	pub c2: E::G1Affine,
	/// c2b = g^{{rf-ry-r1(alpha-t)}*beta}
	pub c2b: E::G1Affine,

	/// cy2 = cy^theta = g^{y*theta} h^{ry*theta}
	pub cy2: E::G1Affine
}

/** it claims that the polynomial sitting behind c_p, letting it be
 p(x) evaluates to p(t) = y, and this y is behind commitment c_y
*/
#[derive(Clone)]
pub struct ZkKzgVsqlClaim<E: PairingEngine>{
	/// the commitment of p(x): g^{p(alpha)} h^rf (h is g^{s2}) in VSQL paper.
	pub c_p: E::G1Affine,
	/// the commit to y: c_y = g^y h^ry
	pub c_y: E::G1Affine,
	/// the challenge point t
	pub t: E::Fr,
}

#[derive(Clone)]
pub struct ZkKzgVsql<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>
{
	/// Prover key 
	pub key: Rc<DisKey<E>>,
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for ZkKzgVsqlInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkKzgVsqlProof<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c1, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c1b, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c2b, &mut b1).unwrap();
		E::G1Affine::serialize(&self.cy2, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c1 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let c1b = E::G1Affine::deserialize(&mut v2).unwrap();		
		let c2 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let c2b = E::G1Affine::deserialize(&mut v2).unwrap();		
		let cy2 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkKzgVsqlProof::<E>{c1:c1, c1b:c1b, c2:c2, c2b:c2b, cy2: cy2};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkKzgVsqlPrf(c1: {:?}, c1b: {:?}, c2: {:?}, c2b: {:?}, cy2: {:?}", prefix, self.c1, self.c1b, self.c2, self.c2b, self.cy2);
		print!(") \n");
	} 
}

impl <E:PairingEngine> Proof for ZkKzgVsqlProof<E> {
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c1= res.c1.clone();
		self.c1b= res.c1b.clone();
		self.c2= res.c2.clone();
		self.c2b= res.c2b.clone();
		self.cy2= res.cy2.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkKzgVsqlProof::<E> = other.as_any().
			downcast_ref::<ZkKzgVsqlProof<E>>().unwrap();
		return self.c1 == obj.c1  &&
			self.c1b == obj.c1b  &&
			self.c2 == obj.c2  &&
			self.c2b == obj.c2b  &&
			self.cy2 == obj.cy2;
	}
}

impl <E:PairingEngine> ProtoObj for ZkKzgVsqlClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_p, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_y, &mut b1).unwrap();
		E::Fr::serialize(&self.t, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c_p= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_y= E::G1Affine::deserialize(&mut v2).unwrap();		
		let t= E::Fr::deserialize(&mut v2).unwrap();		
		let res = ZkKzgVsqlClaim::<E>{c_p: c_p, c_y: c_y, t: t};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkKzgVsqlClaim: c_p: {:?}, c_y: {:?}, t: {:?}",
			prefix, self.c_p, self.c_y, self.t);
	} 
}

impl <E:PairingEngine> Claim for ZkKzgVsqlClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_p= res.c_p;
		self.c_y= res.c_y;
		self.t= res.t;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkKzgVsqlClaim::<E> = obj.as_any().
			downcast_ref::<ZkKzgVsqlClaim<E>>().unwrap();
		return self.c_p==other.c_p && self.c_y==other.c_y
			&& self.t==other.t;
	}
}

impl <E:PairingEngine> Protocol<E> for ZkKzgVsql <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkKzgVsql";
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkKzgVsqlInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkKzgVsqlInput<E>>().unwrap();
		let c_p = self.key.gen_kzg(&mut kinp.p)[0] + 
			self.key.h.mul(kinp.rf).into_affine();
		let y = kinp.p.eval(&kinp.t);
		let c_y= self.key.g.into_affine().mul(y).into_affine() + self.key.h.mul(kinp.ry).into_affine();
		let claim = ZkKzgVsqlClaim::<E>{c_p: c_p, c_y: c_y, t: kinp.t};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//0. downcast input
		let kinp:&ZkKzgVsqlInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkKzgVsqlInput<E>>().unwrap();

		//1. compute C1 and C1b
		let mut dp = kinp.p.clone();
		let val = kinp.p.eval(&kinp.t);
		let pval = get_poly::<E::Fr>(vec![val]);
		let mut dpval = DisPoly::<E::Fr>::from_serial(0, &pval, &pval.degree()+1);
		let mut dp1 = DisPoly::<E::Fr>::sub(&mut dp, &mut dpval);
		let neg_t = E::Fr::zero() - kinp.t;
		let p2= get_poly::<E::Fr>(vec![neg_t, E::Fr::from(1u64)]); 
		let mut dp2 = DisPoly::<E::Fr>::from_serial(0, &p2, &p2.degree()+1);
		dp2.to_partitions();
		let (mut dq, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(&mut dp1, &mut dp2);	
		let bzero = dr.is_zero();
		if RUN_CONFIG.my_rank==0{//only check at main processor 0
			assert!(bzero, "KZG_VSQL::prove() ERR: remainder of step1 != 0!");
		}
		dq.to_partitions();
		let w1= self.key.gen_kzg(&mut dq)[0]; //g^{w(alpha)}
		let c1= w1 + self.key.h.mul(kinp.r1).into_affine();
		let w1b = self.key.gen_kzg_beta(&mut dq)[0];
		let c1b = w1b + self.key.h_beta.mul(kinp.r1).into_affine();


		//2. compute C2 and C2b
		let rf_ry_r1t = kinp.rf - kinp.ry + kinp.r1 * kinp.t;
		let neg_r1 = E::Fr::zero() - kinp.r1;
		let c2 = (self.key.g.into_affine().mul(rf_ry_r1t) + self.key.powers_g[1].mul(neg_r1)).into_affine();
		let c2b = (self.key.powers_g_beta[0].mul(rf_ry_r1t) + self.key.powers_g_beta[1].mul(neg_r1)).into_affine();

		//3. compute Cy2
		let y = kinp.p.eval(&kinp.t);
		let cy2= self.key.g_theta.mul(y).into_affine() + self.key.h_theta.mul(kinp.ry).into_affine();

		//3. return proof
		let kprf = ZkKzgVsqlProof::<E>{ 
			c1: c1, c1b: c1b, c2: c2, c2b: c2b, cy2: cy2 };
		return Box::new(kprf);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//1. type casting
		let mut t = Timer::new();
		t.start();
		let p_claim:&ZkKzgVsqlClaim::<E> = claim.as_any().
			downcast_ref::<ZkKzgVsqlClaim<E>>().unwrap();
		let p_proof:&ZkKzgVsqlProof::<E> = proof.as_any().
			downcast_ref::<ZkKzgVsqlProof<E>>().unwrap();
		let g = self.key.g_g2;
		let h = self.key.h_g2;
		let g_beta = self.key.g_beta_g2;
		let g_theta = self.key.g_theta_g2; 
		t.stop();
		if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 801: set up time: {}us", t.time_us);}

		//		(1) e(C_y, g^theta) = e(C_y2, g)
		let mut t = Timer::new();
		t.start();
		let lhs = E::pairing(p_claim.c_y, g_theta);
		let rhs = E::pairing(p_proof.cy2, g);
		if lhs!=rhs{
			println!("WARNING1: fails e(C_y, g^theta) = e(C_y2, g)");
			return false;
		}
		t.stop();
		if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 802: paring 1-2: {}us", t.time_us);}
		
		//		(2) e(C1, g^beta) = e(C1b, g)
		let mut t = Timer::new();
		t.start();
		let lhs = E::pairing(p_proof.c1, g_beta);
		let rhs = E::pairing(p_proof.c1b, g);
		if lhs!=rhs{
			println!("WARNING2: fails e(C1, g^beta) = e(C1b, g)");
			return false;
		}
		t.stop();
		if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 803: pairing 3-4 time: {}us", t.time_us);}

		//		(3) e(C2, g^beta) = e(C2b, g)
		let mut t = Timer::new();
		t.start();
		let lhs = E::pairing(p_proof.c2, g_beta);
		let rhs = E::pairing(p_proof.c2b, g);
		if lhs!=rhs{
			println!("WARNING3: fails e(C2, g^beta) = e(C2b, g)");
			return false;
		}
		t.stop();
		if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 804: pairing 5-6: {}us", t.time_us);}

		//		(4) e(C_p1/C_y, g) = e(C2, h) e(C1, g^alpha/g^t)
		let mut t = Timer::new();
		t.start();
		let cp1_y = p_claim.c_p.into_projective()  - p_claim.c_y.into_projective();
		let galpha_t = self.key.g_alpha_g2.into_projective() - self.key.g_g2.mul(p_claim.t);
		let lhs = E::pairing(cp1_y, g);
		let rhs1 = E::pairing(p_proof.c2, h);
		let rhs2 = E::pairing(p_proof.c1, galpha_t);
		let rhs = rhs1 * rhs2;
		if lhs!=rhs{
			println!("WARNING4: fails e(C_p1/C_y, g) = e(C2, h) e(C1, g^alpha/g^t)");
			return false;
		}
		t.stop();
		if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 805: pairing 7-9: {}us", t.time_us);}

		return true; //passed
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkKzgVsql::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let mut rng = gen_rng_from_seed(seed);
		let zk = ZkKzgVsql::<E>::new(key); 		
		let rf = E::Fr::rand(&mut rng);
		let ry = E::Fr::rand(&mut rng);
		let r1 = E::Fr::rand(&mut rng);
		let t = E::Fr::rand(&mut rng);
		let p = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp = DisPoly::<E::Fr>::from_serial(0, &p, &p.degree()+1);
		dp.to_partitions();

		//2. generate the input and then claim and proof
		let mut inp: ZkKzgVsqlInput<E> = ZkKzgVsqlInput{p: dp, 
			rf: rf, ry: ry, r1: r1, t: t};
		let prf = zk.prove(&mut inp);
		let mut claim = zk.claim(&mut inp);

		//3. introduce err if asked
		if b_set_err { //introduce an error for unit testing
			let kclaim:&ZkKzgVsqlClaim::<E> = claim.as_any().
				downcast_ref::<ZkKzgVsqlClaim<E>>().unwrap();
			let new_c_p = kclaim.c_p + E::G1Affine::rand(&mut rng);
			let bad_claim: ZkKzgVsqlClaim<E> = ZkKzgVsqlClaim{
				c_p: new_c_p,
				c_y: kclaim.c_y.clone(),
				t: kclaim.t.clone()
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(zk), Box::new(inp), claim, prf);
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let zp_proto = ZkKzgVsql{key: key};
		return zp_proto;
	}
}

impl <E:PairingEngine> ZkKzgVsql <E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>{
	pub fn new_with_generators(key: Rc<DisKey<E>>) -> Self{
		let zp_proto = ZkKzgVsql{key: key};
		return zp_proto;
	}
}
