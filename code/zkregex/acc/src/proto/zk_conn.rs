/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 04/03/2023
*/

/// This module defines the zk_conn protocol.
/// basically it's a zkSame protocol for (c1, c2) hiding same end/start states
/// c1: g1^y1 g2^s1_1 g3^sn_1 g4^r3_1 g5^r4_1
/// c2: h1^y1 h2^s1_2 h3^sn_2 h4^r3_2 h5^r5_1
/// where sn_1 = s1_2
/// NOTE: bases gs and hs may not be the same.


/* 
NOTE: temporarily all dis_poly involved MUST have id 0 to ensure
main processor is 0. This can be relaxed after we have replaced
the dummy implementation of DisPoly mul,div,sub etc.
*/
extern crate ark_ff;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

extern crate ark_ip_proofs; 
extern crate ark_inner_products; 
extern crate ark_dh_commitments; 
extern crate blake2; 
extern crate ark_std;

use self::ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
//use self::ark_poly::{Polynomial, univariate::DensePolynomial};
use self::ark_ff::{Zero,One};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;
use self::ark_inner_products::{ExtensionFieldElement};
use proto::ripp_driver::*;

use std::any::Any;
use std::rc::Rc;

use proto::*;
//use poly::dis_poly::*;
use poly::common::*;
//use poly::dis_key::*;
//use poly::serial::*;
//use proto::zk_poly::*;
//use proto::zk_same::*;
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
pub struct ZkConnInput<E:PairingEngine>{
	/// the y value for c1
	pub y1: E::Fr,
	/// state 1 on accepthan path
	pub s11: E::Fr,
	/// last state on acceptance path
	pub sn1: E::Fr,
	/// random challenge for: c_1 = g1^{y} g2^{s1} g3^{sn} g4^(r4) g5^r5
	pub r41: E::Fr,
	/// last random  
	pub r51: E::Fr,

	/// bases for Pedersen commitment: c_1.
	pub g11: E::G1Affine,
	pub g21: E::G1Affine,
	pub g31: E::G1Affine,
	pub g41: E::G1Affine,
	pub g51: E::G1Affine,

	/// the y value for c2
	pub y2: E::Fr,
	/// state 1 on accepthan path
	pub s12: E::Fr,
	/// last state on acceptance path
	pub sn2: E::Fr,
	/// random challenge for: c_2 = g1^{y2} g2^{s12} g3^{sn2} g4^(r42) g5^r52
	pub r42: E::Fr,
	/// last random  
	pub r52: E::Fr,

	/// bases for Pedersen commitment: c_2.
	pub g12: E::G1Affine,
	pub g22: E::G1Affine,
	pub g32: E::G1Affine,
	pub g42: E::G1Affine,
	pub g52: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkConnProof<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// the random nonce DLOG proof for c1
	pub prf1_r: E::G1Affine,
	pub prf1: Vec<E::Fr>, //5 elements
	pub prf2_r: E::G1Affine,
	pub prf2: Vec<E::Fr>,
	/// the random challenge from verifier
	pub c: E::Fr,
}

/** The claim is c1 hides the same sn as the s1 of c2.
*/
#[derive(Clone)]
pub struct ZkConnClaim<E: PairingEngine>{
	/// commitment 1
	pub c_1: E::G1Affine,
	/// commitment 2
	pub c_2: E::G1Affine,
	/// 5 bases for c_1
	pub g11: E::G1Affine,
	pub g21: E::G1Affine,
	pub g31: E::G1Affine,
	pub g41: E::G1Affine,
	pub g51: E::G1Affine,
	/// 5 bases for c_2
	pub g12: E::G1Affine,
	pub g22: E::G1Affine,
	pub g32: E::G1Affine,
	pub g42: E::G1Affine,
	pub g52: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkConn<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key 
	pub key: Rc<DisKey<E>>,
}

/// aggregated proof 
#[derive(Clone)]
pub struct ZkConnAggProof<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many proofs are aggregated
	pub size: usize,
	/// challanege for DLOG (will be the hash of c_c1, c_c2 and all R's used)
	pub c: E::Fr,
	/// commitments to Z. 10 elements
	pub v_cz: Vec<E::G1Projective>,
	/// commitments to G1m. 10 elements
	pub v_cg1: Vec<ExtensionFieldElement<E>>, 
	/// z values 10 elements (for mipp)
	pub v_z: Vec<E::G1Projective>,
	/// prf of MIPP 10 elements
	pub v_prf: Vec<MyMIPPProof<E>>,
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for ZkConnInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkConnProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.prf1_r, &mut b1).unwrap();
		for i in 0..5{
			E::Fr::serialize(&self.prf1[i], &mut b1).unwrap();
		}
		E::G1Affine::serialize(&self.prf2_r, &mut b1).unwrap();
		for i in 0..5{
			E::Fr::serialize(&self.prf2[i], &mut b1).unwrap();
		}
		E::Fr::serialize(&self.c, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let prf1_r = E::G1Affine::deserialize(&mut v2).unwrap();
		let mut prf1 = vec![];
		for _i in 0..5{
			prf1.push(E::Fr::deserialize(&mut v2).unwrap());
		}
		let prf2_r = E::G1Affine::deserialize(&mut v2).unwrap();
		let mut prf2 = vec![];
		for _i in 0..5{
			prf2.push(E::Fr::deserialize(&mut v2).unwrap());
		}
		let c = E::Fr::deserialize(&mut v2).unwrap();
		let res = Self{
			prf1_r: prf1_r,
			prf1: prf1,
			prf2_r: prf2_r,
			prf2: prf2,
			c: c
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkConnPrf(prf1_r: {}, prf2_r: {}",
			prefix, self.prf1_r, self.prf2_r);
	}
}

impl <E:PairingEngine> Proof for ZkConnProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.prf1_r= res.prf1_r.clone();
		self.prf1= res.prf1.clone();
		self.prf2_r= res.prf2_r.clone();
		self.prf2= res.prf2.clone();
		self.c= res.c.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkConnProof::<E> = other.as_any().
			downcast_ref::<ZkConnProof<E>>().unwrap();
		return self.prf1_r == obj.prf1_r
			&& self.prf1 == obj.prf1
			&& self.prf2_r == obj.prf2_r
			&& self.prf2 == obj.prf2
			&& self.c== obj.c
	}
}

impl <E:PairingEngine> ProtoObj for ZkConnClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_1, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g11, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g21, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g31, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g41, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g51, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g12, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g22, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g32, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g42, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g52, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c_1= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_2= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g11= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g21= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g31= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g41= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g51= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g12= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g22= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g32= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g42= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g52= E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkConnClaim::<E>{c_1: c_1, c_2: c_2,
			g11:g11, g21: g21, g31: g31, g41:g41, g51: g51,
			g12:g12, g22: g22, g32: g32, g42:g42, g52: g52,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkConnClaim: c_1: {:?}, c_2: {:?}",
			 prefix, self.c_1, self.c_2);
	} 
}

impl <E:PairingEngine> Claim for ZkConnClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_1= res.c_1;
		self.c_2= res.c_2;
		self.g11= res.g11;
		self.g21= res.g21;
		self.g31= res.g31;
		self.g41= res.g41;
		self.g51= res.g51;
		self.g12= res.g12;
		self.g22= res.g22;
		self.g32= res.g32;
		self.g42= res.g42;
		self.g52= res.g52;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkConnClaim::<E> = obj.as_any().
			downcast_ref::<ZkConnClaim<E>>().unwrap();
		return self.c_1==other.c_1 
			&& self.c_2==other.c_2
			&& self.g11==other.g11
			&& self.g21==other.g21
			&& self.g31==other.g31
			&& self.g41==other.g41
			&& self.g51==other.g51
			&& self.g12==other.g12
			&& self.g22==other.g22
			&& self.g32==other.g32
			&& self.g42==other.g42
			&& self.g52==other.g52
	}
}

impl <E:PairingEngine> Protocol<E> for ZkConn <E>  where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkConn";
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkConnInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkConnInput<E>>().unwrap();
		let bases1 = vec![kinp.g11.clone(), kinp.g21.clone(), kinp.g31.clone(), kinp.g41.clone(), kinp.g51.clone()];
		let exp1 = vec![kinp.y1, kinp.s11, kinp.sn1, kinp.r41, kinp.r51];
		let c_1 = msm::<E>(&bases1, &exp1);

		let bases2 = vec![kinp.g12.clone(), kinp.g22.clone(), kinp.g32.clone(), kinp.g42.clone(), kinp.g52.clone()];
		let exp2 = vec![kinp.y2, kinp.s12, kinp.sn2, kinp.r42, kinp.r52];
		let c_2 = msm::<E>(&bases2, &exp2);

		let claim = ZkConnClaim::<E>{
			c_1: c_1, 
			c_2: c_2,
			g11: kinp.g11,
			g21: kinp.g21,
			g31: kinp.g31,
			g41: kinp.g41,
			g51: kinp.g51,
			g12: kinp.g12,
			g22: kinp.g22,
			g32: kinp.g32,
			g42: kinp.g42,
			g52: kinp.g52,
		};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//0. downcast input
		let kinp:&mut ZkConnInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkConnInput<E>>().unwrap();
		let bases1 = vec![kinp.g11.clone(), kinp.g21.clone(), kinp.g31.clone(), kinp.g41.clone(), kinp.g51.clone()];
		let bases2 = vec![kinp.g12.clone(), kinp.g22.clone(), kinp.g32.clone(), kinp.g42.clone(), kinp.g52.clone()];
		let (vr1, vr2) = Self::gen_rands();
		let arr1_x = vec![kinp.y1, kinp.s11, kinp.sn1, kinp.r41, kinp.r51];
		let arr2_x= vec![kinp.y2, kinp.s12, kinp.sn2, kinp.r42, kinp.r52];
		let r1 = msm::<E>(&bases1, &vr1);
		let r2 = msm::<E>(&bases2, &vr2);
		let c = hash(&to_vecu8(&vec![r1, r2]));
		let (prf, _clm) = self.prove_direct(
			&bases1, &arr1_x, &vr1,
			&bases2, &arr2_x, &vr2,
			c);
		return Box::new(prf);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		if RUN_CONFIG.my_rank!=0 { return true; }
		let b_perf = false;
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		t1.start();
		t2.start();

		//1. type casting
		let pc:&ZkConnClaim::<E> = claim.as_any().
			downcast_ref::<ZkConnClaim<E>>().unwrap();
		let pp:&ZkConnProof::<E> = proof.as_any().
			downcast_ref::<ZkConnProof<E>>().unwrap();
		let bases1 = vec![pc.g11, pc.g21, pc.g31, pc.g41, pc.g51];
		let bases2 = vec![pc.g12, pc.g22, pc.g32, pc.g42, pc.g52];

		let b1 = dlog_ver::<E>(pc.c_1, pp.prf1_r, pp.c, &bases1, &pp.prf1);  
		ck(b1, "prf1 fails");
		let b2 = dlog_ver::<E>(pc.c_2, pp.prf2_r, pp.c, &bases2, &pp.prf2);  
		ck(b2, "prf2 fails");
		let b3 = pp.prf1[2]==pp.prf2[1];
		ck(b3, "prf1[2]!=prf2[1] for sn and s1 matching");
		let c = hash(&to_vecu8(&vec![pp.prf1_r, pp.prf2_r]));
		let b4 = pp.c==c;
		ck(b4, "prf.c is not hash of prf1_r || prf2_r!");
		if b_perf {log_perf(LOG1,&format!("----- ZKConnVerif"), &mut t1);}
		return b1 && b2 && b3 && b4;
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	/// if vec_g5s is empty, then create its own
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		return self.rand_inst_adv(n, seed, b_set_err, key, &vec![]);
	}


	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let zp_proto = ZkConn{key: key};
		return zp_proto;
	}
}


impl <E:PairingEngine> ZkConn <E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
<<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// if vec_g10s is empty, create its own
	pub fn rand_inst_adv(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>, vec_g10s: &Vec<E::G1Affine>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkConn::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let mut rng = gen_rng_from_seed(seed);
		let zk = ZkConn::<E>::new(key); 		
		let y1= E::Fr::rand(&mut rng);
		let s11 = E::Fr::rand(&mut rng);
		let sn1 = E::Fr::rand(&mut rng);
		let r41 = E::Fr::rand(&mut rng);
		let r51 = E::Fr::rand(&mut rng);
		let y2= E::Fr::rand(&mut rng);
		let s12 = sn1.clone();
		let sn2 = E::Fr::rand(&mut rng);
		let r42 = E::Fr::rand(&mut rng);
		let r52 = E::Fr::rand(&mut rng);
		let mut g1 = self.key.powers_g_beta[1];
		let mut g2 = self.key.powers_g_beta[2];
		let mut g3 = self.key.powers_g_beta[3];
		let mut g4 = self.key.powers_g_beta[4];
		let mut g5 = self.key.powers_g_beta[5];
		let mut h1 = self.key.powers_g_beta[6];
		let mut h2 = self.key.powers_g_beta[7];
		let mut h3 = self.key.powers_g_beta[8];
		let mut h4 = self.key.powers_g_beta[9];
		let mut h5 = self.key.powers_g_beta[10];
		if vec_g10s.len()>0{
			g1 = vec_g10s[0];
			g2 = vec_g10s[1];
			g3 = vec_g10s[2];
			g4 = vec_g10s[3];
			g5 = vec_g10s[4];
			h1 = vec_g10s[5];
			h2 = vec_g10s[6];
			h3 = vec_g10s[7];
			h4 = vec_g10s[8];
			h5 = vec_g10s[9];
		}
		

		//2. generate the input and then claim and proof
		let mut inp: ZkConnInput<E> = ZkConnInput{
			y1: y1, s11: s11, sn1: sn1, r41: r41, r51: r51,
			y2: y2, s12: s12, sn2: sn2, r42: r42, r52: r52,
			g11: g1.clone(), g21: g2.clone(), g31: g3.clone(), g41: g4.clone(), g51: g5.clone(),
			g12: h1.clone(), g22: h2.clone(), g32: h3.clone(), g42: h4.clone(), g52: h5.clone(),
		};	
		let prf = zk.prove(&mut inp);
		let mut claim = zk.claim(&mut inp);
		if b_set_err { //introduce an error for unit testing
			let kclaim:&ZkConnClaim::<E> = claim.as_any().
				downcast_ref::<ZkConnClaim<E>>().unwrap();
			let new_c_1 = kclaim.c_1 + E::G1Affine::rand(&mut rng);
			let bad_claim: ZkConnClaim<E> = ZkConnClaim{
				c_1: new_c_1,
				c_2: kclaim.c_2.clone(),
				g11: g1, g21: g2, g31: g3, g41: g4, g51: g5,
				g12: h1, g22: h2, g32: h3, g42: h4, g52: h5
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(zk), Box::new(inp), claim, prf);
	}

	/// generate two randomnonces array which the one for
	/// sn matches s1 of second one
	pub fn gen_rands() -> (Vec<E::Fr>, Vec<E::Fr>){
		let mut rng = gen_rng();
		let mut v1 = vec![];
		let mut v2 = vec![];
		for _i in 0..5{
			v1.push(E::Fr::rand(&mut rng));
			v2.push(E::Fr::rand(&mut rng));
		}
		v1[2] = v2[1]; //match the nonce for sn in v1 and s1 in v2
		return (v1, v2);
	}
	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// bases1: g5s for c1, arr1_x: secrets for c1, arr1_r nonces for c1
	/// likelywise for bases2, arr2_x, arr2_r,  
	/// c for challenge
	pub fn prove_direct(&self, bases1: &Vec<E::G1Affine>, arr1_x: &Vec<E::Fr>,
		arr1_r: &Vec<E::Fr>, 
		bases2: &Vec<E::G1Affine>, arr2_x: &Vec<E::Fr>, arr2_r: &Vec<E::Fr>, 
		c: E::Fr) 
	-> (ZkConnProof<E>,ZkConnClaim<E>){
		let me = RUN_CONFIG.my_rank;

		let c1 = msm::<E>(&bases1, &arr1_x);
		let c2 = msm::<E>(&bases2, &arr2_x);
		let r1 = msm::<E>(&bases1, &arr1_r);
		let r2 = msm::<E>(&bases2, &arr2_r);
		let s1 = dlog_msg3::<E>(&arr1_x, &arr1_r, c); 
		let s2 = dlog_msg3::<E>(&arr2_x, &arr2_r, c); 
		if me==0 {assert!(arr1_x[2]==arr2_x[1], "arr1_x[2]!=arr2_x[1]");}
		if me==0 {assert!(s1[2]==s2[1], "s1[2]!=s2[1]");}

		let kprf = ZkConnProof::<E>{
			prf1_r: r1, prf1: s1,
			prf2_r: r2, prf2: s2,
			c: c
		};

		let kclaim = ZkConnClaim::<E>{
			c_1: c1, c_2: c2,
			g11: bases1[0],
			g21: bases1[1],
			g31: bases1[2],
			g41: bases1[3],
			g51: bases1[4],
			g12: bases2[0],
			g22: bases2[1],
			g32: bases2[2],
			g42: bases2[3],
			g52: bases2[4],
		};
		return (kprf, kclaim);
	}

	/// expand the leng th the closest power of 2
	pub fn expand_to_pow2(arr_inp: &mut Vec<ZkConnInput<E>>){
		let n = closest_pow2(arr_inp.len());
		if arr_inp.len()<n{
			let n_more = n - arr_inp.len();
			let last_entry = arr_inp[arr_inp.len()-1].clone();
			for _i in 0..n_more{ arr_inp.push(last_entry.clone()); }
		}
	}

	/// batch prove
	pub fn batch_prove(arr_inp: &Vec<ZkConnInput<E>>, gipa: &GIPA<E>, _key: &Rc<DisKey<E>>) -> (Vec<ZkConnClaim<E>>,ZkConnAggProof<E>)
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
		//1. check input 
		let b_perf = true;
		let b_test = true;
		let me = RUN_CONFIG.my_rank;
		let n = arr_inp.len();
		assert!(n.is_power_of_two(), "input len not power of 2");
		let mut t1 = Timer::new();
		t1.start();

		//2. get the vec r1 and r2 to compute Fiat-Shamir c
		let mut v_r1 = vec![];
		let mut v_r2 = vec![];
		let mut v2d_r1 = vec![];
		let mut v2d_r2 = vec![];
		for i in 0..n{
			let inp = &arr_inp[i];
			let (r1s, r2s) = Self::gen_rands();
			let bases1 = vec![inp.g11.clone(), inp.g21.clone(), inp.g31.clone(),				inp.g41.clone(), inp.g51.clone()];
			let bases2 = vec![inp.g12.clone(), inp.g22.clone(), inp.g32.clone(),				inp.g42.clone(), inp.g52.clone()];
			v2d_r1.push(r1s.clone());
			v2d_r2.push(r2s.clone());
			v_r1.push( msm::<E>(&bases1, &r1s) );
			v_r2.push( msm::<E>(&bases2, &r2s) );
		}
		let c_r1 = gipa.cm1(&vec_affine_to_proj::<E>(&v_r1));
		let c_r2 = gipa.cm1(&vec_affine_to_proj::<E>(&v_r2));
		let c = hash::<E::Fr>(&to_vecu8(&vec![c_r1, c_r2]));

		//3. generate the proofs in v2d_s1, v2d_s2 (prf1, prf2)
		let mut v_c1 = vec![];
		let mut v_c2 = vec![];
		let mut v2dg = vec![vec![]; 10]; //10 bases
		let mut v2ds = vec![vec![]; 10]; //10 secrets
		let mut claims = vec![];
		for i in 0..n{
			let inp = &arr_inp[i];
			let bases1 = vec![inp.g11.clone(), inp.g21.clone(), inp.g31.clone(),				inp.g41.clone(), inp.g51.clone()];
			let bases2 = vec![inp.g12.clone(), inp.g22.clone(), inp.g32.clone(),				inp.g42.clone(), inp.g52.clone()];
			for j in 0..5{
				v2dg[j].push(bases1[j].clone());
				v2dg[j+5].push(bases2[j].clone());
			}
			let arr1_x = vec![inp.y1.clone(), inp.s11.clone(), inp.sn1.clone(), inp.r41.clone(), inp.r51.clone()];
			let arr2_x = vec![inp.y2.clone(), inp.s12.clone(), inp.sn2.clone(), inp.r42.clone(), inp.r52.clone()];
			assert!(arr1_x[2]==arr2_x[1], "arr1_x[2] != arr2_x[1]");
			let s1 = dlog_msg3::<E>(&arr1_x, &v2d_r1[i], c);
			let s2 = dlog_msg3::<E>(&arr2_x, &v2d_r2[i], c);
			for j in 0..5{
				v2ds[j].push(s1[j].clone());
				v2ds[j+5].push(s2[j].clone());
			}
			let c1 = msm::<E>(&bases1, &arr1_x);
			let c2 = msm::<E>(&bases2, &arr2_x);
			let claim = ZkConnClaim{
				c_1: c1.clone(), c_2: c2.clone(),
				g11: inp.g11.clone(),
				g21: inp.g21.clone(),
				g31: inp.g31.clone(),
				g41: inp.g41.clone(),
				g51: inp.g51.clone(),
				g12: inp.g12.clone(),
				g22: inp.g22.clone(),
				g32: inp.g32.clone(),
				g42: inp.g42.clone(),
				g52: inp.g52.clone(),
			};
			claims.push(claim);
			v_c1.push(c1);
			v_c2.push(c2);
			if b_test && me==0{
				assert!(dlog_ver::<E>(c1, v_r1[i].clone(), c, &bases1, &s1), 
					"fail on c1 check");
				assert!(dlog_ver::<E>(c2, v_r2[i].clone(), c, &bases2, &s2), 
					"fail on c2 check");
			}
		}

		let v_1 = vec![E::Fr::one(); n];
		let v_z = vec![
			v2ds[0].clone(), v2ds[1].clone(), v2ds[2].clone(), v2ds[3].clone(), v2ds[4].clone(),
			v2ds[5].clone(), v2ds[6].clone(), v2ds[7].clone(), v2ds[8].clone(), v2ds[9].clone(),
			v_1.clone(), v_1.clone(), v_1.clone(), v_1.clone(),
		];

		let v_g1 = vec![
			v2dg[0].clone(), v2dg[1].clone(), v2dg[2].clone(), v2dg[3].clone(), v2dg[4].clone(), 
			v2dg[5].clone(), v2dg[6].clone(), v2dg[7].clone(), v2dg[8].clone(), v2dg[9].clone(), 
			v_r1, v_r2, v_c1, v_c2
		];

		//4. generate the MIPP and TIPP proofs
		let v_g1_proj = v2d_affine_to_proj::<E>(&v_g1);
		let mut v_cz = vec![];
		let mut v_cg1 = vec![];
		for i in 0..v_z.len(){
			v_cz.push(gipa.cmz(&v_z[i]));
			v_cg1.push( gipa.cm1(&v_g1_proj[i]) );
		}
		let mut v_zm = vec![];
		let mut v_prf = vec![];
		let mut b1 = to_vecu8(&v_cz);
		let mut b2 = to_vecu8(&v_cg1);
		b1.append(&mut b2);
		let r = hash(&b1);

		for i in 0..v_g1.len(){
			let (prf, z) = gipa.mipp_prove(&v_g1_proj[i], &v_z[i], &r);
			v_zm.push(z);
			v_prf.push(prf);
		}
		if b_perf {log_perf(LOG1, &format!("-- ZkConn agg_prove Size: {}", n), &mut t1);}

		let aprf = ZkConnAggProof::<E>{
			size: n,
			c: c,
			v_cz: v_cz, v_cg1: v_cg1, 
			v_z: v_zm, v_prf: v_prf
		};
		return (claims, aprf);
	}

	/// aggregate verify
	pub fn agg_verify(claims: &Vec<ZkConnClaim<E>>, 
		agg_prf: &ZkConnAggProof<E>, gipa: &GIPA<E>, _key: &Rc<DisKey<E>>)
	->bool{
		let b_perf = true;
		let mut t1 = Timer::new();
		t1.start();

		//1. C1: check data consistency between claim and proofs
		let n = claims.len();
		assert!(n.is_power_of_two(), "n is not power of 2!");
		let mut v_c1 = vec![];	
		let mut v_c2 = vec![];
		for i in 0..n{v_c1.push(claims[i].c_1); v_c2.push(claims[i].c_2);}
		let v_vc1 = gipa.cm1(&vec_affine_to_proj::<E>(&v_c1));
		let v_vc2 = gipa.cm1(&vec_affine_to_proj::<E>(&v_c2));
		if v_vc1 != agg_prf.v_cg1[12]{
			log(LOG1, &tos("commit(claim.c1) does not match v_cm[12]!"));
			return false;
		}
		if v_vc2 != agg_prf.v_cg1[13]{
			log(LOG1, &tos("commit(claim.c2) does not match v_cm[13]!"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- ZkConn agg_ver check (C1): claims and v_cm"), &mut t1);}

		//2. C2:  check data consistency
		let vids = vec![10, 11, 12, 13];
		for i in vids{
			if agg_prf.v_cz[i]!=gipa.c_z1{
				log(LOG1, &format!("WARN: v_cz[{}] != gipa.c_z1 (vec(1))", i));
				return false;
			}
		}

		for i in 0..10{
			if agg_prf.v_cg1[i] !=gipa.vec_c_conn_gs[i]{
				log(LOG1, &format!("WARN: v_cg1m[{}] !=gipa.v_c_conn_gs",i));
				return false;
			}
		}
		
		if b_perf {log_perf(LOG1, 
			&format!("-- ZkConn agg_ver check (C2): const columns"), &mut t1);}

		// (C3) check MIPP and TIPP proofs
		let mut b1 = to_vecu8(&agg_prf.v_cz);
		let mut b2 = to_vecu8(&agg_prf.v_cg1);
		b1.append(&mut b2);
		let r = hash(&b1);
		for i in 0..agg_prf.v_z.len(){
			if !gipa.mipp_verify(&agg_prf.v_cg1[i], &agg_prf.v_cz[i],
				&r, &agg_prf.v_z[i], &agg_prf.v_prf[i]){
				log(LOG1, &format!("WARN: fails mipp prf {}", i));
				return false;
			}
		}
		if b_perf {log_perf(LOG1, 
			&format!("--  ZkConn agg_ver check (C3): MIPP proofs"), &mut t1);}

		// check C(4) DLOG proofs: c1 and c2
		//C4.1 C1
		let lhs = agg_prf.v_z[10] + 
			agg_prf.v_z[12].into_affine().mul(agg_prf.c);
		let rhs = agg_prf.v_z[0] + agg_prf.v_z[1] +
					agg_prf.v_z[2] + agg_prf.v_z[3] + agg_prf.v_z[4];
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails DLOG check for C1"));
			return false;
		}
		//C4.2 C1
		let lhs = agg_prf.v_z[11] + 
			agg_prf.v_z[13].into_affine().mul(agg_prf.c);
		let rhs = agg_prf.v_z[5] + agg_prf.v_z[6] +
					agg_prf.v_z[7] + agg_prf.v_z[8] + agg_prf.v_z[9];
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails DLOG check for C2"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- ZkConn agg_ver check (C4): DLOG c1 and c2"), &mut t1);}

		// check C(5) - Fiat-Shamir random c
		let exp_c = hash::<E::Fr>(&to_vecu8(&vec![
				agg_prf.v_cg1[10].clone(), agg_prf.v_cg1[11].clone()]));
		if exp_c != agg_prf.c{
			log(LOG1, &tos("WARN: fails check on Fiat-Shamir: agg_prf.c"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- ZkConn agg_ver check (C5): Fiat-Shamir c"), &mut t1);}
		return true;
	}

}

impl <E:PairingEngine> ZkConnProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/* RECOVER LATER
	/// generate a dummy proof
	pub fn dummy() -> Self{
		let g1 = E::G1Affine::prime_subgroup_generator();
		let g2 = E::G2Affine::prime_subgroup_generator();
		//let fr = E::Fr::zero();
		let res = Self{
			c_w: g1,
			prf_w: g1, 
			c_w2: g2,
			prf_q: g1,
			c_1: g1,
			prf_1: [E::Fr::zero(); 4],
			prf_1_r: g1,
			prf_1_c: E::Fr::zero()	,
			aux: ZkConnAux::<E>::dummy()
		
		};
		return res; 
	}
*/

}



impl <E:PairingEngine> ZkConnAggProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		E::Fr::serialize(&self.c, &mut b1).unwrap();
		assert!(self.v_cz.len()==14, "v_cz.len: {} != 14", self.v_cz.len());
		for i in 0..14{
			E::G1Projective::serialize(&self.v_cz[i], &mut b1).unwrap();
		}
		for i in 0..14{
			ExtensionFieldElement::<E>::serialize(&self.v_cg1[i], &mut b1).unwrap();
		}
		for i in 0..14{
			E::G1Projective::serialize(&self.v_z[i], &mut b1).unwrap();
		}	
		for i in 0..14{
			MyMIPPProof::<E>::serialize(&self.v_prf[i], &mut b1).unwrap();
		}
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>, _ripp: &GIPA<E>)->Self{
		let mut b1 = &v[..];
		let size= usize::deserialize(&mut b1).unwrap();		
		let c= E::Fr::deserialize(&mut b1).unwrap();
		let mut v_cz = vec![];
		let mut v_cg1 = vec![];
		let mut v_z = vec![];
		let mut v_prf = vec![];

		for _i in 0..14{
			v_cz.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		for _i in 0..14{
			v_cg1.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		}
		for _i in 0..14{
			v_z.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		for _i in 0..14{
			v_prf.push(MyMIPPProof::<E>::deserialize(&mut b1).unwrap());
		}
		let res = Self{size: size, c: c, 
			v_cz: v_cz, v_cg1: v_cg1, v_z: v_z, v_prf: v_prf
		};
		return res;
	}
}

// ---- Utility Functions ------------
/// sum [bases_i * exps_i]
pub fn msm<E:PairingEngine>(bases: &Vec<E::G1Affine>, exps: &Vec<E::Fr>)
	->E::G1Affine
{
	let zero = E::Fr::zero();
	let mut sum = bases[0].mul(zero);
	for i in 0..bases.len(){
		sum = sum + (bases[i].mul(exps[i]));
	}
	return sum.into_affine();
}

/// compute s_i = cx_i + r[i]
pub fn dlog_msg3<E:PairingEngine>(arr_x: &Vec<E::Fr>, arr_r: &Vec<E::Fr>, 
	c: E::Fr) ->Vec<E::Fr>{
	let mut arr = vec![E::Fr::zero(); arr_x.len()];
	for i in 0..arr.len(){
		arr[i] = arr_x[i]*c + arr_r[i];
	}
	return arr;
}

/// verify dlog proof for knowing c_x = g1^x1...gn^xn
pub fn dlog_ver<E:PairingEngine>(c_x: E::G1Affine, msg1: E::G1Affine, c: E::Fr, bases: &Vec<E::G1Affine>, msg3: &Vec<E::Fr>)->bool{
	//1. lhs = c_x^c + r
	let lhs = c_x.mul(c).into_affine() + msg1;
	//2l rhs = sum bases[i]*msg3[i]
	let zero = E::Fr::zero();
	let mut rhs = bases[0].mul(zero).into_affine();
	for i in 0..bases.len(){
		rhs = rhs + bases[i].mul(msg3[i]).into_affine();
	}
	return lhs==rhs;
}

/// warning and ck
pub fn ck(b: bool, msg: &str){
	if !b {println!("\n\n#########WARN: {}", msg);}
}

