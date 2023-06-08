/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 03/16/2023
	Completed: 03/18/2023
	Revised: 03/24/2023 -> Add Aggregation Support
	Completed: 03/26/2023
*/

/// This module defines the zero knowledge subset protocol.
/// It is an IMPROVEMENT over v3 in that we can skip the Prod Proof
///
/// Given: 
/// (1) the extended KZG commitment of polynomial p_superset, 
///  	c_p = g^{p(alpha) h^r_p} here "h" is the g2 in paper
///	(2) the extended KZG commitment for p_subset:
/// 	c_q= (g^{q(alpha}) h^r_q}
/// Prove that q(X) is a factor poly of p(X).
///
/// Proof idea: compute w(x) = p_super(x)/subset(x) and
/// Generate its extended KZG commitment:
/// c_w= g^{w(x)} h^r_w
/// Prove their relation using zk_poly.
/// let C1 = c_w^{r_q} c_q^{r_w} h^{-r_q* r_w} g^{-r_p}
/// verify e(c_p, g) e(C1, h)= e(c_q, c_w) 
/// For each component involved, provide its knowledge extraction proof
/// See Section 3 of the paper for details...
/// 
/// ----------- REMOVE OR UPDATE LATER ----------------
/// Performance: 32k (8 nodes 1 computer):  ???????? ---- CHECK
/// gen time: 37 sec.  vs 28 sec (in V1)
/// (1 node: 8.3 ms vs 10ms in V1, coz saving 2 ). Prf size: 1008 bytes (more expensive than V1 because there is a G2 element)
/// 1M entries: 265 seconds (rouggly linear).
/// ----------- REMOVE OR UPDATE LATER ABOVE ----------------

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
use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
use self::ark_ff::{Zero,UniformRand,One};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
//use self::ark_ff::UniformRand;
use std::any::Any;
//use std::fs::File;

use self::ark_inner_products::{ExtensionFieldElement};

use proto::*;
//use proto::zk_same::*;
//use proto::zk_prod::*;
//use proto::zk_poly::*;
use proto::ripp_driver::*;
use poly::dis_poly::*;
//use poly::serial::*;
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
pub struct ZkSubsetV3Input<E:PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// the superset polynomail p(x) 
	pub p: DisPoly<E::Fr>,	
	/// the subset polynomail q(x) 
	pub q: DisPoly<E::Fr>,	
	/// for c_p  = g^{p(alpha)} h^r_p
	pub r_p: E::Fr,
	/// for c_q = g^{q(alpha)} h^r_q
	pub r_q: E::Fr,
}

#[derive(Clone)]
pub struct ZkSubsetV3Claim<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// ASSUMPTION: knowledge proof of kzg_superset is provided somewhere else
	/// the poly hiding behind kzg_subset is a factor poly or kzg_superset
	/// c_p = g^{p(alpha)} h^r_p
	pub c_p: E::G1Affine,
	/// c_q= g^{q(alpha} h^r_q
	pub c_q: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkSubsetV3Proof<E: PairingEngine>where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// c_w = g^{w(alpha)} h^beta (the C_w in paper) 
	pub c_w: E::G1Affine,
	/// knowledge proof for c_w
	pub prf_w: E::G1Affine,
	/// c_wover G2
	pub c_w2: E::G2Affine,
	/// knowledge proof for c_q
	pub prf_q: E::G1Affine,
	/// Balanceing term c_w^{gamma} c_q^{beta} h^{-gamma* beta} g^{eta}
	pub c_1: E::G1Affine,
	/// knowledge proof of c_1 (s1, s2, s3, s4)
	pub prf_1: [E::Fr; 4],
	/// part of the prf_1, the R sent in step 1
	pub prf_1_r: E::G1Affine,
	/// the challenge
	pub prf_1_c: E::Fr,
	/// NOTE: Aux info will NOT be serialized
	pub aux: ZkSubsetV3Aux<E>,
}


#[derive(Clone)]
pub struct ZkSubsetV3<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}} on both G1 and G2
	pub key: Rc<DisKey<E>>
}

#[derive(Clone)]
pub struct ZkSubsetV3Aux<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// the aux information for aggregation (secrets for DLOG protocol)
	pub x1: E::Fr,
	pub x2: E::Fr,
	pub x3: E::Fr,
	pub x4: E::Fr
}

/// aggregated claim
#[derive(Clone)]
pub struct ZkSubsetV3AggClaim<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many claims are aggregated
	pub size: usize,
	/// commitment to the vector of C_p's
	pub c_cp: ExtensionFieldElement<E>,
	/// commitment to the vectors of C_q's
	pub c_cq: ExtensionFieldElement<E>,  
}


/// aggregated proof 
#[derive(Clone)]
pub struct ZkSubsetV3AggProof<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many proofs are aggregated
	pub size: usize,
	/// challanege for DLOG
	pub c: E::Fr,
	/// Fiat-Shamir random
	pub r: E::Fr,
	/// commitments to Z. 11 elements
	pub v_cz: Vec<E::G1Projective>,
	/// commitments to G1m. 11 elements
	pub v_cg1m: Vec<ExtensionFieldElement<E>>, 
	/// commitment to G1t, 2 elements
	pub v_cg1t: Vec<ExtensionFieldElement<E>>, 
	/// commitment to G2, 2 elements
	pub v_cg2: Vec<ExtensionFieldElement<E>>, 
	/// z values 11 elements (for mipp)
	pub v_zm: Vec<E::G1Projective>,
	/// prf of MIPP 11 elements
	pub v_prfm: Vec<MyMIPPProof<E>>,
	/// z values for tipp 2 elements
	pub v_zt: Vec<ExtensionFieldElement<E>>,
	/// prf of TIPP 2 elmenets
	pub v_prft: Vec<MyTIPAProof<E>>,
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 
impl <E:PairingEngine> ProverInput for ZkSubsetV3Input<E> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ZkSubsetV3Proof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
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
			aux: ZkSubsetV3Aux::<E>::dummy()
		
		};
		return res; 
	}

	pub fn get_aux(&self) -> ZkSubsetV3Aux<E>{
		return self.aux.clone();
	}

	pub fn set_aux(&mut self, aux_inp: ZkSubsetV3Aux<E>){
		self.aux = aux_inp;	
	}
}

impl <E:PairingEngine> ZkSubsetV3Claim<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// generate a dummy proof
	pub fn dummy() -> Self{
		let g1 = E::G1Affine::prime_subgroup_generator();
		let res = Self{c_p: g1, c_q: g1 };
		return res; 
	}
}

impl <E:PairingEngine> ProtoObj for ZkSubsetV3Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_w, &mut b1).unwrap();
		E::G1Affine::serialize(&self.prf_w, &mut b1).unwrap();
		E::G2Affine::serialize(&self.c_w2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.prf_q, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_1, &mut b1).unwrap();
		for i in 0..self.prf_1.len(){
			E::Fr::serialize(&self.prf_1[i], &mut b1).unwrap();
		}
		E::G1Affine::serialize(&self.prf_1_r, &mut b1).unwrap();
		E::Fr::serialize(&self.prf_1_c, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	/// NOTE: aux will be set as DUMMY!
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v1 = &v[..];
		let c_w= E::G1Affine::deserialize(&mut v1).unwrap();		
		let prf_w = E::G1Affine::deserialize(&mut v1).unwrap();		
		let c_w2 = E::G2Affine::deserialize(&mut v1).unwrap();		
		let prf_q = E::G1Affine::deserialize(&mut v1).unwrap();		
		let c_1 = E::G1Affine::deserialize(&mut v1).unwrap();		
		let mut prf_1 = [E::Fr::from(0u64); 4];
		for i in 0..4{
			prf_1[i] = E::Fr::deserialize(&mut v1).unwrap();
		}
		let prf_1_r = E::G1Affine::deserialize(&mut v1).unwrap();
		let prf_1_c = E::Fr::deserialize(&mut v1).unwrap();

		let res = ZkSubsetV3Proof{
			c_w: c_w,
			prf_w: prf_w,
			c_w2: c_w2,
			prf_q: prf_q,
			c_1: c_1,
			prf_1: prf_1,
			prf_1_r: prf_1_r,
			prf_1_c: prf_1_c,
			aux: ZkSubsetV3Aux::<E>::dummy()
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		print!("{} ZkSubsetV3Prf: c_w: {:?},prf_w: {:?}, c_w2: {:?}, prf_q: {:?}, c_1: {:?}, prf_1: {:?}", prefix, self.c_w2, self.prf_w, self.c_w2, self.prf_q, self.c_1, self.prf_1);
	} 
}

impl <E:PairingEngine> Proof for ZkSubsetV3Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_w= res.c_w.clone();
		self.prf_w= res.prf_w.clone();
		self.c_w2= res.c_w2.clone();
		self.prf_q= res.prf_q.clone();
		self.c_1= res.c_1.clone();
		self.prf_1= res.prf_1.clone();
		self.prf_1_r= res.prf_1_r.clone();
		self.prf_1_c= res.prf_1_c.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkSubsetV3Proof::<E> = other.as_any().
			downcast_ref::<ZkSubsetV3Proof<E>>().unwrap();
		return self.c_w==obj.c_w
			&& self.prf_w==obj.prf_w
			&& self.c_w2==obj.c_w2
			&& self.prf_q==obj.prf_q
			&& self.c_1==obj.c_1
			&& self.prf_1==obj.prf_1
			&& self.prf_1_r==obj.prf_1_r
			&& self.prf_1_c==obj.prf_1_c;
	}
}


impl <E:PairingEngine> ProtoObj for ZkSubsetV3Claim<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_p, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_q, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v3 = &v[..];
		let c_p = E::G1Affine::deserialize(&mut v3).unwrap();		
		let c_q = E::G1Affine::deserialize(&mut v3).unwrap();		
		let res = ZkSubsetV3Claim::<E>{
			c_p: c_p,
			c_q: c_q,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (c_p: {:?}, c_q: {:?}", 
			prefix, self.c_p, self.c_q);
	} 
}

impl <E:PairingEngine> Claim for ZkSubsetV3Claim<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_p= res.c_p;
		self.c_q= res.c_q;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkSubsetV3Claim::<E> = obj.as_any().
			downcast_ref::<ZkSubsetV3Claim<E>>().unwrap();
		return self.c_p==other.c_p&& 
			self.c_q==other.c_q;
	}
}


impl <E:PairingEngine> Protocol<E> for ZkSubsetV3 <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkSubsetV3";
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let proto = ZkSubsetV3{ key: key};
		return proto;
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let sinp:&mut ZkSubsetV3Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkSubsetV3Input<E>>().unwrap();
		//1. compute the W polynomial
		//let g1 = self.key.g.into_affine();
		let c_p= self.key.gen_kzg(&mut sinp.p)[0] + 
			self.key.h.mul(sinp.r_p).into_affine();
		let c_q= self.key.gen_kzg(&mut sinp.q)[0] 
			+ self.key.h.mul(sinp.r_q).into_affine();
		let claim = ZkSubsetV3Claim::<E>{
			c_p: c_p,
			c_q: c_q,
		};
		return Box::new(claim);
	}


	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let sinp:&mut ZkSubsetV3Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkSubsetV3Input<E>>().unwrap();
		let p = &mut sinp.p;
		let q = &mut sinp.q;
		let r_p = sinp.r_p;
		let r_q = sinp.r_q;
		let (res, _) = self.prove_direct(p, q, r_p, r_q);
		return res;
/*
		let b_perf = true;
		let b_mem = false;
		let b_test = true;
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		t1.start();
		t2.start();

		//1. compute the W polynomial
		let me = RUN_CONFIG.my_rank;
		let p = &mut sinp.p;
		let q = &mut sinp.q;
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let h_g2 = self.key.h_g2;
		let h_beta= self.key.h_beta;
		let (mut dw, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(p, q);
		let b_zero = dr.is_zero();
		if b_test{if me==0{assert!(b_zero,"ZkSubsetV3 ERR: dr!= 0!"); }}
		if b_perf {log_perf(LOG1, &format!("------ GenSubsetPrf Step1: w=p/q. p: {}, q: {}, w: {}", p.dvec.len, q.dvec.len, dw.dvec.len), &mut t1);}
		if b_mem {dump_mem_usage("------ GenSubsetPrf Step1");}
		
		//2. evaluate the c_w over Group G1 
		RUN_CONFIG.better_barrier("WAIT HERE");
		dw.to_partitions();
		let mut rng = gen_rng();
		let r_w = E::Fr::rand(&mut rng);
		let c_w = self.key.gen_kzg(&mut dw)[0]+ h.mul(r_w).into_affine();
		let c_w2 = self.key.gen_kzg_g2(&mut dw)[0]+h_g2.mul(r_w).into_affine();
		let prf_w= self.key.gen_kzg_beta(&mut dw)[0] 
			+ h_beta.mul(r_w).into_affine();
		let c_q= self.key.gen_kzg(q)[0]+self.key.h.mul(sinp.r_q).into_affine();
		let prf_q= self.key.gen_kzg_beta(q)[0] 
			+ h_beta.mul(sinp.r_q).into_affine();
		if b_perf {log_perf(LOG1, &format!("------ GenSubsetPrf Step2: gen c_w, prf_w and cw_2, c_q, prf_q. w: {}, q: {}", dw.dvec.len, q.dvec.len), &mut t1);}
		if b_mem {dump_mem_usage("------ GenSubsetPrf Step2");}

		//3. compute c_1 
		let neg_rq_rw = E::Fr::zero() - (sinp.r_q * r_w);
		let neg_rp = E::Fr::zero() - sinp.r_p;
		let c_1 = (c_w.mul(sinp.r_q) + c_q.mul(r_w) +  
			h.mul(neg_rq_rw) + g.mul(neg_rp)).into_affine();
		let mut rs = vec![E::Fr::zero(); 4];
		for i in 0..4{ rs[i] = E::Fr::rand(&mut rng); };
		let zero = E::Fr::zero();
		let arr_x = [sinp.r_q, r_w, neg_rq_rw, neg_rp];
		let mut arr_s = [E::Fr::zero(); 4];
		let r = c_w.mul(rs[0]) + c_q.mul(rs[1]) +  h.mul(rs[2]) + g.mul(rs[3]);
		let c = hash::<E::Fr>(&to_vecu8(&vec![r]));
		for i in 0..4{arr_s[i] = c*arr_x[i] + rs[i]; }
		if b_perf {log_perf(LOG1, &format!("------ GenSubsetPrf Step4: gen c_1 and prf_1: "), &mut t1);}

		//5. build up the proof
		let kprf = ZkSubsetV3Proof::<E>{
			c_w: c_w,
			prf_w: prf_w,
			c_w2: c_w2,
			prf_q: prf_q,
			c_1: c_1,
			prf_1: arr_s,
			prf_1_r: r.into_affine(),
			prf_1_c: c,
		};
		return Box::new(kprf);
*/
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//1. set up keys 
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let p_claim:&ZkSubsetV3Claim::<E> = claim.as_any().
			downcast_ref::<ZkSubsetV3Claim<E>>().unwrap();
		let p_proof:&ZkSubsetV3Proof::<E> = proof.as_any().
			downcast_ref::<ZkSubsetV3Proof<E>>().unwrap();
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let h_g2 = self.key.h_g2;
		//let h_beta= self.key.h_beta;
		let g_g2 = self.key.g_g2;
		let g2_beta = self.key.g_beta_g2;
		if b_perf {log_perf(LOG1,
			&format!("------ VerSubset Step1: key setup"), &mut t1);}

		//1. check knowledge proofs
		if E::pairing(p_claim.c_q, g2_beta) != E::pairing(p_proof.prf_q, g_g2){
			log(LOG1, &tos("WARNING: failed knowledge proof for c_q"));
			return false;
		}
		if E::pairing(p_proof.c_w, g2_beta) != E::pairing(p_proof.prf_w, g_g2){
			log(LOG1, &tos("WARNING: failed knowledge proof for c_w"));
			return false;
		}
		if E::pairing(p_proof.c_w, g_g2) != E::pairing(g, p_proof.c_w2){
			log(LOG1, &tos("WARNING: failed for c_w == c_w2"));
			return false;
		}
		if  E::pairing(p_claim.c_p, g_g2) * E::pairing(p_proof.c_1, h_g2)
			!= E::pairing(p_claim.c_q, p_proof.c_w2){
			log(LOG1, &tos("WARNING: failed for e(c_p,g) * e(c_1, h) = e(c_q, c_w)"));
			return false;
		}

		//2.  check DLOG proof
		let arr_s = p_proof.prf_1;
		let lhs = p_proof.c_1.mul(p_proof.prf_1_c) 
			+ p_proof.prf_1_r.into_projective();
		let rhs = p_proof.c_w.mul(arr_s[0]) + p_claim.c_q.mul(arr_s[1])
			+ h.mul(arr_s[2]) + g.mul(arr_s[3]);
		if lhs!=rhs{
			log(LOG1, &tos("WARNING: VerSubset Failed DLOG")); 
			return false;
		}


		return true; //passed
	}

	
	/// generate a random instance. n is the degree of subset polynomial,
	/// the dgree of superset polynomial is 2n.
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key:Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkSubsetV3::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let n = n/2;		 //make it half.
		let mut rng = gen_rng_from_seed(seed);
		let r_q = E::Fr::rand(&mut rng);
		let r_p = E::Fr::rand(&mut rng);
		let proto = ZkSubsetV3::<E>::new(key); 		 //factory instance
		let p_factor= DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_factor= DisPoly::<E::Fr>::from_serial(0, &p_factor, 
			&p_factor.degree()+1);
		let p_subset = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_subset = DisPoly::<E::Fr>::from_serial(0, &p_subset, 
			&p_subset.degree()+1);
		let mut dp_superset = DisPoly::<E::Fr>::mul(&mut dp_factor, 
			&mut dp_subset);
		dp_subset.to_partitions();
		dp_superset.to_partitions(); 

		//2. builds SubsetV3Input 
		let mut inp: ZkSubsetV3Input<E> = ZkSubsetV3Input{
			p: dp_superset, q: dp_subset, r_q: r_q, r_p: r_p};
		let prf = proto.prove(&mut inp);
		let mut claim = proto.claim(&mut inp);

		//3. introduce error if asked
		if b_set_err { 
			let kclaim:&ZkSubsetV3Claim::<E> = claim.as_any().
				downcast_ref::<ZkSubsetV3Claim<E>>().unwrap();
			let new_c_p= kclaim.c_p.mul(2u32).into_affine();
			let bad_claim: ZkSubsetV3Claim<E> = ZkSubsetV3Claim{
				c_p: new_c_p,
				c_q: kclaim.c_q,
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

}

impl <E:PairingEngine> ZkSubsetV3 <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// generate the proof by mutating an existing proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// See section 3.2 of paper
	/// Inputs: see paper. c_q: commit to q(X), prf_q its knowledge proof.
	/// gw: g^{w(alpha)}, gw2: gw over G2, gw_beta: g^{beta w(alpha}
	/// r_q, r_w the new random nonces to apply
	pub fn shortcut_prove(&self, 
		c_q: E::G1Affine, prf_q: E::G1Affine,
		gw: E::G1Affine, 
		gw_beta: E::G1Affine,
		gw2: E::G2Affine,
		r_q: E::Fr, r_w: E::Fr, r_p: E::Fr) -> Box<dyn Proof> {

		//1. regenerate the cw, prf, c_q
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let h_beta = self.key.h_beta;
		let h_2 = self.key.h_g2;
		let new_cq = c_q + h.mul(r_q).into_affine();
		let new_prfq = prf_q + h_beta.mul(r_q).into_affine();
		let new_cw = gw + h.mul(r_w).into_affine();
		let new_prfw = gw_beta + h_beta.mul(r_w).into_affine();
		let new_cw2 = gw2 + h_2.mul(r_w).into_affine();	

		//2. regenerate the DLOG proof
		let seed = 923842342341u128;
		let mut rng = gen_rng_from_seed(seed);
		let zero = E::Fr::zero();
		let neg_rq_rw = zero - r_q * r_w;
		let neg_rp = zero - r_p;
		let c_1 = (new_cw.mul(r_q) + new_cq.mul(r_w) +  
			h.mul(neg_rq_rw) + g.mul(neg_rp)).into_affine();
		let mut rs = vec![E::Fr::zero(); 4];
		for i in 0..4{ rs[i] = E::Fr::rand(&mut rng); };
		let arr_x = [r_q, r_w, neg_rq_rw, neg_rp];
		let aux = ZkSubsetV3Aux::<E>{x1: arr_x[0], x2: arr_x[1], 
			x3: arr_x[2], x4: arr_x[3]};
		let mut arr_s = [E::Fr::zero(); 4];
		let r = new_cw.mul(rs[0]) + new_cq.mul(rs[1]) +  
			h.mul(rs[2]) + g.mul(rs[3]);
		let c = hash::<E::Fr>(&to_vecu8(&vec![r]));
		for i in 0..4{arr_s[i] = c*arr_x[i] + rs[i]; }

		//3. assemble the new proof
		let kprf = ZkSubsetV3Proof::<E>{
			c_w: new_cw,
			prf_w: new_prfw,
			c_w2: new_cw2,
			prf_q: new_prfq,
			c_1: c_1,
			prf_1: arr_s,
			prf_1_r: r.into_affine(),
			prf_1_c: c,
			aux: aux,
		};
		return Box::new(kprf);
	}

	/// generate the claim in shortcut way
	/// NOTE only return valid result in main processor 0
	pub fn shortcut_claim(&self,  c_p: E::G1Affine, c_q: E::G1Affine, 
		r_q: E::Fr) -> Box<dyn Claim> {
		//1. compute the W polynomial
		//let g1 = self.key.g.into_affine();
		let new_cq = c_q + self.key.h.mul(r_q).into_affine();
		let claim = ZkSubsetV3Claim::<E>{
			c_p: c_p, c_q: new_cq
		};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	pub fn prove_direct(&self, p: &mut DisPoly<E::Fr>, q: &mut DisPoly<E::Fr>, r_p: E::Fr, r_q: E::Fr) -> (Box<dyn Proof>, Box<dyn Claim>) {
		let b_perf = false;
		let b_mem = false;
		let b_test = false;
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		t1.start();
		t2.start();

		//1. compute the W polynomial
		let me = RUN_CONFIG.my_rank;
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let h_g2 = self.key.h_g2;
		let h_beta= self.key.h_beta;
		let (mut dw, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(p, q);
		let b_zero = dr.is_zero();
		if b_test{if me==0{assert!(b_zero,"ZkSubsetV3 ERR: dr!= 0!"); }}
		if b_perf {log_perf(LOG1, &format!("------ ZkSubsetPrf Step1: w=p/q. p: {}, q: {}, w: {}", p.dvec.len, q.dvec.len, dw.dvec.len), &mut t1);}
		if b_mem {dump_mem_usage("------ GenSubsetPrf Step1");}
		
		//2. evaluate the c_w over Group G1 
		RUN_CONFIG.better_barrier("WAIT HERE");
		dw.to_partitions();
		let mut rng = gen_rng();
		let r_w = E::Fr::rand(&mut rng);
		let c_w = self.key.gen_kzg(&mut dw)[0]+ h.mul(r_w).into_affine();
		let c_w2 = self.key.gen_kzg_g2(&mut dw)[0]+h_g2.mul(r_w).into_affine();
		let prf_w= self.key.gen_kzg_beta(&mut dw)[0] 
			+ h_beta.mul(r_w).into_affine();
		let c_p= self.key.gen_kzg(p)[0]+self.key.h.mul(r_p).into_affine();
		let c_q= self.key.gen_kzg(q)[0]+self.key.h.mul(r_q).into_affine();
		let prf_q= self.key.gen_kzg_beta(q)[0] 
			+ h_beta.mul(r_q).into_affine();
		if b_perf {log_perf(LOG1, &format!("------ ZkSubsetPrf Step2: gen c_w, prf_w and cw_2, c_q, prf_q. w: {}, q: {}", dw.dvec.len, q.dvec.len), &mut t1);}
		if b_mem {dump_mem_usage("------ GenSubsetPrf Step2");}

		//3. compute c_1 
		let neg_rq_rw = E::Fr::zero() - (r_q * r_w);
		let neg_rp = E::Fr::zero() - r_p;
		let c_1 = (c_w.mul(r_q) + c_q.mul(r_w) +  
			h.mul(neg_rq_rw) + g.mul(neg_rp)).into_affine();
		let mut rs = vec![E::Fr::zero(); 4];
		for i in 0..4{ rs[i] = E::Fr::rand(&mut rng); };
		//let zero = E::Fr::zero();
		let arr_x = [r_q, r_w, neg_rq_rw, neg_rp];
		let aux = ZkSubsetV3Aux::<E>{x1: arr_x[0], x2: arr_x[1], 
			x3: arr_x[2], x4: arr_x[3]};
		let mut arr_s = [E::Fr::zero(); 4];
		let r = c_w.mul(rs[0]) + c_q.mul(rs[1]) +  h.mul(rs[2]) + g.mul(rs[3]);
		let c = hash::<E::Fr>(&to_vecu8(&vec![r]));
		for i in 0..4{arr_s[i] = c*arr_x[i] + rs[i]; }
		if b_perf {log_perf(LOG1, &format!("------ ZkSubsetPrf Step3: gen c_1 and prf_1: "), &mut t1);}

		//5. build up the proof
		let kprf = ZkSubsetV3Proof::<E>{
			c_w: c_w,
			prf_w: prf_w,
			c_w2: c_w2,
			prf_q: prf_q,
			c_1: c_1,
			prf_1: arr_s,
			prf_1_r: r.into_affine(),
			prf_1_c: c,
			aux: aux,
		};

		let kclaim = ZkSubsetV3Claim::<E>{
			c_p: c_p, 
			c_q: c_q
		};
		return (Box::new(kprf), Box::new(kclaim));
	}

	/// aggregate prove
	pub fn agg_prove(claims: &Vec<ZkSubsetV3Claim<E>>, prfs: &Vec<ZkSubsetV3Proof<E>>, gipa: &GIPA<E>, key: &Rc<DisKey<E>>) -> (ZkSubsetV3AggClaim<E>, ZkSubsetV3AggProof<E>)
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		//0. check data
		let n = claims.len();
		assert!(n.is_power_of_two(), "n: {} is not power of 2!", n);

		//1. generate new rands and v_R
		let mut rng = gen_rng();
		let mut v_msg1 = vec![];
		let mut v_r4 = vec![];
		let h = key.h;
		let g = key.g.into_affine();
		let g1_zero = g.mul(E::Fr::zero());
		for i in 0..n{
			let v_h = vec![prfs[i].c_w, claims[i].c_q, h, g]; 
			let mut r4 = vec![];
			for _j in 0..4{r4.push(E::Fr::rand(&mut rng));}
			let mut msg_r = g1_zero.clone();
			for j in 0..4{msg_r= msg_r + v_h[j].mul(r4[j].clone());} 
			v_r4.push(r4);
			v_msg1.push(msg_r);
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_prove Step1: Regen msg_r"), &mut t1);}

		//2. compute C_r and Fiat-Shamir c
		let c_r = gipa.cm1(&v_msg1);	
		let c = hash::<E::Fr>(&to_vecu8(&vec![c_r]));
		let mut vec_s = vec![vec![], vec![], vec![], vec![]];
		for i in 0..n{
			let x4 = vec![prfs[i].aux.x1, prfs[i].aux.x2,
				prfs[i].aux.x3, prfs[i].aux.x4];
			for j in 0..4{vec_s[j].push(c * x4[j] + v_r4[i][j]);}
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_prove Step2: Recompute DLOG Prf"), &mut t1);}

		//3. generate data set 
		let z1 = vec![E::Fr::one(); n];
		let mut v_cq = vec![];
		for i in 0..n {v_cq.push(claims[i].c_q.clone());}
		let mut v_cw = vec![];
		for i in 0..n {v_cw.push(prfs[i].c_w.clone());}
		let mut v_prfq = vec![];
		for i in 0..n {v_prfq.push(prfs[i].prf_q.clone());}
		let mut v_prfw = vec![];
		for i in 0..n {v_prfw.push(prfs[i].prf_w.clone());}
		let mut v_c1= vec![];
		for i in 0..n {v_c1.push(prfs[i].c_1.clone());}
		let mut v_cp= vec![];
		for i in 0..n {v_cp.push(claims[i].c_p.clone());}
		let v_s2 = vec![h; n];
		let v_1 = vec![g; n];
		let mut v_cw2 = vec![];
		for i in 0..n {v_cw2.push(prfs[i].c_w2.clone());}

		let v_z = vec![vec_s[0].clone(), vec_s[1].clone(), vec_s[2].clone(), vec_s[3].clone(), z1.clone(), z1.clone(), z1.clone(), z1.clone(), z1.clone(), z1.clone(), z1.clone()]; //11 elements
		let v_g1m = vec![//11 elemements
			v_cw.clone(), v_cq.clone(), v_s2.clone(), v_1.clone(),
			v_cq.clone(), v_prfq.clone(), v_cw.clone(), v_prfw.clone(),
			v_c1.clone(), v_cp.clone(), 
			E::G1Projective::batch_normalization_into_affine(&v_msg1[..])];
		let v_g1m_proj = v2d_affine_to_proj::<E>(&v_g1m);
		let v_g1t = vec![vec![g;n], v_cq.clone()]; 
		let v_g1t_proj = v2d_affine_to_proj::<E>(&v_g1t);
		let v_g2 = vec![v_cw2.clone(), v_cw2.clone()];
		let v_g2_proj = v2d_affine2_to_proj::<E>(&v_g2);

		//4. generate commits and build fiat-shamir r again
		let mut v_cz = vec![];
		let mut v_cg1m = vec![];
		let mut v_cg1t = vec![];
		let mut v_cg2 = vec![];
		for i in 0..v_z.len(){
			v_cz.push(gipa.cmz(&v_z[i]));
			v_cg1m.push( gipa.cm1(&v_g1m_proj[i]) );
		}
		for i in 0..2{
			v_cg1t.push(gipa.cm1(&v_g1t_proj[i]));
			v_cg2.push(gipa.cm2(&v_g2_proj[i]));
		}
		let mut b1 = vec![];
		for i in 0..v_z.len(){
			E::G1Projective::serialize(&v_cz[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&v_cg1m[i], &mut b1).unwrap();
		}
		for i in 0..2{
			ExtensionFieldElement::<E>::serialize(&v_cg1t[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&v_cg2[i], &mut b1).unwrap();
		}
		let r = hash::<E::Fr>(&b1);
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_prove Step3: Build Commitments"), &mut t1);}

		//5. generate mipp and tipp proofs
		let mut v_zm = vec![];
		let mut v_prfm = vec![];
		let mut v_zt = vec![];
		let mut v_prft = vec![];
		for i in 0..v_g1m.len(){
			let (prf, z) = gipa.mipp_prove(&v_g1m_proj[i], &v_z[i], &r);
			v_zm.push(z);
			v_prfm.push(prf);
		}
		for i in 0..2{
			let (prf, z) = gipa.tipp_prove(&v_g1t_proj[i], &v_g2_proj[i], &r);
			v_zt.push(z);
			v_prft.push(prf);	
		}
		if b_perf {log_perf(LOG1, &format!("-- SubsetPrf agg_prove Step4: MIPP & TIPP proofs. Size: {}", n), &mut t1);}

		//6. assemble and return prf
		let c_cp = v_cg1m[9].clone();
		let c_cq = v_cg1m[1].clone();
		let aprf = ZkSubsetV3AggProof::<E>{
			size: n,
			c: c,
			r: r,
			v_cz: v_cz, v_cg1m: v_cg1m, v_cg1t: v_cg1t, v_cg2: v_cg2,
			v_zm: v_zm, v_prfm: v_prfm, v_zt: v_zt, v_prft: v_prft	
		};
		let aclaim = ZkSubsetV3AggClaim::<E>{
			size: n, c_cp: c_cp, c_cq: c_cq
		};
		return (aclaim, aprf);
	}

	/// aggregate verify
	pub fn agg_verify(agg_claim: &ZkSubsetV3AggClaim<E>, agg_prf: &ZkSubsetV3AggProof<E>, gipa: &GIPA<E>, key: &Rc<DisKey<E>>)->bool{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();

		//1. C1:  check data consistency
		if agg_claim.c_cp != agg_prf.v_cg1m[9]{
			log(LOG1, &tos("WARN: claim.c_cp != prf.v_cg1m[9]"));
			return false;
		}
		if agg_claim.c_cq != agg_prf.v_cg1m[1]{
			log(LOG1, &tos("WARN: claim.c_cq != prf.v_cg1m[1]"));
			return false;
		}
		for i in 4..11{
			if agg_prf.v_cz[i]!=agg_prf.v_cz[4]{
				log(LOG1, &format!("WARN: v_cz[{}] != v_cz[5]", i));
				return false;
			}
		}
		if agg_prf.v_cg1m[1] != agg_prf.v_cg1m[4] ||
			agg_prf.v_cg1m[1] != agg_prf.v_cg1t[1]{
			log(LOG1, &format!("WARN: Cq: v_cg1m[1]!=[4] or !=v_cg1t[1]"));
			return false;
		}
		if agg_prf.v_cg1m[0] != agg_prf.v_cg1m[6]{
			log(LOG1, &format!("WARN: Cw: v_cg1m[0]!=v_cg1m[6]"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C1)"), &mut t1);}

		//2. check (C2) in paper
		if agg_prf.v_cz[5] != gipa.c_z1{
			log(LOG1, &tos("WARN: prf.c_z[5] != CM(vec(1)"));
			return false;
		}	
		if agg_prf.v_cg1m[2] != gipa.c_vh{
			log(LOG1, &tos("WARN: prf.v_cg1m[2] != CM([s_2]_1)"));
			return false;
		}
		if agg_prf.v_cg1m[3] != gipa.c_vg{
			log(LOG1, &tos("WARN: prf.v_cg1m[3] != CM([1]_1)"));
			return false;
		}
		if agg_prf.v_cg1t[0] != gipa.c_vg{
			log(LOG1, &tos("WARN: prf.v_cg1t[0] != CM([1]_1)"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C2)"), &mut t1);}

		// (C3) check MIPP and TIPP proofs
		for i in 0..11{
			if !gipa.mipp_verify(&agg_prf.v_cg1m[i], &agg_prf.v_cz[i],
				&agg_prf.r, &agg_prf.v_zm[i], &agg_prf.v_prfm[i]){
				log(LOG1, &format!("WARN: fails mipp prf {}", i));
				return false;
			}
		}
		for i in 0..2{
			if !gipa.tipp_verify(&agg_prf.v_cg1t[i], &agg_prf.v_cg2[i],
				&agg_prf.r, &agg_prf.v_zt[i], &agg_prf.v_prft[i]){
				log(LOG1, &format!("WARN: fails tipp prf {}", i));
				return false;
			}
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C3)"), &mut t1);}

		// (C4) check knowledge proofs
		let pairs = vec![(4,5), (6,7)];
		let g_g2 = key.g_g2;
		let g_beta_g2 = key.g_beta_g2;
		let h_g2 = key.h_g2;
		for pair in pairs{
			let lhs = E::pairing(agg_prf.v_zm[pair.0].into_affine(),g_beta_g2);
			let rhs = E::pairing(agg_prf.v_zm[pair.1].into_affine(),g_g2);
			if lhs!=rhs{
				log(LOG1, &format!("WARN: fails knprf({},{})",pair.0, pair.1));
				return false;
			}
		}
		if ExtensionFieldElement(E::pairing(agg_prf.v_zm[6].into(), g_g2))
				!=agg_prf.v_zt[0]{
			log(LOG1, &format!("WARN: fails w=w2 prf"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C4)"), &mut t1);}

		// (C5) check 
		let lhs = E::pairing(agg_prf.v_zm[9].into_affine(), g_g2)
				* E::pairing(agg_prf.v_zm[8].into_affine(), h_g2);
		let rhs = agg_prf.v_zt[1].clone();
		if ExtensionFieldElement(lhs)!=rhs{
			log(LOG1, &format!("WARN: fails Cp[1]_1 + C1[s_2]_1 = C(q,c_w)"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C5)"), &mut t1);}

		// check C(6)
		let mut lhs = agg_prf.v_zm[0];
		for i in 1..4{ lhs = lhs + agg_prf.v_zm[i];} 
		let rhs = agg_prf.v_zm[10] + 
			agg_prf.v_zm[8].into_affine().mul(agg_prf.c);	
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails prf_1 check"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C6)"), &mut t1);}

		// check C(7)
		let exp_c=hash::<E::Fr>(&to_vecu8(&vec![agg_prf.v_cg1m[10].clone()])); 
		if exp_c != agg_prf.c{
			log(LOG1, &tos("WARN: fails check on agg_prf.c"));
			return false;
		}
		let mut b1 = vec![];
		for i in 0..agg_prf.v_cg1m.len(){
			E::G1Projective::serialize(&agg_prf.v_cz[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::
				serialize(&agg_prf.v_cg1m[i], &mut b1).unwrap();
		}
		for i in 0..2{
			ExtensionFieldElement::<E>::
				serialize(&agg_prf.v_cg1t[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::
				serialize(&agg_prf.v_cg2[i], &mut b1).unwrap();
		}
		let exp_r = hash::<E::Fr>(&b1);
		if exp_r != agg_prf.r{
			log(LOG1, &tos("WARN: fails check on agg_prf.r"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- SubsetPrf agg_ver check (C7)"), &mut t1);}

		return true;
	}

}

impl <E:PairingEngine> ZkSubsetV3Aux <E> 
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// serialization
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::Fr::serialize(&self.x1, &mut b1).unwrap();
		E::Fr::serialize(&self.x2, &mut b1).unwrap();
		E::Fr::serialize(&self.x3, &mut b1).unwrap();
		E::Fr::serialize(&self.x4, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let mut v1 = &v[..];
		let x1= E::Fr::deserialize(&mut v1).unwrap();		
		let x2= E::Fr::deserialize(&mut v1).unwrap();		
		let x3= E::Fr::deserialize(&mut v1).unwrap();		
		let x4= E::Fr::deserialize(&mut v1).unwrap();		

		let res = ZkSubsetV3Aux{
			x1: x1, x2: x2, x3: x3, x4: x4
		};
		return res;
	}

	pub fn dummy() -> Self{
		let zero = E::Fr::zero();
		return Self{x1: zero.clone(), 
			x2: zero.clone(), x3: zero.clone(), x4: zero.clone()};
	}

	pub fn is_dummy(&self) -> bool{
		let v = vec![self.x1, self.x2, self.x3, self.x4];
		for x in v {
			if !x.is_zero() {return false;}
		}
		return true;
	}
}

impl <E:PairingEngine> ZkSubsetV3AggClaim<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&self.c_cp, &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&self.c_cq, &mut b1).unwrap();
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let mut v1 = &v[..];
		let size= usize::deserialize(&mut v1).unwrap();		
		let c_cp = ExtensionFieldElement::<E>::deserialize(&mut v1).unwrap();
		let c_cq = ExtensionFieldElement::<E>::deserialize(&mut v1).unwrap();
		let res = Self{size: size, c_cp: c_cp, c_cq};
		return res;
	}
}

impl <E:PairingEngine> ZkSubsetV3AggProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		E::Fr::serialize(&self.c, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		for i in 0..4{//ONLY 4! skip rest 7
			E::G1Projective::serialize(&self.v_cz[i], &mut b1).unwrap();
		}
		for i in 0..self.v_cg1m.len(){
			ExtensionFieldElement::<E>::
				serialize(&self.v_cg1m[i], &mut b1).unwrap();
		}
		ExtensionFieldElement::<E>::
				serialize(&self.v_cg1t[1], &mut b1).unwrap();
		ExtensionFieldElement::<E>::
				serialize(&self.v_cg2[0], &mut b1).unwrap();

		for i in 0..self.v_zm.len(){
			E::G1Projective::serialize(&self.v_zm[i], &mut b1).unwrap();
		}
		for i in 0..self.v_prfm.len(){
			MyMIPPProof::<E>::serialize(&self.v_prfm[i], &mut b1).unwrap();
		}
		for i in 0..self.v_zt.len(){
			ExtensionFieldElement::<E>::
				serialize(&self.v_zt[i], &mut b1).unwrap();
		}
		for i in 0..self.v_prft.len(){
			MyTIPAProof::<E>::serialize(&self.v_prft[i], &mut b1).unwrap();
		}

		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>, ripp: &GIPA<E>)->Self{
		let mut b1 = &v[..];
		let size= usize::deserialize(&mut b1).unwrap();		
		let c= E::Fr::deserialize(&mut b1).unwrap();
		let r= E::Fr::deserialize(&mut b1).unwrap();
		let mut v_cz = vec![];
		for _i in 0..4{//ONLY 4! 
			v_cz.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		for _i in 4..11{
			v_cz.push(ripp.c_z1.clone());
		}
		assert!(v_cz.len()==11, "c_vz.len !=11");
		let mut v_cg1m = vec![];
		for _i in 0..11{
			v_cg1m.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		}
		let mut v_cg1t = vec![];
		v_cg1t.push(ripp.c_vg.clone());
		v_cg1t.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		v_cg1t.push(v_cg1t[0].clone());
		let mut v_cg2 = vec![];
		v_cg2.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		v_cg2.push(v_cg2[0].clone());

		let mut v_zm = vec![];
		for _i in 0..11{
			v_zm.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		let mut v_prfm= vec![];
		for _i in 0..11{
			v_prfm.push(MyMIPPProof::<E>::deserialize(&mut b1).unwrap());
		}

		let mut v_zt = vec![];
		for _i in 0..2{
			v_zt.push(ExtensionFieldElement::<E>
				::deserialize(&mut b1).unwrap());
		}
		let mut v_prft= vec![];
		for _i in 0..2{
			v_prft.push(MyTIPAProof::<E>::deserialize(&mut b1).unwrap());
		}
		let res = Self{size: size, c: c, r: r,
			v_cz: v_cz, v_cg1m: v_cg1m, v_cg1t: v_cg1t, v_cg2: v_cg2,
			v_zm: v_zm, v_prfm: v_prfm, v_zt: v_zt, v_prft
		};
		return res;
	}
}
