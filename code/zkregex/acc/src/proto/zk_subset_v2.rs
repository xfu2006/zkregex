/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 10/01/2022
	Completed: 08/025/2022
*/

/// This module defines the zero knowledge subset protocol.
/// Compared with zk_subset its prover time is longer and proof is shorter
/// and verification time is faster. Also the superset is hidden as well.
/// TO speed up (as usually witness polynomial is larger), place witnesss
/// on G1 and place kzg_subset on G2. (need an extra element).
///
/// Given: 
/// (1) the extended KZG commitment of polynomial p_superset, 
///  	kzg_superset = g^{p_superset(alpha) h^eta, c_eta = g^eta h^r0} 
///	(2) the extended KZG commitment for p_subset:
/// 	kzg_subset = (g^{p_subset(alpha}) h^gamma, c_gamma = g^gamma h^r1. 
/// Prove that p_subset is
/// a subset of p_superset without leaking information of p_subset
///
/// Proof idea: compute w(x) = p_super(x)/subset(x) and
/// Generate its extended KZG commitment:
/// kzg_w = g^{w(x)} h^beta c_beta  = g^beta h^r2. 
/// Prove their relation using zk_poly.
/// let B = kzg_w^{gamma} kzg_subset^{beta} h^{-gamma * beta} g^{-eta}
/// verify e(kzg_superset, g) e(B, h)= e(kzg_subset, kgz_w) 
/// kzg_w is on group 2
///
/// Performance: 32k (8 nodes 1 computer):  ????????
/// gen time: 37 sec.  vs 28 sec (in V1)
/// (1 node: 8.3 ms vs 10ms in V1, coz saving 2 ). Prf size: 1008 bytes (more expensive than V1 because there is a G2 element)
/// 1M entries: 265 seconds (rouggly linear).

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
use self::ark_ff::{Zero,UniformRand};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
//use self::ark_ff::UniformRand;
use std::any::Any;

use proto::*;
use proto::zk_same::*;
use proto::zk_prod::*;
use proto::zk_poly::*;
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
pub struct ZkSubsetV2Input<E:PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// the superset polynomail 
	pub p_superset: DisPoly<E::Fr>,	
	/// the subset polynomail 
	pub p_subset: DisPoly<E::Fr>,	
	/// gamma: for kzg_subset = g^{p_subset(alpha)} h^gamma
	pub gamma: E::Fr,
	/// r1: for comm_gamma = g^gamma h^r1
	pub r1: E::Fr,
	/// for kzg_superset = g^{p_superset(alpha)} h^eta
	pub eta: E::Fr,
	/// for comm_eta = g^eta h^r0
	pub r0: E::Fr
}

#[derive(Clone)]
pub struct ZkSubsetV2Claim<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// the EXTENDED kzg commitment of superset(x) = g^p_suprset(alpha) h^eta
	pub kzg_superset: E::G1Affine,
	/// comm_eta = g^eta h^r0
	pub comm_eta: E::G1Affine,
	/// kzg_subset = g^{p_subset(alpha} h^gamma
	pub kzg_subset: E::G1Affine,
	/// comm_gamma: g^gamma h^r1 (2nd part of extended KZG of p_subset)
	pub comm_gamma: E::G1Affine
}

#[derive(Clone)]
pub struct ZkSubsetV2Proof<E: PairingEngine>where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// kzg_w = g^{w(alpha)} h^beta 
	pub kzg_w: E::G1Affine,
	/// comm_beta (Pedersen commitment to beta)
	pub comm_beta: E::G1Affine,
	/// kzg_subset over G2
	pub kzg_subset_g2: E::G2Affine,
	/// Balanceing term B= kzg_w^{gamma} kzg_subset^{beta} h^{-gamma* beta} g^{eta}
	pub b: E::G1Affine,
	/// comm_gamma_beta = g^{gamma*beta} h^r2, (little extra for convenince
	/// of implementation), could be skipped actually
	pub comm_gamma_beta: E::G1Affine,
	/// proof that comm_gamma_beta is a Pedersen commitemnt to alpha*beta
	pub prf_prod: ZkProdProof<E::G1Affine>,
	/// zk_poly proof for pair (kzg_w, comm_beta) 
	pub prf_poly: ZkPolyProof<E>,
	/// zk_same proof
	pub prf_same: ZkSameProof<E::G1Affine>
}


#[derive(Clone)]
pub struct ZkSubsetV2<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}} on both G1 and G2
	pub key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 
impl <E:PairingEngine> ProverInput for ZkSubsetV2Input<E> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkSubsetV2Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg_w, &mut b1).unwrap();
		E::G1Affine::serialize(&self.comm_beta, &mut b1).unwrap();
		E::G2Affine::serialize(&self.kzg_subset_g2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.b, &mut b1).unwrap();
		E::G1Affine::serialize(&self.comm_gamma_beta, &mut b1).unwrap();
		let mut b2 = self.prf_prod.to_bytes();
		let mut b3 = self.prf_poly.to_bytes();
		let mut b4 = self.prf_same.to_bytes();
		b1.append(&mut b2);
		b1.append(&mut b3);
		b1.append(&mut b4);
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v1 = &v[..];
		let kzg_w = E::G1Affine::deserialize(&mut v1).unwrap();		
		let comm_beta = E::G1Affine::deserialize(&mut v1).unwrap();		
		let kzg_subset_g2 = E::G2Affine::deserialize(&mut v1).unwrap();		
		let b = E::G1Affine::deserialize(&mut v1).unwrap();		
		let comm_gamma_beta= E::G1Affine::deserialize(&mut v1).unwrap();		

		let start_pos = comm_beta.serialized_size()*4 + kzg_subset_g2.serialized_size();
		let v2 = &v[start_pos..].to_vec();
		let prf_prod= ZkProdProof::<E::G1Affine>::static_from_bytes(&v2);
		
		//a little slow, imprv later
		let start_pos2 = start_pos + prf_prod.to_bytes().len(); 
		let v3 = &v[start_pos2..].to_vec();
		let prf_poly = ZkPolyProof::<E>::static_from_bytes(&v3);

		let start_pos3 = start_pos2 + prf_poly.to_bytes().len(); 
		let v4 = &v[start_pos3..].to_vec();
		let prf_same= ZkSameProof::<E::G1Affine>::static_from_bytes(&v4);

		let res = ZkSubsetV2Proof{
			kzg_w: kzg_w,
			comm_beta: comm_beta,
			kzg_subset_g2: kzg_subset_g2,
			b: b,
			comm_gamma_beta: comm_gamma_beta,
			prf_prod: *prf_prod,
			prf_poly: *prf_poly,
			prf_same: *prf_same	
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		print!("{} ZkSubsetV2Prf: kzg_w: {:?}, comm_beta: {:?}, b: {:?}, comm_gamma_beta: {:?}", prefix, self.kzg_w, self.comm_beta, self.b, self.comm_gamma_beta);
		self.prf_prod.dump(" prf_prod:");
		self.prf_poly.dump(" prf_poly:");
		self.prf_same.dump(" prf_same:");
	} 
}

impl <E:PairingEngine> Proof for ZkSubsetV2Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg_w = res.kzg_w.clone();
		self.comm_beta = res.comm_beta.clone();
		self.kzg_subset_g2 = res.kzg_subset_g2.clone();
		self.b= res.b.clone();
		self.comm_gamma_beta= res.comm_gamma_beta.clone();
		self.prf_prod= res.prf_prod.clone();
		self.prf_poly= res.prf_poly.clone();
		self.prf_same = res.prf_same.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkSubsetV2Proof::<E> = other.as_any().
			downcast_ref::<ZkSubsetV2Proof<E>>().unwrap();
		return self.kzg_w==obj.kzg_w 
			&& self.comm_beta==obj.comm_beta
			&& self.kzg_subset_g2==obj.kzg_subset_g2
			&& self.b==obj.b 
			&& self.comm_gamma_beta==obj.comm_gamma_beta
			&& self.prf_prod.equals(&obj.prf_prod)
			&& self.prf_poly.equals(&obj.prf_poly)
			&& self.prf_same.equals(&obj.prf_same);
	}
}


impl <E:PairingEngine> ProtoObj for ZkSubsetV2Claim<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg_superset, &mut b1).unwrap();
		E::G1Affine::serialize(&self.comm_eta, &mut b1).unwrap();
		E::G1Affine::serialize(&self.kzg_subset, &mut b1).unwrap();
		E::G1Affine::serialize(&self.comm_gamma, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let kzg_superset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let comm_eta = E::G1Affine::deserialize(&mut v2).unwrap();		
		let kzg_subset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let comm_gamma = E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkSubsetV2Claim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
			comm_gamma: comm_gamma,
			comm_eta: comm_eta,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (kzg_superset: {:?}, kzg_subset: {:?}, comm_gamma: {:?})", 
			prefix, self.kzg_superset, self.kzg_subset, self.comm_gamma);
	} 
}

impl <E:PairingEngine> Claim for ZkSubsetV2Claim<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg_superset  = res.kzg_superset;
		self.comm_eta= res.comm_eta;
		self.kzg_subset  = res.kzg_subset;
		self.comm_gamma = res.comm_gamma;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkSubsetV2Claim::<E> = obj.as_any().
			downcast_ref::<ZkSubsetV2Claim<E>>().unwrap();
		return self.kzg_superset==other.kzg_superset && 
			self.kzg_subset==other.kzg_subset &&
			self.comm_gamma==other.comm_gamma &&
			self.comm_eta==other.comm_eta;
	}
}


impl <E:PairingEngine> Protocol<E> for ZkSubsetV2 <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkSubsetV2";
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let proto = ZkSubsetV2{ key: key};
		return proto;
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let sinp:&mut ZkSubsetV2Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkSubsetV2Input<E>>().unwrap();
		//1. compute the W polynomial
		let g1 = self.key.g.into_affine();
		let kzg_superset = self.key.gen_kzg(&mut sinp.p_superset)[0] + 
			self.key.h.mul(sinp.eta).into_affine();
		let kzg_subset = self.key.gen_kzg(&mut sinp.p_subset)[0] 
			+ self.key.h.mul(sinp.gamma).into_affine();
		let comm_gamma = g1.mul(sinp.gamma) + self.key.h.mul(sinp.r1);
		let comm_eta= g1.mul(sinp.eta) + self.key.h.mul(sinp.r0);
		let claim = ZkSubsetV2Claim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
			comm_gamma: comm_gamma.into_affine(),
			comm_eta: comm_eta.into_affine(),
		};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let sinp:&mut ZkSubsetV2Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkSubsetV2Input<E>>().unwrap();
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		let mut t3 = Timer::new();
		let mut t4 = Timer::new();
		let mut t5 = Timer::new();
		let mut t6 = Timer::new();

		t1.start();
		//1. compute the W polynomial
		let mut p_superset = sinp.p_superset.clone();
		let mut p_subset = sinp.p_subset.clone();
		let (mut dq, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(
			&mut p_superset, &mut p_subset);
		let bzero = dr.is_zero();
		if RUN_CONFIG.my_rank==0{//only check at main processor 0
			assert!(bzero, "ZkSubsetV2::prove() ERR: remainder of step1 != 0!");
		}
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let inv_g =  (E::G1Affine::zero().into_projective() - self.key.g).into_affine();
		let inv_h =  (E::G1Affine::zero().into_projective() - self.key.h.into_projective()).into_affine();
		t1.stop();


		t2.start();
		//2. evaluate the kzg_w over Group G1 
		dq.to_partitions();
		let mut rng = gen_rng();
		let r2 = E::Fr::rand(&mut rng);
		let beta = E::Fr::rand(&mut rng);
		let r3 = E::Fr::rand(&mut rng);
		let wval1 = self.key.gen_kzg(&mut dq)[0]; //g^{w(alpha)}
		let wval2 = self.key.h.mul(beta);
		let kzg_w = wval1+wval2.into_affine();
		let comm_beta = g.mul(beta) + h.mul(r2);
		t2.stop();


		t3.start();
		//3. compute b
		let prod_gamma_beta = sinp.gamma * beta;
		//let kzg_superset = self.key.gen_kzg(&sinp.p_superset)[0];
		let kzg_subset= 
			self.key.gen_kzg(&mut sinp.p_subset)[0] +
			self.key.h.mul(sinp.gamma).into_affine();
		let kzg_subset_g2 = 
			self.key.gen_kzg_g2(&mut sinp.p_subset)[0] +
			self.key.h_g2.mul(sinp.gamma).into_affine();
		let b = kzg_w.mul(sinp.gamma) + kzg_subset.mul(beta) +  inv_h.mul(prod_gamma_beta) + inv_g.mul(sinp.eta);
		t3.stop();


		t4.start();
		//4. build the proof for prf_poly
		let zk_poly = ZkPoly::<E>::new(self.key.clone());
		let mut zkpoly_input = ZkPolyInput::<E>{q: dq, r: beta, r2: r2};
		let prf_poly = zk_poly.prove(&mut zkpoly_input).as_any().
			downcast_ref::<ZkPolyProof<E>>().unwrap().clone(); 
		t4.stop();


		t5.start();
		//4. compute the prf_prod 
		let zkprod = ZkProd::new_with_generator(self.key.clone(), g, h);
		let mut prod_inp = ZkProdInput::<E::G1Affine>{
			x: sinp.gamma, //comm_gamma = g^gamma h^r1
			r1: sinp.r1,
			y: beta, //comm_beta = g^beta h^r2
			r2: r2,
			r3: r3, //comm_gamma_beta: g^(gamma*beta) h^r3
		};
		let prf_prod = zkprod.prove(&mut prod_inp).as_any().
			downcast_ref::<ZkProdProof<E::G1Affine>>().unwrap().clone(); 
		let comm_gamma_beta= self.key.g.into_affine().
			mul(sinp.gamma * beta) +self.key.h.mul(r3);
		t5.stop();


		t6.start();
		//4. compute the zk_same proof 
		let exps = vec![
			vec![sinp.gamma, beta, prod_gamma_beta, sinp.eta], //B
			vec![sinp.gamma, sinp.r1], //comm_gamma = g^gamma h^r1
			vec![beta, r2], //comm_beta= g^beta h^r2
			vec![prod_gamma_beta, r3], // 1/comm_gamma_beta
			vec![sinp.eta, sinp.r0], // comm_eta
		];
		let mut zksame_input = ZkSameInput::<E::G1Affine>{ exps: exps };
		let bases = vec![
			vec![kzg_w, kzg_subset, inv_h, inv_g], //B
			vec![g, h], // comm_gamma 
			vec![g, h], // comm_beta 
			vec![inv_g, inv_h], // 1/comm_gamma_beta
			vec![inv_g, inv_h], // 1/comm_eta
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let prf_same = zksame.prove(&mut zksame_input).as_any().
			downcast_ref::<ZkSameProof<E::G1Affine>>().unwrap().clone(); 
		t6.stop();


		//5. build up the proof
		let kprf = ZkSubsetV2Proof::<E>{
			kzg_w: kzg_w,
			comm_beta: comm_beta.into_affine(),
			kzg_subset_g2: kzg_subset_g2,
			b: b.into_affine(),
			comm_gamma_beta: comm_gamma_beta.into_affine(),
			prf_prod: prf_prod,
			prf_poly: prf_poly,
			prf_same: prf_same	
		};
		return Box::new(kprf);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//1. type casting
		let p_claim:&ZkSubsetV2Claim::<E> = claim.as_any().
			downcast_ref::<ZkSubsetV2Claim<E>>().unwrap();
		let p_proof:&ZkSubsetV2Proof::<E> = proof.as_any().
			downcast_ref::<ZkSubsetV2Proof<E>>().unwrap();
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let g_g2 = self.key.g_g2;
		let h_g2 = self.key.h_g2;
		let inv_g =  (E::G1Affine::zero().into_projective() - self.key.g).into_affine();
		let inv_h =  (E::G1Affine::zero().into_projective() - self.key.h.into_projective()).into_affine();
		let bases = vec![
			vec![p_proof.kzg_w, p_claim.kzg_subset, inv_h, inv_g], //B
			vec![g, h], // comm_gamma 
			vec![g, h], // comm_beta 
			vec![inv_g, inv_h], // 1/comm_gamma_beta
			vec![inv_g, inv_h], // 1/comm_eta
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let zk_poly = ZkPoly::new(self.key.clone());
		let zk_prod = ZkProd::new_with_generator(self.key.clone(), g, h);

		//2. check equation of pairing:
		// e(kzg_superset, g) e(b, h) = e(kzg_w, kzg_subset)
		// e(kzg_subset_g1, h) = e(h, kzg_subset)
		if RUN_CONFIG.my_rank!=0 {return true;} //only check on main node
		if E::pairing(p_claim.kzg_subset, g_g2) != E::pairing(g, p_proof.kzg_subset_g2){
			println!("DEBUG USE 301: failed pairing check1");
			return false;
		}
		if  E::pairing(p_claim.kzg_superset, g_g2) * E::pairing(p_proof.b, h_g2)
			!= E::pairing(p_proof.kzg_w, p_proof.kzg_subset_g2){
			println!("DEBUG USE 301: failed pairing check2");
			return false;
		}

		//4. check the prf_poly instance
		let poly_claim= ZkPolyClaim::<E>{c_q: p_proof.kzg_w, c_r: p_proof.comm_beta};
		let bres = zk_poly.verify(&poly_claim, &p_proof.prf_poly);
		if !bres{
			println!("DEBUG USE 301: failed zk_poly");
			return false;
		}

		//5. check the prf_prod instance
		let prod_claim = ZkProdClaim::<E::G1Affine>{
			a: p_claim.comm_gamma, 
			b: p_proof.comm_beta, 
			c: p_proof.comm_gamma_beta
		};
		let bres = zk_prod.verify(&prod_claim, &p_proof.prf_prod);
		if !bres{
			println!("DEBUG USE 302: failed zk_prod");
			return false;
		}

		//6. check the prf_same instance
		let inv_comm_gamma_beta = (E::G1Affine::zero().into_projective() - p_proof.comm_gamma_beta.into_projective()).into_affine();
		let inv_comm_eta= (E::G1Affine::zero().into_projective() - p_claim.comm_eta.into_projective()).into_affine();
		let y = vec![p_proof.b, p_claim.comm_gamma, p_proof.comm_beta, inv_comm_gamma_beta, inv_comm_eta];
		let zksame_claim = ZkSameClaim::<E::G1Affine>{y: y}; 
		let bres = zksame.verify(&zksame_claim, &p_proof.prf_same); 
		if !bres{
			println!("DEBUG USE 303: failed zk_same");
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
		if n>key.n-16 {panic!("ZkSubsetV2::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let n = n/2;		 //make it half.
		let mut rng = gen_rng_from_seed(seed);
		let gamma = E::Fr::rand(&mut rng);
		let eta = E::Fr::rand(&mut rng);
		let r1 = E::Fr::rand(&mut rng);
		let r0 = E::Fr::rand(&mut rng);
		let proto = ZkSubsetV2::<E>::new(key); 		 //factory instance
		let p_factor= DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_factor= DisPoly::<E::Fr>::from_serial(0, &p_factor, &p_factor.degree()+1);
		let p_subset = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp_subset = DisPoly::<E::Fr>::from_serial(0, &p_subset, &p_subset.degree()+1);
		let mut dp_superset = DisPoly::<E::Fr>::mul(&mut dp_factor, &mut dp_subset);
		dp_subset.to_partitions();
		dp_superset.to_partitions(); 

		//2. builds SubsetV2Input 
		let mut inp: ZkSubsetV2Input<E> = ZkSubsetV2Input{
			p_superset: dp_superset, p_subset: 
			dp_subset, gamma: gamma, eta: eta, r1: r1, r0: r0};  
		let prf = proto.prove(&mut inp);
		let mut claim = proto.claim(&mut inp);

		//3. introduce error if asked
		if b_set_err { 
			let kclaim:&ZkSubsetV2Claim::<E> = claim.as_any().
				downcast_ref::<ZkSubsetV2Claim<E>>().unwrap();
			let new_kzg_subset = kclaim.kzg_subset.mul(2u32).into_affine();
			let bad_claim: ZkSubsetV2Claim<E> = ZkSubsetV2Claim{
				kzg_superset: kclaim.kzg_superset.clone(),
				kzg_subset: new_kzg_subset,
				comm_gamma: kclaim.comm_gamma.clone(),
				comm_eta: kclaim.comm_eta.clone()
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

}

impl <E:PairingEngine> ZkSubsetV2 <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// generate the proof (FASTER WAY. Given directly
	///  g^p(alpha), g^w(alpha), g^q(alpha) without computing it. 
	/// gwit = g^w(alpha) where w = p_superset/p_subset
	/// gwit_beta = g^w(alpha) * beta
	/// gsubset = g^subset(alpha)
	/// gsubset_g2= g^{subset(alpha)} over G2
	/// gamma: used to compute the kzg_subset = g^subset(alpha) h^gamma
	/// eta: used to compute kzg_superset = g^superset(alpha) h^eta 
	/// r0: used to produce comm_eta = g^eta h^r0
	/// r1: used to produce comm_gamma = g^gamma h^r1 
	/// NOTE: it only return valid result in main processor 0!!!
	pub fn shortcut_prove(&self, 
		gwit: E::G1Affine, gwit_beta: E::G1Affine,
		gsubset: E::G1Affine, gsubset_g2: E::G2Affine, 
		gamma: E::Fr, eta: E::Fr, r0: E::Fr, r1: E::Fr) -> Box<dyn Proof> {
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let inv_g =  (E::G1Affine::zero().into_projective() - self.key.g).into_affine();
		let inv_h =  (E::G1Affine::zero().into_projective() - self.key.h.into_projective()).into_affine();
		//let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		let mut t3 = Timer::new();
		let mut t4 = Timer::new();
		let mut t5 = Timer::new();
		let mut t6 = Timer::new();

		t2.start();
		//2. evaluate the kzg_w over Group G1 
		let mut rng = gen_rng();
		let beta = E::Fr::rand(&mut rng);
		let r2 = E::Fr::rand(&mut rng);
		let r3 = E::Fr::rand(&mut rng);
		let wval2 = self.key.h.mul(beta);
		let kzg_w = gwit + wval2.into_affine();
		let comm_beta = g.mul(beta) + h.mul(r2);
		t2.stop();


		t3.start();
		//3. compute b
		let prod_gamma_beta = gamma * beta;
		//let kzg_superset = self.key.gen_kzg(&sinp.p_superset)[0];
		let kzg_subset= gsubset + self.key.h.mul(gamma).into_affine();
		let kzg_subset_g2 = gsubset_g2 + self.key.h_g2.mul(gamma).into_affine();
		let b = kzg_w.mul(gamma) + kzg_subset.mul(beta) +  inv_h.mul(prod_gamma_beta) + inv_g.mul(eta);
		t3.stop();


		t4.start();
		//4. build the proof for prf_poly
		let zk_poly = ZkPoly::<E>::new(self.key.clone());
		let prf_poly = zk_poly.shortcut_prove(gwit_beta, beta, r2).as_any().
			downcast_ref::<ZkPolyProof<E>>().unwrap().clone(); 
		t4.stop();


		t5.start();
		//4. compute the prf_prod 
		let zkprod = ZkProd::new_with_generator(self.key.clone(), g, h);
		let mut prod_inp = ZkProdInput::<E::G1Affine>{
			x: gamma, //comm_gamma = g^gamma h^r1
			r1: r1,
			y: beta, //comm_beta = g^beta h^r2
			r2: r2,
			r3: r3, //comm_gamma_beta: g^(gamma*beta) h^r3
		};
		let prf_prod = zkprod.prove(&mut prod_inp).as_any().
			downcast_ref::<ZkProdProof<E::G1Affine>>().unwrap().clone(); 
		let comm_gamma_beta= self.key.g.into_affine().
			mul(gamma * beta) +self.key.h.mul(r3);
		t5.stop();


		t6.start();
		//4. compute the zk_same proof 
		let exps = vec![
			vec![gamma, beta, prod_gamma_beta, eta], //B
			vec![gamma, r1], //comm_gamma = g^gamma h^r1
			vec![beta, r2], //comm_beta= g^beta h^r2
			vec![prod_gamma_beta, r3], // 1/comm_gamma_beta
			vec![eta, r0], // comm_eta
		];
		let mut zksame_input = ZkSameInput::<E::G1Affine>{ exps: exps };
		let bases = vec![
			vec![kzg_w, kzg_subset, inv_h, inv_g], //B
			vec![g, h], // comm_gamma 
			vec![g, h], // comm_beta 
			vec![inv_g, inv_h], // 1/comm_gamma_beta
			vec![inv_g, inv_h], // 1/comm_eta
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let prf_same = zksame.prove(&mut zksame_input).as_any().
			downcast_ref::<ZkSameProof<E::G1Affine>>().unwrap().clone(); 
		t6.stop();


		//5. build up the proof
		let kprf = ZkSubsetV2Proof::<E>{
			kzg_w: kzg_w,
			comm_beta: comm_beta.into_affine(),
			kzg_subset_g2: kzg_subset_g2,
			b: b.into_affine(),
			comm_gamma_beta: comm_gamma_beta.into_affine(),
			prf_prod: prf_prod,
			prf_poly: prf_poly,
			prf_same: prf_same	
		};
		return Box::new(kprf);
	}

	/// generate the claim in shortcut way
	/// NOTE only return valid result in main processor 0
	pub fn shortcut_claim(&self,  g_superset: E::G1Affine, g_subset: E::G1Affine, gamma: E::Fr, eta: E::Fr, r0: E::Fr, r1: E::Fr) -> Box<dyn Claim> {
		//1. compute the W polynomial
		let g1 = self.key.g.into_affine();
		let kzg_superset = g_superset + self.key.h.mul(eta).into_affine();
		let kzg_subset = g_subset + self.key.h.mul(gamma).into_affine();
		let comm_gamma = g1.mul(gamma) + self.key.h.mul(r1);
		let comm_eta= g1.mul(eta) + self.key.h.mul(r0);
		let claim = ZkSubsetV2Claim::<E>{
			kzg_superset: kzg_superset,
			kzg_subset: kzg_subset,
			comm_gamma: comm_gamma.into_affine(),
			comm_eta: comm_eta.into_affine(),
		};
		return Box::new(claim);
	}

}

