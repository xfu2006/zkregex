/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 03/18/2023
	Revised: 03/28/2023 -> Add Aggregation Support
	Completed: 03/29/2023
*/

/// This module defines the blindeval KZG protocol (see paper)
/// It is EXTENDED with an additional zk_same proof for the zkregex application
///
/// 	Claim: 
/// 		Let C_p = g^{p(alpha) h^r_p} be its zk-vpd commitment.
/// 		r the random challenge point
/// 		Let C_z be a G1 elemen.
///		We claim that C_z is the Pedersen commitment to p(r), i.e.
///			C_z = g1^{p(r)} g2^s1 g3^sn g2^r4 g3^r5.
///			Here s1 and sn are the first and last states of the
///			path for future connection proof
/// 
/// 	Public input: 
///			g1, g2, g3, g4, g5 (assume no linear relation between them)
///
/// 	SecretInput:
/// 		p: DisPoly; and nonces r, s1, sn, r4, r5, 


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
use self::ark_ff::{Zero,One};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;
use self::ark_inner_products::{ExtensionFieldElement};
use proto::ripp_driver::*;

use std::any::Any;
use std::rc::Rc;

use proto::*;
use poly::dis_poly::*;
//use poly::dis_key::*;
use poly::serial::*;
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
pub struct ZkKZGV2Input<E:PairingEngine>{
	/// the polynomail to prove
	pub p: DisPoly<E::Fr>,	
	/// random nonce for C_p = g^{p(alpha)} h^r_p
	pub r_p: E::Fr,
	/// the random nonce for p(r)
	pub r: E::Fr,
	/// state 1 on accepthan path
	pub s1: E::Fr,
	/// last state on acceptance path
	pub sn: E::Fr,
	/// random challenge for: c_z = g1^{p(r)} g2^{s1} g3^{sn} g4^(r4) g5^r5
	pub r4: E::Fr,
	/// last random  
	pub r5: E::Fr,
	/// bases for Pedersen commitment: c_z.
	pub g1: E::G1Affine,
	pub g2: E::G1Affine,
	pub g3: E::G1Affine,
	pub g4: E::G1Affine,
	pub g5: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkKZGV2Proof<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// c1 = [y + ry s2]_1 (see paper)
	pub c1: E::G1Affine,
	/// c2 = [s2(s1-t)r_q + (ry-rp)]_1
	pub c2: E::G1Affine,
	/// cy = [p(r) + r_y s2]]1
	pub cy: E::G1Affine,
	/// DLOG y proof R, s1, s2
	pub prf_y_r: E::G1Affine,
	pub prf_y: Vec<E::Fr>,
	/// DLOG C2 R, s1, s2
	pub prf_2_r: E::G1Affine,
	pub prf_2: Vec<E::Fr>,
	/// DLOG c_z [R, s1, s2, s3, s4, s5]
	pub prf_z_r: E::G1Affine,
	pub prf_z: Vec<E::Fr>,
	/// the fiat-shamir challenge
	pub c: E::Fr,
	/// aux information
	pub aux: ZkKZGV2Aux<E>,
}

/** The claim is that the polyomial behind c_p evalutes to z
and z is behind Pedersen commitment c_z.
Note that s1,sn are the first and last states for connecting
proofs (segments of a file).
r4 and r5 are blinding factors.
r5 is the ri1 from Groth16 (which is "FIXED". Thus needs an
additional r4 for zk.
*/
#[derive(Clone)]
pub struct ZkKZGV2Claim<E: PairingEngine>{
	/// the extended KZG commitment of q(x), i.e., g^{q(\alpha)} h^r_p
	pub c_p: E::G1Affine,
	/// the Pedersen commitment C_z = g1^{p(r)} g2^s1 g3^sn g4^r4 g3^r5
	pub c_z: E::G1Affine,
	/// the random challenge point
	pub r: E::Fr,
	/// bases for Pedersen commitment: c_z.
	pub g1: E::G1Affine,
	pub g2: E::G1Affine,
	pub g3: E::G1Affine,
	pub g4: E::G1Affine,
	pub g5: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkKZGV2<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key 
	pub key: Rc<DisKey<E>>,
}

#[derive(Clone)]
pub struct ZkKZGV2Aux<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	// the aux information for Cy = [y+ry(s2)], C2 = [rq+(ry-rp)(s2)]_1, 
	// Cz = yg1 + s1g2 + sng3 + r3g4 + r5g5
	// Note: sy1 is the SAME as sz1 (due to same y used)
	// the aux are the SECRET information for the three DLOG proofs
	// see prove_direct()
	pub y: E::Fr,
	pub ry: E::Fr,
	pub rq: E::Fr,
	pub ry_rp: E::Fr,
	pub s1: E::Fr,
	pub sn: E::Fr,
	pub r4: E::Fr,
	pub r5: E::Fr,
}

/// aggregated claim 
#[derive(Clone)]
pub struct ZkKZGV2AggClaim<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many proofs are aggregated
	pub size: usize,
	/// commitments to the vector of C_p
	pub c_cp: ExtensionFieldElement<E>,
	/// commitments to the vector of C_z
	pub c_cz: ExtensionFieldElement<E>,
	///  commitment to the vector of NEGATIVE of r!!!!
	pub c_neg_r: E::G1Projective,
}

/// aggregated proof 
#[derive(Clone)]
pub struct ZkKZGV2AggProof<E: PairingEngine> where 
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

impl <E:PairingEngine> ProverInput for ZkKZGV2Input<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkKZGV2Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c1, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.cy, &mut b1).unwrap();
		E::G1Affine::serialize(&self.prf_y_r, &mut b1).unwrap();
		for i in 0..2{E::Fr::serialize(&self.prf_y[i], &mut b1).unwrap();}
		E::G1Affine::serialize(&self.prf_2_r, &mut b1).unwrap();
		for i in 0..2{E::Fr::serialize(&self.prf_2[i], &mut b1).unwrap();}
		E::G1Affine::serialize(&self.prf_z_r, &mut b1).unwrap();
		for i in 0..5{E::Fr::serialize(&self.prf_z[i], &mut b1).unwrap();}
		E::Fr::serialize(&self.c, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c1 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let c2 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let cy = E::G1Affine::deserialize(&mut v2).unwrap();		
		let prf_y_r = E::G1Affine::deserialize(&mut v2).unwrap();		
		let mut prf_y = vec![E::Fr::zero(); 2];
		for i in 0..2{prf_y[i] = E::Fr::deserialize(&mut v2).unwrap();}

		let prf_2_r = E::G1Affine::deserialize(&mut v2).unwrap();		
		let mut prf_2 = vec![E::Fr::zero(); 2];
		for i in 0..2{prf_2[i] = E::Fr::deserialize(&mut v2).unwrap();}

		let prf_z_r = E::G1Affine::deserialize(&mut v2).unwrap();		
		let mut prf_z = vec![E::Fr::zero(); 5];
		for i in 0..5{prf_z[i] = E::Fr::deserialize(&mut v2).unwrap();}
		let c= E::Fr::deserialize(&mut v2).unwrap();		

		let res = ZkKZGV2Proof::<E>{
			c1: c1, c2: c2, cy: cy, prf_y_r: prf_y_r, prf_y: prf_y,
			prf_2_r: prf_2_r, prf_2: prf_2, prf_z_r: prf_z_r, prf_z: prf_z,
			c: c, aux: ZkKZGV2Aux::<E>::dummy()}; 
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkKZGV2Prf(c1: {:?}, c2: {:?}, cy: {:?} ... ", 
			prefix, self.c1, self.c2, self.cy);
	}
}

impl <E:PairingEngine> Proof for ZkKZGV2Proof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c1= res.c1.clone();
		self.c2= res.c2.clone();
		self.cy= res.cy.clone();
		self.prf_y_r= res.prf_y_r.clone();
		self.prf_y= res.prf_y.clone();
		self.prf_2_r= res.prf_2_r.clone();
		self.prf_2= res.prf_2.clone();
		self.prf_z_r= res.prf_z_r.clone();
		self.prf_z= res.prf_z.clone();
		self.c= res.c.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkKZGV2Proof::<E> = other.as_any().
			downcast_ref::<ZkKZGV2Proof<E>>().unwrap();
		return self.c1 == obj.c1
			&& self.c2 == obj.c2
			&& self.cy == obj.cy
			&& self.prf_y_r== obj.prf_y_r
			&& self.prf_y== obj.prf_y
			&& self.prf_2_r== obj.prf_2_r
			&& self.prf_2== obj.prf_2
			&& self.prf_z_r== obj.prf_z_r
			&& self.prf_z== obj.prf_z
			&& self.c== obj.c
	}
}

impl <E:PairingEngine> ProtoObj for ZkKZGV2Claim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_p, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_z, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g1, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g2, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g3, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g4, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g5, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c_p= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_z= E::G1Affine::deserialize(&mut v2).unwrap();		
		let r= E::Fr::deserialize(&mut v2).unwrap();		
		let g1= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g2= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g3= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g4= E::G1Affine::deserialize(&mut v2).unwrap();		
		let g5= E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkKZGV2Claim::<E>{c_p: c_p, c_z: c_z, r: r, 
			g1: g1, g2:g2, g3:g3, g4:g4, g5:g5};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkKZGV2Claim: c_p: {:?}, c_z: {:?}, r: {:?}...",
			 prefix, self.c_p, self.c_z, self.r);
	} 
}

impl <E:PairingEngine> Claim for ZkKZGV2Claim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_p= res.c_p;
		self.c_z= res.c_z;
		self.r= res.r;
		self.g1= res.g1;
		self.g2= res.g2;
		self.g3= res.g3;
		self.g4= res.g4;
		self.g5= res.g5;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkKZGV2Claim::<E> = obj.as_any().
			downcast_ref::<ZkKZGV2Claim<E>>().unwrap();
		return self.c_p==other.c_p 
			&& self.c_z==other.c_z
			&& self.r==other.r
			&& self.g1==other.g1
			&& self.g2==other.g2
			&& self.g3==other.g3
			&& self.g4==other.g4
			&& self.g5==other.g5;
	}
}

impl <E:PairingEngine> Protocol<E> for ZkKZGV2 <E>  where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkKZGV2";
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkKZGV2Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkKZGV2Input<E>>().unwrap();
		let c_p = self.key.gen_kzg(&mut kinp.p)[0] + 
			self.key.h.mul(kinp.r_p).into_affine();
		let y = kinp.p.eval(&kinp.r);
		let c_z = kinp.g4.mul(y) + kinp.g1.mul(kinp.s1) + 
			kinp.g2.mul(kinp.sn) + kinp.g3.mul(kinp.r4) +
			kinp.g5.mul(kinp.r5);
		let claim = ZkKZGV2Claim::<E>{
			c_p: c_p, 
			c_z: c_z.into_affine(),
			r: kinp.r,
			g1: kinp.g1,
			g2: kinp.g2,
			g3: kinp.g3,
			g4: kinp.g4,
			g5: kinp.g5
		};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//0. downcast input
		let kinp:&mut ZkKZGV2Input::<E> = inp.as_any_mut().
			downcast_mut::<ZkKZGV2Input<E>>().unwrap();
		let c_p = self.key.gen_kzg(&mut kinp.p)[0] + 
			self.key.h.mul(kinp.r_p).into_affine();
		let p_r = kinp.p.eval(&kinp.r);
		let (prf, _clm) = self.prove_direct(
			&mut kinp.p, kinp.r_p, kinp.r, 
			kinp.g1, kinp.g2, kinp.g3, kinp.g4, kinp.g5,
			kinp.s1, kinp.sn, kinp.r4, kinp.r5, c_p, p_r);
		return Box::new(prf);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }
		let b_perf = false;
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		t1.start();
		t2.start();

		//1. type casting
		let pc:&ZkKZGV2Claim::<E> = claim.as_any().
			downcast_ref::<ZkKZGV2Claim<E>>().unwrap();
		let pp:&ZkKZGV2Proof::<E> = proof.as_any().
			downcast_ref::<ZkKZGV2Proof<E>>().unwrap();
		let zero = E::Fr::zero();
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let g_g2 = self.key.g_g2;
		//let alpha_g2 = self.key.powers_g2[1];
		let alpha_g2 = self.key.g_alpha_g2; //g_powers_g2[1];
		let gh = self.key.gh; // the [s1s2]_1 in paper
		let gt = gh + h.mul(zero-pc.r).into_affine(); 
		let b1 = dlog_ver::<E>(pp.cy, pp.prf_y_r, 
			pp.c,&vec![g,h],&pp.prf_y);  
		ck(b1, "prf_y fails");
		let b2 = dlog_ver::<E>(pp.c2, pp.prf_2_r, 
			pp.c,&vec![gt,h],&pp.prf_2);  
		ck(b2, "prf_2 fails");
		let b3 = dlog_ver::<E>(pc.c_z, pp.prf_z_r, 
			pp.c,&vec![pc.g4,pc.g1,pc.g2,pc.g3,pc.g5],&pp.prf_z);  
		ck(b3, "prf_z fails");
		let b4 = pp.prf_z[0]==pp.prf_y[0];
		ck(b4, "prfz[0]!=prfy[0]");
		let hash2 = hash::<E::Fr>(&to_vecu8(&vec![pp.prf_y_r, pp.prf_2_r, pp.prf_z_r]));
		let b5 = hash2==pp.c;
		ck(b5, "hash not right!");
		if b_perf {log_perf(LOG1,&format!("----- ZKGVer Step1: check DLOGS"), 
			&mut t1);}
	
		//2. check equation of pairing:
		//(Cp - Cy + C2) [1]_2 = C1 [s-t]_2, here alpha is the s in paper
		let lexp1 = pc.c_p.into_projective() - pp.cy.into_projective() + pp.c2.into_projective();
		let lhs = E::pairing(lexp1, self.key.g_g2);
		let neg_r = zero - pc.r;
		let g2_r = alpha_g2 + g_g2.mul(neg_r).into_affine();
		let rhs = E::pairing(pp.c1, g2_r);
		let b6 = lhs==rhs;
		ck(b6, "(Cp-Cy+C2 ) [1]_2 != C1 [s-r]_2");
		if b_perf {log_perf(LOG1,&format!("----- ZKGVer Step2: Pairing"), 
			&mut t1);}
		return b1 && b2 && b3 && b4 && b5 && b6; 
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	/// if vec_g5s is empty, then create its own
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		return self.rand_inst_adv(n, seed, b_set_err, key, &vec![]);
	}


	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let zp_proto = ZkKZGV2{key: key};
		return zp_proto;
	}
}


impl <E:PairingEngine> ZkKZGV2 <E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
<<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// if vec_g5s is empty, create its own
	pub fn rand_inst_adv(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>, vec_g5s: &Vec<E::G1Affine>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkKZGV2::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let mut rng = gen_rng_from_seed(seed);
		let zk = ZkKZGV2::<E>::new(key); 		
		let r_p = E::Fr::rand(&mut rng);
		let r = E::Fr::rand(&mut rng);
		let s1 = E::Fr::rand(&mut rng);
		let sn = E::Fr::rand(&mut rng);
		let r4 = E::Fr::rand(&mut rng);
		let r5 = E::Fr::rand(&mut rng);
		let mut g1 = self.key.powers_g_beta[1];
		let mut g2 = self.key.powers_g_beta[2];
		let mut g3 = self.key.powers_g_beta[3];
		let mut g4 = self.key.powers_g_beta[4];
		let mut g5 = self.key.powers_g_beta[5];
		if vec_g5s.len()>0{
			g1 = vec_g5s[0];
			g2 = vec_g5s[1];
			g3 = vec_g5s[2];
			g4 = vec_g5s[3];
			g5 = vec_g5s[4];
		}
		
		let p = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp = DisPoly::<E::Fr>::from_serial(0, &p, &p.degree()+1);
		dp.to_partitions();


		//2. generate the input and then claim and proof
		let mut inp: ZkKZGV2Input<E> = ZkKZGV2Input{
			p: dp, r_p: r_p, r: r, s1: s1, sn: sn, r4: r4, r5: r5,
			g1: g1, g2: g2, g3: g3, g4: g4, g5: g5
		};	
		let prf = zk.prove(&mut inp);
		let mut claim = zk.claim(&mut inp);
		if b_set_err { //introduce an error for unit testing
			let kclaim:&ZkKZGV2Claim::<E> = claim.as_any().
				downcast_ref::<ZkKZGV2Claim<E>>().unwrap();
			let new_c_p = kclaim.c_p + E::G1Affine::rand(&mut rng);
			let bad_claim: ZkKZGV2Claim<E> = ZkKZGV2Claim{
				c_p: new_c_p,
				c_z: kclaim.c_z.clone(),
				r: kclaim.r.clone(),
				g1: g1, g2: g2, g3: g3, g4: g4, g5: g5
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(zk), Box::new(inp), claim, prf);
	}
	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// prove that C_z in claim holds g1^q(r) g2^s1 g3^s2 g4^r4 g5^r5
	/// c_p: precomputed commitment to c_p (to avoid wasting efforts)
	/// s1, sn are the first and last state.
	/// p_v is the value of p(v), for verification purpose 
	pub fn prove_direct(&self, p: &mut DisPoly<E::Fr>, r_p: E::Fr, r: E::Fr, g1: E::G1Affine, g2: E::G1Affine, g3: E::G1Affine, g4: E::G1Affine, g5: E::G1Affine, s_1: E::Fr, s_n: E::Fr, r4: E::Fr, r5: E::Fr, c_p: E::G1Affine, p_v: E::Fr) 
	-> (ZkKZGV2Proof<E>,ZkKZGV2Claim<E>){
		let b_perf = false;
		let mut t1 = Timer::new();
		let mut t2 = Timer::new();
		let me = RUN_CONFIG.my_rank;
		t1.start();
		t2.start();

		//1. compute y and the witness polynomial q1(x)
		//produce q_1(X) in paper.
		let y = p.eval(&r);
		if me==0 {assert!(y==p_v, "y!=pv");}
		let y = p_v; //AS ALL NODES have the right value of p_v but NOT y.
		let py = get_poly::<E::Fr>(vec![y]);
		let mut dp_y = DisPoly::<E::Fr>::from_serial(0, &py, &py.degree()+1);
		let mut dp1 = DisPoly::<E::Fr>::sub(p, &mut dp_y);
		dp1.to_partitions();	
		let zero = E::Fr::zero();
		let neg_r = zero - r;
		let p2= get_poly::<E::Fr>(vec![neg_r, E::Fr::from(1u64)]); 
		let mut dp2 = DisPoly::<E::Fr>::from_serial(0, &p2, &p2.degree()+1);
		dp2.to_partitions();
		let (mut q1, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(&mut dp1, &mut dp2);	
		let bzero = dr.is_zero();
		if me==0{assert!(bzero, "KZG::prove() ERR: remainder dr != 0!");}
		if b_perf {log_perf(LOG1, &format!("----- -- Zkg Step1: compute q1(x): {}", q1.dvec.len), &mut t1);}

		//2. compute cy, c1, c2
		let g = self.key.g.into_affine();
		let h = self.key.h;
		let gh = self.key.gh; // the [s1s2]_1 in paper
		let gt = gh + h.mul(zero-r).into_affine(); //the [s2(s1-t)]_1 in paper
		let mut rng = gen_rng();
		let r_y = E::Fr::rand(&mut rng);
		let r_q = E::Fr::rand(&mut rng);
		let cy = (g.mul(y) + h.mul(r_y)).into_affine();
		q1.to_partitions();
		let c1 = self.key.gen_kzg(&mut q1)[0] + h.mul(r_q).into_affine(); 
		let c2 = (gt.mul(r_q) + h.mul(r_y-r_p)).into_affine();

		let cz = (g4.mul(y) + g1.mul(s_1) + g2.mul(s_n) + g3.mul(r4) + g5.mul(r5)).into_affine();
		if b_perf {log_perf(LOG1, &format!("----- -- Zkg Step2: compute c1,cy,cz"), &mut t1);}

		//3. produce the dlog proof for cy, c2, cz but not c1.
		//note use same rs[0] for for m1_c1 and m1_c3
		let rs = rand_arr_field_ele(8, 234098234u128);
		let m1_cy = msm::<E>(&vec![g,h], &vec![rs[0], rs[1]]);
		let m1_c2 = msm::<E>(&vec![gt,h], &vec![rs[2], rs[3]]);
		let m1_cz = msm::<E>(&vec![g4,g1,g2,g3,g5], &vec![rs[0], rs[4], rs[5], rs[6], rs[7]]); 
		let c = hash::<E::Fr>(&to_vecu8(&vec![m1_cy, m1_c2, m1_cz]));
		let x_y = dlog_msg3::<E>(&vec![y,r_y], &vec![rs[0],rs[1]], c);
		let x_2 = dlog_msg3::<E>(&vec![r_q,r_y-r_p], &vec![rs[2],rs[3]], c);
		let x_z = dlog_msg3::<E>(&vec![y,s_1,s_n,r4,r5], &vec![rs[0],rs[4],rs[5],rs[6],rs[7]], c);

		let aux = ZkKZGV2Aux::<E>{
			y: y, ry: r_y, rq: r_q, ry_rp: r_y-r_p, 
			s1: s_1, sn: s_n, r4: r4, r5: r5
		};

		let kprf = ZkKZGV2Proof::<E>{
			c1: c1,
			c2: c2,
			cy: cy,
			prf_y_r: m1_cy,
			prf_y: x_y,
			prf_2_r: m1_c2,
			prf_2: x_2,
			prf_z_r: m1_cz,
			prf_z: x_z,
			c: c,
			aux: aux
		};
		if b_perf {log_perf(LOG1, &format!("----- -- Zkg Step3: compute DLOG proofs"), &mut t1);}


		let kclaim = ZkKZGV2Claim::<E>{
			c_p: c_p, 
			c_z: cz,
			r: r,
			g1: g1,
			g2: g2,
			g3: g3,
			g4: g4,
			g5: g5,
		};
		return (kprf, kclaim);
	}

	/// aggregate prove
	pub fn agg_prove(claims: &Vec<ZkKZGV2Claim<E>>, prfs: &Vec<ZkKZGV2Proof<E>>, gipa: &GIPA<E>, key: &Rc<DisKey<E>>) -> (ZkKZGV2AggClaim<E>,ZkKZGV2AggProof<E>)
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		//0. check data
		let n = claims.len();
		assert!(n.is_power_of_two(), "n: {} is not power of 2!", n);

		//1. generate new rands and v_msg1_y, v_msg_2, v_msg_z
		let h = key.h;
		let g = key.g.into_affine();
		//let g1_zero = g.mul(E::Fr::zero());
		let alpha_g2 = key.g_alpha_g2; 
		let g_g2 = key.g_g2;
		let gh = key.gh; // the [s1s2]_1 in paper
		let mut seed = 234234234234u128;
		let zero = E::Fr::zero();
		//let mut rng = gen_rng();

		let mut v_msg1_y = vec![]; //for DLOG: c_y
		let mut v_msg1_2 = vec![]; //for DLOG: c_2
		let mut v_msg1_z = vec![]; //for DLOG: c_z
		let mut v_rs_y = vec![]; 
		let mut v_rs_2 = vec![]; 
		let mut v_rs_z = vec![]; 
		let mut vbase_y = vec![];
		let mut vbase_2 = vec![];
		let mut vbase_z = vec![];

		for i in 0..n{
			seed += 1;
			let rs = rand_arr_field_ele(8, seed); 

			//1. for Cy = [y + ry(s2)]_1
			let v_base = vec![g, h];  
			let v_r = vec![rs[0], rs[1]];
			let msg1_y = msm::<E>(&v_base, &v_r);
			v_rs_y.push(v_r);
			v_msg1_y.push(msg1_y);
			vbase_y.push(v_base.clone());

			//2. for C2
			//the [s2(s1-t)]_1 in paper
			let t = claims[i].r;
			let v_r = vec![rs[2], rs[3]];
			let gt = gh + h.mul(zero-t).into_affine(); 
			let v_base  = vec![gt, h];
			let msg1_2 = msm::<E>(&v_base, &v_r);
			v_rs_2.push(v_r);
			v_msg1_2.push(msg1_2);
			vbase_2.push(v_base.clone());


			//2. for Cz 
			let v_r = vec![rs[0], rs[4], rs[5], rs[6], rs[7]];
			let v_base = vec![claims[i].g4, claims[i].g1, claims[i].g2, claims[i].g3, claims[i].g5];
			let msg1_z = msm::<E>(&v_base, &v_r);
			v_rs_z.push(v_r);
			v_msg1_z.push(msg1_z);
			vbase_z.push(v_base.clone());
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZG agg_prove Step1: Regen msg_r"), &mut t1);}

		//2. compute C_r and Fiat-Shamir c
		let c_msg1_y = gipa.cm1(&vec_affine_to_proj::<E>(&v_msg1_y));	
		let c_msg1_2 = gipa.cm1(&vec_affine_to_proj::<E>(&v_msg1_2));	
		let c_msg1_z = gipa.cm1(&vec_affine_to_proj::<E>(&v_msg1_z));	
		let c = hash::<E::Fr>(&to_vecu8(&vec![c_msg1_y, c_msg1_2, c_msg1_z]));
		let mut vec_s_y = vec![vec![], vec![]];
		let mut vec_s_2 = vec![vec![], vec![]];
		let mut vec_s_z = vec![vec![], vec![], vec![], vec![], vec![]];
		for i in 0..n{
			let x_y = vec![prfs[i].aux.y, prfs[i].aux.ry];
			for j in 0..2{vec_s_y[j].push(c * x_y[j] + v_rs_y[i][j]);}

			let x_2 = vec![prfs[i].aux.rq, prfs[i].aux.ry_rp];
			for j in 0..2{vec_s_2[j].push(c * x_2[j] + v_rs_2[i][j]);}

			let x_z = vec![prfs[i].aux.y, prfs[i].aux.s1, prfs[i].aux.sn,
				prfs[i].aux.r4, prfs[i].aux.r5];
			for j in 0..5{vec_s_z[j].push(c * x_z[j] + v_rs_z[i][j]);}
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZG agg_prove Step2: Recompute DLOG Prf"), &mut t1);}

		//3. generate data set 
		let z1 = vec![E::Fr::one(); n];
		let mut vec_neg_r =  vec![];
		for i in 0..prfs.len(){
			vec_neg_r.push(zero - claims[i].r);
		}
		//3.1 v_z: 17 elements
		let v_z = vec![
			//0
			vec_s_y[0].clone(), vec_s_y[1].clone(),
			//2
			vec_s_2[0].clone(), vec_s_2[1].clone(),
			//4
			vec_s_z[0].clone(), vec_s_z[1].clone(), vec_s_z[2].clone(),
			//7
			vec_s_z[3].clone(), vec_s_z[4].clone(), 
			//9
			z1.clone(), z1.clone(), z1.clone(), z1.clone(),
			//13
			z1.clone(), z1.clone(), z1.clone(), z1.clone(),
			//17
			z1.clone(), vec_neg_r.clone(), z1.clone(), vec_neg_r.clone(),
			//21
			z1.clone(),
		];

		//3.2 v_g1m
		let v_s2 = vec![h; n];
		let v_1 = vec![g; n];
		let mut v_gt = vec![];
		for i in 0..n {v_gt.push(vbase_2[i][0].clone());}

		let mut v_g4= vec![];
		for i in 0..n {v_g4.push(vbase_z[i][0].clone());}
		let mut v_g1= vec![];
		for i in 0..n {v_g1.push(vbase_z[i][1].clone());}
		let mut v_g2= vec![];
		for i in 0..n {v_g2.push(vbase_z[i][2].clone());}
		let mut v_g3= vec![];
		for i in 0..n {v_g3.push(vbase_z[i][3].clone());}
		let mut v_g5= vec![];
		for i in 0..n {v_g5.push(vbase_z[i][4].clone());}
		let mut v_cp= vec![];
		for i in 0..n {v_cp.push(claims[i].c_p.clone());}
		let mut v_cy= vec![];
		for i in 0..n {v_cy.push(prfs[i].cy.clone());}
		let mut v_c2= vec![];
		for i in 0..n {v_c2.push(prfs[i].c2.clone());}
		let mut v_c1= vec![];
		for i in 0..n {v_c1.push(prfs[i].c1.clone());}
		let mut v_cz= vec![];
		for i in 0..n {v_cz.push(claims[i].c_z.clone());}
		let mut v_gh = vec![];
		for _i in 0..n {v_gh.push(key.gh.clone());}
		let mut v_alpha_g = vec![];
		for _i in 0..n {v_alpha_g.push(key.g_alpha.clone());}

		let v_g1m = vec![
			v_1.clone(), v_s2.clone(), v_gt.clone(), v_s2.clone(),
			//4
			v_g4, v_g1, v_g2, v_g3, v_g5,
			//9
			v_cp, v_cy, v_c2, v_c1.clone(), v_cz,
			//14
			v_msg1_y, v_msg1_2, v_msg1_z,
			//17
			v_gh, v_s2.clone(), v_alpha_g, v_1.clone(),
			//21
			v_gt.clone(),
		];	
		assert!(v_z.len()==v_g1m.len(), "v_z.len()!=v_g1m.len()");
		//3.3 G1t
		let v_g1t = vec![v_c1.clone(), v_1.clone()]; 

		//3.4 G2
		let mut v_s_t = vec![];
		for i in 0..n {
			let neg_t = zero - claims[i].r;
			let g2_r = alpha_g2 + g_g2.mul(neg_t).into_affine();
			v_s_t.push(g2_r);
		}
		let v_g2 = vec![v_s_t.clone(), v_s_t.clone()];
		if b_perf {log_perf(LOG1, 
			&format!("-- KZG agg_prove Step3: Setup DataArr"), &mut t1);}


		let v_g1m_proj = v2d_affine_to_proj::<E>(&v_g1m);
		let v_g1t_proj = v2d_affine_to_proj::<E>(&v_g1t);
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
		for i in 0..v_g1t.len(){
			v_cg1t.push(gipa.cm1(&v_g1t_proj[i]));
			v_cg2.push(gipa.cm2(&v_g2_proj[i]));
		}
		let mut b1 = vec![];
		for i in 0..v_z.len(){
			E::G1Projective::serialize(&v_cz[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&v_cg1m[i], &mut b1).unwrap();
		}
		for i in 0..v_cg1t.len(){
			ExtensionFieldElement::<E>::serialize(&v_cg1t[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&v_cg2[i], &mut b1).unwrap();
		}
		let r = hash::<E::Fr>(&b1);
		if b_perf {log_perf(LOG1, 
			&format!("-- KZG agg_prove Step4: Build Commitments"), &mut t1);}

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
		for i in 0..v_g1t_proj.len(){
			let (prf, z) = gipa.tipp_prove(&v_g1t_proj[i], &v_g2_proj[i], &r);
			v_zt.push(z);
			v_prft.push(prf);	
		}
		if b_perf {log_perf(LOG1, &format!("-- KZG agg_prove Step5: MIPP & TIPP proofs. Size: {}", n), &mut t1);}

		//6. assemble and return prf
		let c_neg_r = gipa.cmz(&vec_neg_r);
		let aclaim = ZkKZGV2AggClaim::<E>{
			size: n,
			c_cp: v_cg1m[9].clone(),
			c_cz: v_cg1m[13].clone(),
			c_neg_r: c_neg_r,
		};
		let aprf = ZkKZGV2AggProof::<E>{
			size: n,
			c: c,
			r: r,
			v_cz: v_cz, v_cg1m: v_cg1m, v_cg1t: v_cg1t, v_cg2: v_cg2,
			v_zm: v_zm, v_prfm: v_prfm, v_zt: v_zt, v_prft: v_prft	
		};
		return (aclaim, aprf);
	}

	/// aggregate verify
	pub fn agg_verify(agg_claim: &ZkKZGV2AggClaim<E>, 
		agg_prf: &ZkKZGV2AggProof<E>, gipa: &GIPA<E>, key: &Rc<DisKey<E>>)
	->bool{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		//0. C0: check data consistency between claim and proofs
		let vids = vec![18,20];
		for i in vids{
			if agg_prf.v_cz[i]!=agg_claim.c_neg_r{
				log(LOG1, &format!(
					"WARN: v_cz[{}] != claim.c_neg_r (vec(neg_r))", i));
				return false;
			}
		}
	
		if agg_prf.v_cg1m[9] != agg_claim.c_cp{
			log(LOG1, &tos("claim.c_cp does not match prf.v_cg1m[9]"));
			return false;
		}	
		if agg_prf.v_cg1m[13] != agg_claim.c_cz{
			log(LOG1, &tos("claim.c_cz does not match prf.v_cg1m[13]"));
			return false;
		}	
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C0)"), &mut t1);}

		//1. C1:  check data consistency
		//let n = agg_prf.size;
		let vids = vec![9,10,11,12,13,14,15,16,17,19,21];
		for i in vids{
			if agg_prf.v_cz[i]!=gipa.c_z1{
				log(LOG1, &format!("WARN: v_cz[{}] != gipa.c_z1 (vec(1))", i));
				return false;
			}
		}

		let vids = vec![0, 20];
		for i in vids{
			if agg_prf.v_cg1m[i] !=gipa.c_vg{
				log(LOG1, &format!("WARN: Cq: v_cg1m[{}] !=gipa.c_vg",i));
				return false;
			}
		}

		let vids = vec![1,3,18];
		for i in vids{
			if agg_prf.v_cg1m[i] !=gipa.c_vh{
				log(LOG1, &format!("WARN: Cq: v_cg1m[{}] !=gipa.c_vh",i));
				return false;
			}
		}

		if agg_prf.v_cg1m[12] != agg_prf.v_cg1t[0] {
			log(LOG1, &format!("WARN: Cw: v_cg1m[12]!=v_cg1t[0] (c1)"));
			return false;
		}
		if agg_prf.v_cg1m[0] != agg_prf.v_cg1t[1] {
			log(LOG1, &format!("WARN: Cw: v_cg1m[0]!=v_cg1t[1] (v_1)"));
			return false;
		}
		if agg_prf.v_cg1t[0] != agg_prf.v_cg1m[12]{
			log(LOG1, &format!("WARN: v_cg1m[12]!=v_cg1t[2] ([v_c1)"));
			return false;
		}
		if agg_prf.v_cg2[0] != agg_prf.v_cg2[1]{
			log(LOG1, &format!("WARN: v_cg2[0]!=v_cgg[1] ([(s1-t)]_2)"));
			return false;
		}


		if agg_prf.v_cg1m[21] != agg_prf.v_cg1m[2]{
			log(LOG1, &format!("WARN: v_cg1m[21]!=v_cg1m[2] ([s2(s1-t)]_1)"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C1)"), &mut t1);}

		//2. check (C2) in paper [constant vectors] - there are some
		//overlap with C1, will refactor later.
		//c2.1 CM(vec(1))
		if agg_prf.v_cz[9] != gipa.c_z1{
			log(LOG1, &tos("WARN: prf.c_z[9] != CM(vec(1)"));
			return false;
		}	
		//c2.2 CM(vec(s_2))
		if agg_prf.v_cg1m[1] != gipa.c_vh{
			log(LOG1, &tos("WARN: prf.v_cg1m[1] != CM([s_2]_1)"));
			return false;
		}
		//c2.3 CM(vec([1]))
		if agg_prf.v_cg1m[0] != gipa.c_vg{
			log(LOG1, &tos("WARN: prf.v_cg1m[0] != CM([1]_1)"));
			return false;
		}
		//c2.4 check g1, g2, g3, g4, g5 from Groth'16 (info from claim)
		let cg = vec![gipa.c_g4.clone(), gipa.c_g1.clone(), gipa.c_g2.clone(),
			gipa.c_g3.clone(), gipa.c_g5.clone()];
		for i in 0..5{
			if agg_prf.v_cg1m[i+4] != cg[i]{
				log(LOG1, &format!("v_cg1m[{}] != gipa_setup.c_g{}", i+4, i));
				return false;
			}
		}
		//c2.5 check [s2(s1-t)] - consistency between gh and gt
		let c_gt = agg_prf.v_zm[17].clone() + agg_prf.v_zm[18].clone();
		if c_gt!=agg_prf.v_zm[21]{
			log(LOG1, &format!("v_zm[21] != z_gt"));
			return false;
		}
		if agg_prf.v_cg1m[17] != gipa.c_vgh{
			log(LOG1, &format!("v_cg1m[17] != gipa.c_vgh"));
			return false;
		}
		if agg_prf.v_cg1m[19] != gipa.c_v_g_alpha{
			log(LOG1, &format!("v_cg1m[19] != gipa.c_v_g_alpha"));
			return false;
		}
		
		//c2.6 check [s1-t]: note cg1t[0] and cg1t[1] already checked earlier  
		//which are related to cg1m[12] and cg1m[0]
		let lhs_g1 = (agg_prf.v_zm[19] + agg_prf.v_zm[20]).into_affine();
		let lhs = ExtensionFieldElement(E::pairing(lhs_g1, key.g_g2));
		if lhs!= agg_prf.v_zt[1]{
			log(LOG1, &format!("WARN: failed check on [s1-t]_1"));
			return false;
		}
		
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C2)"), &mut t1);}

		// (C3) check MIPP and TIPP proofs
		for i in 0..agg_prf.v_zm.len(){
			if !gipa.mipp_verify(&agg_prf.v_cg1m[i], &agg_prf.v_cz[i],
				&agg_prf.r, &agg_prf.v_zm[i], &agg_prf.v_prfm[i]){
				log(LOG1, &format!("WARN: fails mipp prf {}", i));
				return false;
			}
		}
		for i in 0..agg_prf.v_zt.len(){
			if !gipa.tipp_verify(&agg_prf.v_cg1t[i], &agg_prf.v_cg2[i],
				&agg_prf.r, &agg_prf.v_zt[i], &agg_prf.v_prft[i]){
				log(LOG1, &format!("WARN: fails tipp prf {}", i));
				return false;
			}
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C3)"), &mut t1);}

		// (C4) check knowledge proofs
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C4) - no knowledge prfs checks. "), &mut t1);}

		// (C5) check  (Cp - Cy + C2) [1]_2 = C1 [s-t]_2
		let g_g2 = key.g_g2;
		let items = agg_prf.v_zm[9] - agg_prf.v_zm[10] + agg_prf.v_zm[11];
		let lhs = E::pairing(items, g_g2);
		let rhs = agg_prf.v_zt[0].clone();
		if ExtensionFieldElement(lhs)!=rhs{
			log(LOG1, &format!("WARN: fails (Cp - Cy + C2) [1]_2 = C1 [s-t]_2
"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C5)"), &mut t1);}

		// check C(6) DLOG proofs
		//C6.1 Cy
		let lhs = agg_prf.v_zm[14] + 
			agg_prf.v_zm[10].into_affine().mul(agg_prf.c);
		let rhs = agg_prf.v_zm[0] + agg_prf.v_zm[1];
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails DLOG check for Cy"));
			return false;
		}
		//C6.1 C2
		let lhs = agg_prf.v_zm[15] + 
			agg_prf.v_zm[11].into_affine().mul(agg_prf.c);
		let rhs = agg_prf.v_zm[2] + agg_prf.v_zm[3];
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails DLOG check for C2"));
			return false;
		}
		//C6.1 Cz
		let lhs = agg_prf.v_zm[16] + 
			agg_prf.v_zm[13].into_affine().mul(agg_prf.c);
		let rhs = agg_prf.v_zm[4] + agg_prf.v_zm[5] +
					agg_prf.v_zm[6] + agg_prf.v_zm[7] + agg_prf.v_zm[8];
		if lhs!=rhs{
			log(LOG1, &tos("WARN: fails DLOG check for Cz"));
			return false;
		}
		if b_perf {log_perf(LOG1, 
			&format!("-- KZGPrf agg_ver check (C6)"), &mut t1);}


		// check C(7)
		// C7.1 -c
		let (c_msg1_y, c_msg1_2, c_msg1_z) = (agg_prf.v_cg1m[14].clone(),
			agg_prf.v_cg1m[15].clone(), agg_prf.v_cg1m[16].clone());
		let exp_c = hash::<E::Fr>(&to_vecu8(&vec![c_msg1_y, c_msg1_2, c_msg1_z]));
		if exp_c != agg_prf.c{
			log(LOG1, &tos("WARN: fails check on agg_prf.c"));
			return false;
		}
		// C7.2 - r
		let mut b1 = vec![];
		for i in 0..agg_prf.v_cg1m.len(){
			E::G1Projective::serialize(&agg_prf.v_cz[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::
				serialize(&agg_prf.v_cg1m[i], &mut b1).unwrap();
		}
		for i in 0..agg_prf.v_cg1t.len(){
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
			&format!("-- KZGPrf agg_ver check (C7)"), &mut t1);}
		return true;
	}

}

impl <E:PairingEngine> ZkKZGV2Proof<E>
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
			aux: ZkKZGV2Aux::<E>::dummy()
		
		};
		return res; 
	}
*/

	pub fn get_aux(&self) -> ZkKZGV2Aux<E>{
		return self.aux.clone();
	}

	pub fn set_aux(&mut self, aux_inp: ZkKZGV2Aux<E>){
		self.aux = aux_inp;	
	}
}

impl <E:PairingEngine> ZkKZGV2Aux <E> 
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// serialization
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::Fr::serialize(&self.y, &mut b1).unwrap();
		E::Fr::serialize(&self.ry, &mut b1).unwrap();
		E::Fr::serialize(&self.rq, &mut b1).unwrap();
		E::Fr::serialize(&self.ry_rp, &mut b1).unwrap();
		E::Fr::serialize(&self.s1, &mut b1).unwrap();
		E::Fr::serialize(&self.sn, &mut b1).unwrap();
		E::Fr::serialize(&self.r4, &mut b1).unwrap();
		E::Fr::serialize(&self.r5, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let mut v1 = &v[..];
		let y= E::Fr::deserialize(&mut v1).unwrap();		
		let ry= E::Fr::deserialize(&mut v1).unwrap();		
		let rq= E::Fr::deserialize(&mut v1).unwrap();		
		let ry_rp= E::Fr::deserialize(&mut v1).unwrap();		
		let s1= E::Fr::deserialize(&mut v1).unwrap();		
		let sn= E::Fr::deserialize(&mut v1).unwrap();		
		let r4= E::Fr::deserialize(&mut v1).unwrap();		
		let r5= E::Fr::deserialize(&mut v1).unwrap();		

		let res = ZkKZGV2Aux{
			y: y, ry: ry, rq: rq, ry_rp: ry_rp,
			s1: s1, sn: sn, r4: r4, r5:r5
		};
		return res;
	}
	pub fn dummy() -> Self{
		let zero = E::Fr::zero();
		return Self{
			y: zero.clone(),
			ry: zero.clone(),
			rq: zero.clone(),
			ry_rp: zero.clone(),
			s1: zero.clone(),
			sn: zero.clone(),
			r4: zero.clone(),
			r5: zero.clone(),
		}
	}

	pub fn is_dummy(&self) -> bool{
		let v = vec![self.y, self.ry, self.rq, self.ry_rp,
			self.s1, self.sn, self.r4, self.r5];
		for x in v {
			if !x.is_zero() {return false;}
		}
		return true;
	}
}

impl <E:PairingEngine> ZkKZGV2AggClaim<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&self.c_cp, &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&self.c_cz, &mut b1).unwrap();
		E::G1Projective::serialize(&self.c_neg_r, &mut b1).unwrap();
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let mut v1 = &v[..];
		let size= usize::deserialize(&mut v1).unwrap();		
		let c_cp = ExtensionFieldElement::<E>::deserialize(&mut v1).unwrap();
		let c_cz = ExtensionFieldElement::<E>::deserialize(&mut v1).unwrap();
		let c_neg_r = E::G1Projective::deserialize(&mut v1).unwrap();
		let res = Self{size: size, c_cp: c_cp, c_cz: c_cz, c_neg_r: c_neg_r};
		return res;
	}
}

impl <E:PairingEngine> ZkKZGV2AggProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		E::Fr::serialize(&self.c, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		let vids = vec![0,1,2,3,4,5,6,7,8,18]; //10
		for i in vids{//0-8, and then 
			E::G1Projective::serialize(&self.v_cz[i], &mut b1).unwrap();
		}
		for i in 0..self.v_cg1m.len(){
			ExtensionFieldElement::<E>::
				serialize(&self.v_cg1m[i], &mut b1).unwrap();
		}

		// no need for v_cg1t (coz can take from v_cg1m[12] and [0]

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
		for _i in 0..9{
			v_cz.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		for _i in 0..9{ v_cz.push(ripp.c_z1); }
		let c_neg_r = E::G1Projective::deserialize(&mut b1).unwrap();
		v_cz.push(c_neg_r.clone());
		v_cz.push(ripp.c_z1.clone());
		v_cz.push(c_neg_r.clone());
		v_cz.push(ripp.c_z1.clone());
		assert!(v_cz.len()==22, "c_vz.len !=22");

		let mut v_cg1m = vec![];
		for _i in 0..22{
			v_cg1m.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		}
		let mut v_cg1t = vec![];
		v_cg1t.push(v_cg1m[12].clone());
		v_cg1t.push(v_cg1m[0].clone());
		let mut v_cg2 = vec![];
		v_cg2.push(ExtensionFieldElement::<E>::
				deserialize(&mut b1).unwrap());
		v_cg2.push(v_cg2[0].clone());

		let mut v_zm = vec![];
		for _i in 0..22{
			v_zm.push(E::G1Projective::deserialize(&mut b1).unwrap());
		}
		let mut v_prfm= vec![];
		for _i in 0..22{
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

