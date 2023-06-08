/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/27/2022
*/

/// This module defines the blindeval KZG protocol (see paper)
///
/// Claim: given C_p = g^{p(\alpha} h^\gamma, C_gamma = g^gamma h^r1
/// C_z = g^z h^r2, r and O. Claim that the prover knows the
/// secrets behind C_p, C_gamma and C_z and  O = z + p(r). We call
/// z the blinding factor as it hides the real value of p(r).
///
/// Proof Idea: Let w(x) = (p(x)-p(r))/(x-r).
/// prover samples r3 and builds:
/// 	W = g^w(alpha) h^r3 and C_r3 = g^r3 h^r4 
///     B = h^(alpha-r)^r3 h^gamma g^-z
/// Prover shows: (1) prfpoly(W, C_r3); (2) prf_same
///   of the exponents over W, C_r3, B, Cz.
/// Verifier verifies: e(C_p/(g^O*B), g) = e(W, g^alpha/g^r) 
///
/// Performance: 32k: 10 sec (prover), verification: 13 ms (8 nodes) can 
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
use proto::zk_poly::*;
use proto::zk_same::*;
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
pub struct ZkKZGInput<E:PairingEngine>{
	/// the polynomail to prove
	pub p: DisPoly<E::Fr>,	
	/// random nonce for C_p = g^{p(alpha)} h^gamma
	pub gamma: E::Fr,
	/// random nonce for C_gamma = g^gamma h^r1
	pub r1: E::Fr,
	/// the random nonce for z*p(r)
	pub r: E::Fr,
	/// the blinding factor 
	pub z: E::Fr,
	/// random nonce for C_z = g^z h^r2
	pub r2: E::Fr,
}

#[derive(Clone)]
pub struct ZkKZGProof<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// W = g^{w(alpha} h^r3
	pub w: E::G1Affine,
	/// C_r3 = g^r3 h^h4
	pub c_r3: E::G1Affine,
	/// B = h^{alpha - r}^r3 h^gamma g^-z
	pub b: E::G1Affine,
	/// Proof that B, C_r3, C_gamma, C_z have same matching exponents
	pub prf_same: ZkSameProof<E::G1Affine>,
	/// Proof that W and C_r3 is extended KZG 
	pub prf_poly: ZkPolyProof<E>,
}

#[derive(Clone)]
pub struct ZkKZGClaim<E: PairingEngine>{
	/// the extended KZG commitment of q(x), i.e., g^{q(\alpha)} h^gamma
	pub c_p: E::G1Affine,
	/// the Pedersen commitment of gammar, i.e., g^gamma h^{r1}
	pub c_gamma: E::G1Affine,
	/// the Pedersen commitment of blinding factor C_z = g^z h^r2
	pub c_z: E::G1Affine,
	/// the claimed random challenge
	pub r: E::Fr,
	/// the output: O = z * p(r)
	pub o: E::Fr,
}

#[derive(Clone)]
pub struct ZkKZG<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>
{
	/// Prover key 
	pub key: Rc<DisKey<E>>,
	/// z_g and z_h for generating comm_z
	pub z_g: E::G1Affine,
	/// z_h for generating comm_z
	pub z_h: E::G1Affine,
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <E:PairingEngine> ProverInput for ZkKZGInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <E:PairingEngine> ProtoObj for ZkKZGProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.w, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_r3, &mut b1).unwrap();
		E::G1Affine::serialize(&self.b, &mut b1).unwrap();
		let mut b2 = self.prf_same.to_bytes();
		let mut b3 = self.prf_poly.to_bytes();
		b1.append(&mut b2);
		b1.append(&mut b3);
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let start_pos= E::G1Affine::zero().serialized_size()*3;
		let mut v3 = &v[start_pos..].to_vec();
		let mut v2 = &v[..];
		let w = E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_r3 = E::G1Affine::deserialize(&mut v2).unwrap();		
		let b = E::G1Affine::deserialize(&mut v2).unwrap();		
		let prf_same = ZkSameProof::<E::G1Affine>::static_from_bytes(&mut v3);
		let start_pos2 = start_pos + prf_same.to_bytes().len();
		let mut v4 = &v[start_pos2..].to_vec();
		let prf_poly= ZkPolyProof::<E>::static_from_bytes(&mut v4);
		let res = ZkKZGProof::<E>{w: w, c_r3: c_r3, b: b, prf_same: *prf_same, prf_poly: *prf_poly};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkKZGPrf(w: {:?}, c_r3: {:?}, b: {:?}, ", 
			prefix, self.w, self.c_r3, self.b);
		self.prf_same.dump("prf_same: ");
		self.prf_same.dump("prf_poly: ");
		print!(") \n");
	} 
}

impl <E:PairingEngine> Proof for ZkKZGProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.w= res.w.clone();
		self.c_r3 = res.c_r3.clone();
		self.b= res.b.clone();
		self.prf_same = res.prf_same.clone();
		self.prf_poly= res.prf_poly.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkKZGProof::<E> = other.as_any().
			downcast_ref::<ZkKZGProof<E>>().unwrap();
		return self.w == obj.w && self.c_r3==obj.c_r3 && self.b==obj.b 
			&& self.prf_same.equals(&obj.prf_same) 
			&& self.prf_poly.equals(&obj.prf_poly); 
	}
}

impl <E:PairingEngine> ProtoObj for ZkKZGClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.c_p, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_gamma, &mut b1).unwrap();
		E::G1Affine::serialize(&self.c_z, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		E::Fr::serialize(&self.o, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let c_p= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_gamma= E::G1Affine::deserialize(&mut v2).unwrap();		
		let c_z= E::G1Affine::deserialize(&mut v2).unwrap();		
		let r= E::Fr::deserialize(&mut v2).unwrap();		
		let o= E::Fr::deserialize(&mut v2).unwrap();		
		let res = ZkKZGClaim::<E>{c_p: c_p, c_gamma: c_gamma, c_z: c_z, 
				r:r, o: o};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkKZGClaim: c_p: {:?}, c_gamma: {:?}, c_z: {:?}, r: {:?}, o: {:?})", prefix, self.c_p, self.c_gamma, self.c_z, self.r, self.o);
	} 
}

impl <E:PairingEngine> Claim for ZkKZGClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.c_p= res.c_p;
		self.c_gamma= res.c_gamma;
		self.c_z= res.c_z;
		self.r= res.r;
		self.o= res.o;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkKZGClaim::<E> = obj.as_any().
			downcast_ref::<ZkKZGClaim<E>>().unwrap();
		return self.c_p==other.c_p && self.c_gamma==other.c_gamma	
			&& self.c_z==other.c_z && self.r==other.r && self.o==other.o;
	}
}

impl <E:PairingEngine> Protocol<E> for ZkKZG <E>  where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkKZG";
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkKZGInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkKZGInput<E>>().unwrap();
		let c_p = self.key.gen_kzg(&mut kinp.p)[0] + 
			self.key.h.mul(kinp.gamma).into_affine();
		let c_gamma = self.key.g.into_affine().mul(kinp.gamma) 
			+ self.key.h.mul(kinp.r1);
		let c_z= self.z_g.mul(kinp.z) 
			+ self.z_h.mul(kinp.r2);
		let o = kinp.z + kinp.p.eval(&kinp.r); 
		let claim = ZkKZGClaim::<E>{c_p: c_p, c_gamma: c_gamma.into_affine(), 
			c_z: c_z.into_affine(), o: o, r: kinp.r};
		return Box::new(claim);
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	/// However, it needs cooperation of all processors!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//0. downcast input
		let kinp:&mut ZkKZGInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkKZGInput<E>>().unwrap();

		//1. compute the c_r3
		let mut t1 =  Timer::new();
		t1.start();
		let mut dp = kinp.p.clone();
		t1.stop();
		let val = kinp.p.eval(&kinp.r);
		let pval = get_poly::<E::Fr>(vec![val]);
		let mut dpval = DisPoly::<E::Fr>::from_serial(0, &pval, &pval.degree()+1);
		let mut dp1 = DisPoly::<E::Fr>::sub(&mut dp, &mut dpval);
		dp1.to_partitions();

		let mut rng = gen_rng();
		let r3 = E::Fr::rand(&mut rng);
		let r4 = E::Fr::rand(&mut rng);
		let c_r3 = self.key.g.into_affine().mul(r3) + self.key.h.mul(r4);

		//2. compute b
		let zero = E::Fr::zero();
		let neg_z = zero - kinp.z;
		let neg_r = zero - kinp.r;
		let neg_r2 = zero - kinp.r2;
		let neg_r3 = zero - r3;
		let neg_r4 = zero - r4;
		let h_negr = self.key.h.mul(neg_r);
		let h_alpha_r = self.key.h_alpha + h_negr.into_affine();
		let b = h_alpha_r.mul(neg_r3) 
				+ self.key.h.mul(kinp.gamma)
				+ self.key.g.into_affine().mul(neg_z);

		//3. compute the W
		//p2 = (x-r)
		let p2= get_poly::<E::Fr>(vec![neg_r, E::Fr::from(1u64)]); 
		let mut dp2 = DisPoly::<E::Fr>::from_serial(0, &p2, &p2.degree()+1);
		dp2.to_partitions();
		let (mut dq, dr) = DisPoly::<E::Fr>::divide_with_q_and_r(&mut dp1, &mut dp2);	
		let bzero = dr.is_zero();
		if RUN_CONFIG.my_rank==0{//only check at main processor 0
			assert!(bzero, "KZG::prove() ERR: remainder of step1 != 0!");
		}
		dq.to_partitions();
		let w1= self.key.gen_kzg(&mut dq)[0]; //g^{w(alpha)}
		let w= w1 + self.key.h.mul(r3).into_affine();
		

		//3. construct the prf_same
		let exps = vec![
			vec![neg_r3, kinp.gamma, neg_z], //B
			vec![neg_r3, neg_r4], // 1/C_r3
			vec![kinp.gamma, kinp.r1 ], //C_gamma
			vec![neg_z, neg_r2], // 1/C_z
		];
		let mut zksame_input = ZkSameInput::<E::G1Affine>{ exps: exps };
		let g_affine = self.key.g.into_affine();
		let bases = vec![
			vec![h_alpha_r, self.key.h, self.key.g.into_affine()], //B
			vec![g_affine, self.key.h], // 1/C_r3
			vec![g_affine, self.key.h], // C_gamma
			vec![self.z_g, self.z_h], //  1/C_z
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let zksame_prf = zksame.prove(&mut zksame_input).as_any().
			downcast_ref::<ZkSameProof<E::G1Affine>>().unwrap().clone(); 

		//4. construct prf_poly for W and C_r3
		let mut poly_inp = ZkPolyInput::<E>{q: dq, r: r3, r2: r4};
		let zk_poly = ZkPoly::new(self.key.clone());
		let prf_poly = zk_poly.prove(&mut poly_inp).as_any().
			downcast_ref::<ZkPolyProof<E>>().unwrap().clone();

		//3. return proof
		let kprf = ZkKZGProof::<E>{
			w: w,
			c_r3: c_r3.into_affine(), 
			b: b.into_affine(),
			prf_same: zksame_prf,
			prf_poly: prf_poly
		};
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
		let p_claim:&ZkKZGClaim::<E> = claim.as_any().
			downcast_ref::<ZkKZGClaim<E>>().unwrap();
		let p_proof:&ZkKZGProof::<E> = proof.as_any().
			downcast_ref::<ZkKZGProof<E>>().unwrap();
		let g_affine = self.key.g.into_affine();
		let zero = E::Fr::zero();
		let neg_r = zero - p_claim.r;
		let h_negr = self.key.h.mul(neg_r);
		let h_alpha_r = self.key.h_alpha + h_negr.into_affine();
		let bases = vec![
			vec![h_alpha_r, self.key.h, self.key.g.into_affine()], //B
			vec![g_affine, self.key.h], //C_r3
			vec![g_affine, self.key.h], //C_gamma
			vec![self.z_g, self.z_h], //C_z
		];
		let zksame = ZkSame::new_with_bases(bases, self.key.clone());
		let zk_poly = ZkPoly::new(self.key.clone());
		t.stop();
		//if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 901: set up time: {}us", t.time_us);}

		//2. check equation of pairing e(Cp/g^O, g) = e(w, g^alpha/g^r)e(B,g) 
		//WHICH is equiv to: e(Cp/(g^O B), g) = e(w, g^alpha/g^r)
		if RUN_CONFIG.my_rank!=0 {return true;} //only check on main node
		let mut t = Timer::new();
		t.start();
		let mut t1 = Timer::new();
		t1.start();
		let g_exp_o = g_affine.mul(p_claim.o);
		let sum1 = g_exp_o + p_proof.b.into_projective();
		let cp_go = p_claim.c_p.into_projective() - sum1;
		let g2_alpha_r = self.key.g_alpha_g2.into_projective() - &self.key.g_g2.mul(p_claim.r);
		t1.stop();
		//if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 901.5: mul time: {}us", t1.time_us);}
		let lhs = E::pairing(cp_go, self.key.g_g2);
		let rhs = E::pairing(p_proof.w, g2_alpha_r);
		if lhs!=rhs {
			return false;
		}
		t.stop();
		//if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 902: pairing time: {}us", t.time_us);}

		//3. check the prf_same instance 
		let mut t = Timer::new();
		t.start();
		let zero = E::G1Affine::zero().into_projective();
		let inv_c_r3 = (zero - p_proof.c_r3.into_projective()).into_affine(); 
		let inv_c_z = (zero - p_claim.c_z.into_projective()).into_affine();
		let y = vec![p_proof.b, inv_c_r3, p_claim.c_gamma, inv_c_z];
		let zksame_claim = ZkSameClaim::<E::G1Affine>{y: y}; 
		let bres = zksame.verify(&zksame_claim, &p_proof.prf_same); 
		if !bres{
			return false;
		}
		t.stop();
		//if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 903: zksame time: {}us", t.time_us);}

		//4. check the prf_poly instance
		let mut t = Timer::new();
		t.start();
		let poly_claim= ZkPolyClaim::<E>{ c_q: p_proof.w, c_r: p_proof.c_r3 };
		let bres = zk_poly.verify(&poly_claim, &p_proof.prf_poly);
		if !bres{
			return false;
		}
		t.stop();
		//if RUN_CONFIG.my_rank==0 {println!("DEBUG USE 904: zkpoly time: {}us", t.time_us);}
	

		return true; //passed
	}

	/// generate a random instance. n is the degree of polynomial
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		let np = RUN_CONFIG.n_proc;
		if n<np {panic!("rand_inst input n < n_proc");}
		if n>key.n-16 {panic!("ZkKZG::rand_inst ERR: make n < key.n-16!");}
		
		//1. generate the random polynomial	
		let mut rng = gen_rng_from_seed(seed);
		let zk = ZkKZG::<E>::new(key); 		
		let gamma = E::Fr::rand(&mut rng);
		let r = E::Fr::rand(&mut rng);
		let z = E::Fr::rand(&mut rng);
		let r1 = E::Fr::rand(&mut rng);
		let r2 = E::Fr::rand(&mut rng);
		let p = DensePolynomial::<E::Fr>::rand(n, &mut rng);
		let mut dp = DisPoly::<E::Fr>::from_serial(0, &p, &p.degree()+1);
		dp.to_partitions();

		//2. generate the input and then claim and proof
		let mut inp: ZkKZGInput<E> = ZkKZGInput{p: dp, gamma: gamma, r1: r1, 
			r: r, z:z, r2: r2};
		let prf = zk.prove(&mut inp);
		let mut claim = zk.claim(&mut inp);
		if b_set_err { //introduce an error for unit testing
			let kclaim:&ZkKZGClaim::<E> = claim.as_any().
				downcast_ref::<ZkKZGClaim<E>>().unwrap();
			let new_c_p = kclaim.c_p + E::G1Affine::rand(&mut rng);
			let bad_claim: ZkKZGClaim<E> = ZkKZGClaim{
				c_p: new_c_p,
				c_gamma: kclaim.c_gamma.clone(),
				c_z: kclaim.c_z.clone(),
				o: kclaim.o.clone(),
				r: kclaim.r.clone(),
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(zk), Box::new(inp), claim, prf);
	}

	/// factory method. 
	fn new(key: Rc<DisKey<E>>) -> Self{
		let z_g = key.g.into_affine();
		let z_h = key.h.clone();
		let zp_proto = ZkKZG{key: key, z_g: z_g, z_h: z_h};
		return zp_proto;
	}
}

impl <E:PairingEngine> ZkKZG <E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>{
	pub fn new_with_generators(key: Rc<DisKey<E>>, z_g: E::G1Affine,
		z_h: E::G1Affine) -> Self{
		let zp_proto = ZkKZG{key: key, z_g: z_g, z_h: z_h};
		return zp_proto;
	}
}

