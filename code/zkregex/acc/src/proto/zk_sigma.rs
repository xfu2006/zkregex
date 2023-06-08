/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 08/05/2022
	Completed: 08/07/2022
*/
/// This module defines the zk-Sigma protocol. This protocol provides the full
/// zero knowledge, when convincing the verifier that
/// the ``set support" (standard set of a multi-set) of the union
/// of transitions and sets is a SUBSET of the AC-DFA union of sets and trans.
/// Also it generates the expected output given a random challenge, so that
/// it can be linked to arithmetic circuit (see paper about 2-stage
/// revised Groth'16 scheme).
///
/// The basic idea is to combine the zk_subset and zk_kzg proof.  This is
/// the zk-version of the nonzk-Sigma protocol. Note that we only need
/// to argue about the set support of union of states and transitions.
/// For the proof for final state belongs to a final state set,
/// it is handled directly in the arithmetic circuit using range proof.
///
/// Performance: 32k: prover 16 sec, verifier 40ms (8 nodes 1 computer 20ms
/// 1 node 1 computer for verification). 1M: 534 sec prover time. 


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
use proto::zk_subset::*;
use proto::zk_kzg::*;
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
pub struct ZkSigmaInput<E:PairingEngine>{
	/// the superset polynomail 
	pub p_superset: DisPoly<E::Fr>,	
	/// the subset polynomail 
	pub p_subset: DisPoly<E::Fr>,	
	/// the r for evaluating p_subset
	pub r: E::Fr,
	/// the blinding factor z, so that it generates output: p_subset(r) + z
	pub z: E::Fr,
	/// the randon nonce for comm_z = g_z ^ z h_z ^r2
	/// here g_z and h_z are two given generators from the fixed I/O
	/// scheme of Groth'16 keys.
	pub r2: E::Fr,
}

#[derive(Clone)]
pub struct ZkSigmaProof<E: PairingEngine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// the proof to shta that p_subset is a factor of p_superset
	pub prf_subset: ZkSubsetProof<E>,
	/// proof that p_subset evaluates to p(r) + z
	pub prf_kzg: ZkKZGProof<E>,
	/// g^{p_subset(alpha)} h^gamma at G2
	/// (kzg_subset_g2, comm_gamma_g2) extended KZG of p_subset
	pub kzg_subset_g2: E::G2Affine, 
	/// comm_gamma = g^gamma h^r1
	pub comm_gamma_g2: E::G2Affine,
	/// same kzg_subset over g1 (zk_kzg better takes the G1 version, which is cheaper in verifying its zk_same)
	pub kzg_subset_g1: E::G1Affine, 
	/// same comm_gamma_g1 over g1
	pub comm_gamma_g1: E::G1Affine
}

/// The prover claims to know a SECRET polynomial p_subset(x) s.t.
/// (1) p_subset is a subset of the p_superset behind kzg_superset
/// (2) given Pedersen commitment to some secret z, and given
/// a public challenge r. Output O = p_subset(r) + z
#[derive(Clone)]
pub struct ZkSigmaClaim<E: PairingEngine>{
	/// the kzg commitment of some superset(x)
	pub kzg_superset: E::G1Affine,
	/// the Pedersen commitment to z (from commited I/O scheme)
	pub comm_z: E::G1Affine, 
	/// the random verifier challenge r
	pub r: E::Fr,
	/// the value of p_subset(r)+z
	pub p_r_z: E::Fr,
	/// the generator needed for Pedersen commitment of comm_z 
	/// copied from ZkSigmaInput
	pub g_z: E::G1Affine,
	/// the 2nd generator needed for Pedersen commitment of comm_z
	pub h_z: E::G1Affine,
}

#[derive(Clone)]
pub struct ZkSigma<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// Prover key series: {g^{alpha^0}, ...., g^{alpha^n}} on both G1 and G2
	pub key: Rc<DisKey<E>>,
	/// the generator needed for Pedersen commitment of comm_z
	pub g_z: E::G1Affine,
	/// the 2nd generator needed for Pedersen commitment of comm_z
	pub h_z: E::G1Affine,
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 
impl <E:PairingEngine> ProverInput for ZkSigmaInput<E>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}


impl <E:PairingEngine> ProtoObj for ZkSigmaProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1 = self.prf_subset.to_bytes();
		let mut b2 = self.prf_kzg.to_bytes();
		let mut b3 = vec![];
		E::G2Affine::serialize(&self.kzg_subset_g2, &mut b3).unwrap();
		E::G2Affine::serialize(&self.comm_gamma_g2, &mut b3).unwrap();
		E::G1Affine::serialize(&self.kzg_subset_g1, &mut b3).unwrap();
		E::G1Affine::serialize(&self.comm_gamma_g1, &mut b3).unwrap();
		b1.append(&mut b2);
		b1.append(&mut b3);
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		// This approach is wasting on speed though. should have
		// used reader interface. refactor later.
		let prf_subset = ZkSubsetProof::<E>::static_from_bytes(v);
		let size1 = prf_subset.to_bytes().len();
		let v2 = v[size1..].to_vec();
		let prf_kzg = ZkKZGProof::<E>::static_from_bytes(&v2);
		let size2 = prf_kzg.to_bytes().len();
		let mut v3 = &v2[size2..];
		let kzg_subset_g2 = E::G2Affine::deserialize(&mut v3).unwrap();		
		let comm_gamma_g2= E::G2Affine::deserialize(&mut v3).unwrap();		
		let kzg_subset_g1 = E::G1Affine::deserialize(&mut v3).unwrap();		
		let comm_gamma_g1= E::G1Affine::deserialize(&mut v3).unwrap();		
		let res = ZkSigmaProof::<E>{
			prf_subset: *prf_subset,
			prf_kzg: *prf_kzg,
			kzg_subset_g2: kzg_subset_g2,
			comm_gamma_g2: comm_gamma_g2,
			kzg_subset_g1: kzg_subset_g1,
			comm_gamma_g1: comm_gamma_g1 
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		print!("{} ZkSigmaProof: (", prefix);
		self.prf_subset.dump("prf_subset: ");
		self.prf_kzg.dump("prf_kzg: ");
		println!("kzg_subset_g2: {} )", self.kzg_subset_g2);
		println!("comm_gamma_g2: {} )", self.comm_gamma_g2);
		println!("kzg_subset_g1: {} )", self.kzg_subset_g1);
		println!("comm_gamma_g1: {} )", self.comm_gamma_g1);
	} 
}

impl <E:PairingEngine> Proof for ZkSigmaProof<E> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.prf_subset = res.prf_subset.clone();
		self.prf_kzg= res.prf_kzg.clone();
		self.kzg_subset_g2= res.kzg_subset_g2.clone();
		self.comm_gamma_g2= res.comm_gamma_g2.clone();
		self.kzg_subset_g1= res.kzg_subset_g1.clone();
		self.comm_gamma_g1= res.comm_gamma_g1.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkSigmaProof::<E> = other.as_any().
			downcast_ref::<ZkSigmaProof<E>>().unwrap();
		return self.prf_subset.equals(&obj.prf_subset) &&
			self.prf_kzg.equals(&obj.prf_kzg) &&
			self.kzg_subset_g2 == obj.kzg_subset_g2 &&
			self.comm_gamma_g2== obj.comm_gamma_g2 &&
			self.kzg_subset_g1 == obj.kzg_subset_g1 &&
			self.comm_gamma_g1== obj.comm_gamma_g1;
	}
}

impl <E:PairingEngine> ProtoObj for ZkSigmaClaim<E> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		E::G1Affine::serialize(&self.kzg_superset, &mut b1).unwrap();
		E::G1Affine::serialize(&self.comm_z, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		E::Fr::serialize(&self.p_r_z, &mut b1).unwrap();
		E::G1Affine::serialize(&self.g_z, &mut b1).unwrap();
		E::G1Affine::serialize(&self.h_z, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut v2 = &v[..];
		let kzg_superset = E::G1Affine::deserialize(&mut v2).unwrap();		
		let comm_z= E::G1Affine::deserialize(&mut v2).unwrap();		
		let r = E::Fr::deserialize(&mut v2).unwrap();		
		let p_r_z = E::Fr::deserialize(&mut v2).unwrap();		
		let g_z= E::G1Affine::deserialize(&mut v2).unwrap();		
		let h_z= E::G1Affine::deserialize(&mut v2).unwrap();		
		let res = ZkSigmaClaim::<E>{
			kzg_superset: kzg_superset,
			comm_z: comm_z,
			r: r, 
			p_r_z: p_r_z,
			g_z: g_z,
			h_z: h_z
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (kzg_superset: {:?}, comm_z: {:?}, r: {:?}, p_r_z{:?}, g_h: {:?}, h_z: {:?})", 
			prefix, self.kzg_superset, self.comm_z, self.r, self.p_r_z,
			self.g_z, self.h_z);
	} 
}

impl <E:PairingEngine> Claim for ZkSigmaClaim<E> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.kzg_superset  = res.kzg_superset;
		self.comm_z = res.comm_z;
		self.r = res.r;
		self.p_r_z = res.p_r_z;
		self.g_z = res.g_z;
		self.h_z = res.h_z;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkSigmaClaim::<E> = obj.as_any().
			downcast_ref::<ZkSigmaClaim<E>>().unwrap();
		return self.kzg_superset==other.kzg_superset && 
			self.comm_z==other.comm_z &&
			self.r ==other.r && 
			self.p_r_z ==other.p_r_z &&
			self.g_z == other.g_z &&
			self.h_z == other.h_z ;
	}
}

impl <E:PairingEngine> Protocol<E> for ZkSigma <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// return the name
	fn name(&self)->&str{
		return "ZkSigma";
	}

	/// generate the proof
	/// NOTE: it only return valid result in main processor 0!!!
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		let sinp:&mut ZkSigmaInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkSigmaInput<E>>().unwrap();
		//1. compute the prf_subset
		let mut rng = gen_rng(); 
		let gamma = E::Fr::rand(&mut rng);
		let r1 = E::Fr::rand(&mut rng);
		let mut subset_input = ZkSubsetInput::<E>{
			p_superset: sinp.p_superset.clone(),
			p_subset: sinp.p_subset.clone(),
			gamma: gamma.clone(),
			r1: r1.clone(),
		};
		let proto_subset = ZkSubset::new(self.key.clone());
		let prf_subset = proto_subset.prove(&mut subset_input).as_any().
			downcast_ref::<ZkSubsetProof<E>>().unwrap().clone();

		//2. compute the prf_kzg
		let mut kzg_input = ZkKZGInput::<E>{
			p: sinp.p_subset.clone(),
			r: sinp.r.clone(),
			gamma: gamma.clone(),
			r1: r1.clone(),
			z: sinp.z.clone(),
			r2: sinp.r2.clone(),
		};
		let proto_kzg = ZkKZG::new_with_generators(self.key.clone(), 
			self.g_z, self.h_z);
		let prf_kzg= proto_kzg.prove(&mut kzg_input).as_any().
			downcast_ref::<ZkKZGProof<E>>().unwrap().clone();

		//3. compute the kzg_subset_g2 and comm_gamma_g2
		let kzg_subset_g2 = self.key.gen_kzg_g2(&mut sinp.p_subset)[0] + 
				self.key.h_g2.mul(gamma).into_affine(); 
		let comm_gamma_g2 = self.key.g_g2.mul(gamma) + 
				self.key.h_g2.mul(r1);
		let kzg_subset_g1 = self.key.gen_kzg(&mut sinp.p_subset)[0] + 
				self.key.h.mul(gamma).into_affine(); 
		let comm_gamma_g1 = self.key.g.into_affine().mul(gamma) + 
				self.key.h.mul(r1);
		let prf = ZkSigmaProof::<E>{
			prf_subset: prf_subset,
			prf_kzg: prf_kzg,
			kzg_subset_g2: kzg_subset_g2,
			comm_gamma_g2: comm_gamma_g2.into_affine(),
			kzg_subset_g1: kzg_subset_g1,
			comm_gamma_g1: comm_gamma_g1.into_affine(),
		};
		return Box::new(prf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let sinp:&mut ZkSigmaInput::<E> = inp.as_any_mut().
			downcast_mut::<ZkSigmaInput<E>>().unwrap();
		//1. compute the W polynomial
		let kzg_superset = self.key.gen_kzg(&mut sinp.p_superset)[0];
		let comm_z = self.g_z.mul(sinp.z)  + self.h_z.mul(sinp.r2);
		let p_r_z = sinp.p_subset.eval(&sinp.r) + sinp.z;
		let claim = ZkSigmaClaim::<E>{
			kzg_superset: kzg_superset,
			comm_z: comm_z.into_affine(),
			r: sinp.r,
			p_r_z: p_r_z,
			g_z: self.g_z,
			h_z: self.h_z
		};
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let n_claim:&ZkSigmaClaim::<E> = claim.as_any().
			downcast_ref::<ZkSigmaClaim<E>>().unwrap();
		let n_proof:&ZkSigmaProof::<E> = proof.as_any().
			downcast_ref::<ZkSigmaProof<E>>().unwrap();

		//1. check the validity of two subproofs
		let proto_subset = ZkSubset::new(self.key.clone());
		let sclaim = ZkSubsetClaim::<E>{
			kzg_superset: n_claim.kzg_superset,
			kzg_subset: n_proof.kzg_subset_g2,
			comm_gamma: n_proof.comm_gamma_g2,
		};
		let b1 = proto_subset.verify(&sclaim, &n_proof.prf_subset);
		if !b1 {return false;}

		let proto_kzg = ZkKZG::new_with_generators(self.key.clone(), 
			n_claim.g_z, n_claim.h_z);
		let kclaim = ZkKZGClaim::<E>{
			c_p: n_proof.kzg_subset_g1,
			c_gamma: n_proof.comm_gamma_g1,
			c_z: n_claim.comm_z,
			r: n_claim.r,
			o: n_claim.p_r_z,
		};
		let b2 = proto_kzg.verify(&kclaim, &n_proof.prf_kzg);
		if !b2 {return false;}

		//3. check e(g, kzg_subset_g2) = e(kzg_subset, g)
	 	//e(g, comm_gamma_g2) = e(comm_gamma_g1, g)
		if E::pairing(self.key.g, n_proof.kzg_subset_g2) !=
			E::pairing(n_proof.kzg_subset_g1, self.key.g_g2){
			return false;
		}
		if E::pairing(self.key.g, n_proof.comm_gamma_g2) !=
			E::pairing(n_proof.comm_gamma_g1, self.key.g_g2){
			return false;
		}
		return true;
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
		let proto = ZkSigma::<E>::new(key); 		 //factory instance
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
		let z = E::Fr::rand(&mut rng);
		let r2 = E::Fr::rand(&mut rng);

		//2. builds ZkSigmaInput 
		let mut inp: ZkSigmaInput<E> = ZkSigmaInput{
			p_superset: dp_superset, 
			p_subset: dp_subset,
			r: r,
			z: z,
			r2: r2
		};  
		let prf = proto.prove(&mut inp);
		let mut claim = proto.claim(&mut inp);

		//3. introduce error if asked
		if b_set_err { 
			let kclaim:&ZkSigmaClaim::<E> = claim.as_any().
				downcast_ref::<ZkSigmaClaim<E>>().unwrap();
			let new_kzg_superset= kclaim.kzg_superset.mul(2u32).into_affine();
			let mut bad_claim = kclaim.clone();
			bad_claim.kzg_superset = new_kzg_superset;
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	fn new(key: Rc<DisKey<E>>) -> Self{
		let g_z = key.g.into_affine();
		let h_z = key.h.clone();
		let proto = ZkSigma{ key: key, g_z: g_z, h_z: h_z};
		return proto;
	}
}

impl <E:PairingEngine> ZkSigma <E> 
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn new_with_generators(key: Rc<DisKey<E>>, z_g: E::G1Affine,
		z_h: E::G1Affine) -> Self{
		let zp_proto = ZkSigma{key: key, g_z: z_g, h_z: z_h};
		return zp_proto;
	}
}

