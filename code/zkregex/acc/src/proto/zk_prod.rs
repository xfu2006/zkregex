/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/19/2022
	Completed: 07/21/2022
*/

/// This module defines zero kowledge prod relation proof for
/// A: g^x h^r1  B:g^y h^r2  C: g^{xy} h^r3
/// Where the exponent of C is the product of that of A and B
///
/// Proof Idea: simply show C = A^y h^{r3-r1*y} (has the same
/// exponent of B, i.e., y over base g.
///
/// Performance: Verification: 700us (on 8 nodes 1 computer) - 6 group exp.
/// Proof size: 160 bytes (2 group elements + 3 field elements) - BN254

extern crate ark_ff;
extern crate ark_serialize;

use proto::*;
use tools::*;
use self::ark_ec::{AffineCurve, ProjectiveCurve};
use self::ark_ff::{Zero,UniformRand};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::profiler::config::*;

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// --------------------------------------------------- 
//  Data Structures: zkProd Claim, Proof, and Input
// --------------------------------------------------- 
/// The input that are used to generate claim and proof
#[derive(Clone)]
pub struct ZkProdInput<G: AffineCurve>{
	/// A = g^x h^r1
	pub x: G::ScalarField,
	/// random nonce for A
	pub r1: G::ScalarField,
	/// B = g^y h^r2
	pub y: G::ScalarField,
	/// random nonce for B
	pub r2: G::ScalarField,
	/// C = g ^{xy} h^r3
	pub r3: G::ScalarField
}

/// Built from Schnorr's DLOG protocol. It consists of random commitment
/// sent in the first round, and the responses sent in the 2nd round.
#[derive(Clone)]
pub struct ZkProdProof<G: AffineCurve>{
	/// random commitment for C
	pub commit_c: G,
	/// random commitment for B
	pub commit_b: G,
	/// responses for C: A^sc1 h^sc2 = commit_c C^e where e is rand challenge
	pub sc1: G::ScalarField,
	pub sc2: G::ScalarField,
	/// responses for B: g^sb1 h^sb2 = commit_b B^e  
	/// here sb1 is the same as sc1
	pub sb2: G::ScalarField,
}

/// The claim is that C has the exponent which is the product
/// of the exponents of A and B.
#[derive(Clone)]
pub struct ZkProdClaim<G: AffineCurve>{
	/// A = g^x h^r1
	pub a: G,
	/// B = g^y h^r2
	pub b: G,
	/// C = g^{xy} h^r3
	pub c: G,
}

/// The ZkProd protocol 
#[derive(Clone)]
pub struct ZkProd<E: PairingEngine, G: AffineCurve>{
	/// base g
	pub g: G,
	/// base h
	pub h: G,
	/// This is a parameter vector, never used. Listed because need to use E
	pub _key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <G:AffineCurve> ProverInput for ZkProdInput<G>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <G:AffineCurve> ProtoObj for ZkProdProof<G> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1 = vec![];
		G::serialize(&self.commit_c, &mut b1).unwrap();
		G::serialize(&self.commit_b, &mut b1).unwrap();
		G::ScalarField::serialize(&self.sc1, &mut b1).unwrap();
		G::ScalarField::serialize(&self.sc2, &mut b1).unwrap();
		G::ScalarField::serialize(&self.sb2, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut b1 = &v[..];
		let commit_c = G::deserialize(&mut b1).unwrap();
		let commit_b = G::deserialize(&mut b1).unwrap();
		let sc1 = G::ScalarField::deserialize(&mut b1).unwrap();
		let sc2 = G::ScalarField::deserialize(&mut b1).unwrap();
		let sb2 = G::ScalarField::deserialize(&mut b1).unwrap();
		let res = ZkProdProof::<G>{
			commit_c: commit_c,
			commit_b: commit_b,
			sc1: sc1,
			sc2: sc2,
			sb2: sb2,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!(" {} ZkProdProof: (", prefix);
		print!(" commit_c: {} ", self.commit_c);
		print!(" commit_b: {} ", self.commit_b);
		print!(" sc1: {} ", self.sc1);
		print!(" sc2: {} ", self.sc2);
		print!(" sb2: {} )\n", self.sb2);
	} 
}

impl <G:AffineCurve> Proof for ZkProdProof<G> {
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.commit_c = res.commit_c;
		self.commit_b = res.commit_b;
		self.sc1 = res.sc1;
		self.sc2 = res.sc2;
		self.sb2 = res.sb2;
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkProdProof::<G> = other.as_any().
			downcast_ref::<ZkProdProof<G>>().unwrap();
		return self.commit_c == obj.commit_c  &&  
			self.commit_b == obj.commit_b  &&  
			self.sc1 == obj.sc1  &&  
			self.sc2 == obj.sc2  &&  
			self.sb2 == obj.sb2;
	}
}

impl <G:AffineCurve> ProtoObj for ZkProdClaim<G> {
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1 = vec![];
		G::serialize(&self.a, &mut b1).unwrap();
		G::serialize(&self.b, &mut b1).unwrap();
		G::serialize(&self.c, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut b1 = &v[..];
		let a = G::deserialize(&mut b1).unwrap();		
		let b = G::deserialize(&mut b1).unwrap();		
		let c = G::deserialize(&mut b1).unwrap();		
		let res = ZkProdClaim::<G>{
			a: a,
			b: b,
			c: c,
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkProdClaim (a: {}, b: {}, c: {})\n", 
			prefix, self.a, self.b, self.c);
	} 
}

impl <G:AffineCurve> Claim for ZkProdClaim<G> {
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.a = res.a;
		self.b = res.b;
		self.c = res.c;
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkProdClaim::<G> = obj.as_any().
			downcast_ref::<ZkProdClaim<G>>().unwrap();
		return self.a==other.a && self.b==other.b && self.c==other.c;
	}
}

impl <E: PairingEngine, G: AffineCurve> Protocol<E> for ZkProd<E, G>{
	/// return the name
	fn name(&self)->&str{
		return "ZkProd";
	}

	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//0. cast input
		let sinp:&mut ZkProdInput<G> = inp.as_any_mut().
			downcast_mut::<ZkProdInput<G>>().unwrap();

		//1. generate the random commitments for each base signature
		let mut rng = gen_rng();
		let n1 = G::ScalarField::rand(&mut rng);
		let n2 = G::ScalarField::rand(&mut rng);
		let n4 = G::ScalarField::rand(&mut rng);

		let a= (self.g.mul(sinp.x) + self.h.mul(sinp.r1)).into_affine(); 
		let commit_c = a.mul(n1) + self.h.mul(n2); 
		let commit_b = self.g.mul(n1) + self.h.mul(n4);  //n3 = n1
		let commits = vec![commit_c, commit_b];
	
		//2. generate the random challenge: e,  as hash of round 1
		let b8 = to_vecu8(&commits);
		let e = hash::<G::ScalarField>(&b8);

		//4. generate the responses
		let sc1 = n1 + sinp.y*e; 
		let sc2 = n2 + (sinp.r3-sinp.r1*sinp.y)*e;
		let sb2 = n4 + sinp.r2*e;

		//5. build up the proof 
		let prf = ZkProdProof::<G>{
			commit_c: commit_c.into_affine(),
			commit_b: commit_b.into_affine(),
			sc1: sc1,
			sc2: sc2,
			sb2: sb2,
		};
		return Box::new(prf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkProdInput::<G> = inp.as_any_mut().
			downcast_mut::<ZkProdInput<G>>().unwrap();
		let a; let b; let c;
		if RUN_CONFIG.my_rank!=0{
			a = G::zero();
			b = G::zero();
			c = G::zero();
		}else{
			let xy = kinp.x * kinp.y;
			a = (self.g.mul(kinp.x) + self.h.mul(kinp.r1)).into_affine();
			b = (self.g.mul(kinp.y) + self.h.mul(kinp.r2)).into_affine();
			c = (self.g.mul(xy) + self.h.mul(kinp.r3)).into_affine();
		}
		let claim = ZkProdClaim::<G>{ a: a, b: b, c: c};
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let s_claim:&ZkProdClaim::<G> = claim.as_any().
			downcast_ref::<ZkProdClaim<G>>().unwrap();
		let s_proof:&ZkProdProof::<G> = proof.as_any().
			downcast_ref::<ZkProdProof<G>>().unwrap();

		//1. get the challenge e
		let commits = vec![s_proof.commit_c, s_proof.commit_b];
		let b8 = to_vecu8(&commits);
		let e = hash::<G::ScalarField>(&b8);

		//2. check the following:
		// (1) C^e * commit_c = A^sc1 h^sc2
		// (2) B^e * commit_b = g^sc1 h^sb2 [note: sc1 is used twice] 
		let eq1_lhs = s_claim.c.mul(e) + s_proof.commit_c.into_projective();
		let eq1_rhs = s_claim.a.mul(s_proof.sc1) + self.h.mul(s_proof.sc2);
		let eq2_lhs = s_claim.b.mul(e) + s_proof.commit_b.into_projective();
		let eq2_rhs = self.g.mul(s_proof.sc1) + self.h.mul(s_proof.sb2);
		let b1 = eq1_lhs == eq1_rhs;
		let b2 = eq2_lhs == eq2_rhs;
		return b1 && b2;
	}

	/// generate a random instance. 
	/// seed uniquely determines the instance generated
	/// n_proposed is the proposed size. (in this protocol, it is ignored!)
	fn rand_inst(&self, _n_proposed: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		//1. generate the protocol
		//NOTE: due to the pack_small_u64 restriction, n cannot be >=8
		let mut rng = gen_rng_from_seed(seed);
		let proto = ZkProd::<E,G>::new(key); 		

		//2. generate the input, claim, and proof
		let mut v = vec![G::ScalarField::zero(); 5];
		for i in 0..5 {v[i] = G::ScalarField::rand(&mut rng);}
		let mut inp = ZkProdInput::<G> {x: v[0], r1: v[1], y: v[2], r2: v[3], r3: v[4]};
		let mut claim = proto.claim(&mut inp);
		let prf = proto.prove(&mut inp);

		//3. introduce error
		if b_set_err{
			let one: G = G::rand(&mut rng);
			let sclaim:&ZkProdClaim::<G> = claim.as_any().
				downcast_ref::<ZkProdClaim<G>>().unwrap();
			let new_b = sclaim.b + one;
			let bad_claim: ZkProdClaim<G> = ZkProdClaim {
				a: sclaim.a.clone(),
				b: new_b,
				c: sclaim.c.clone()
			};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	/// factory method.  ONLY USED FOR testing purpose
	fn new(key: Rc<DisKey<E>>) -> Self{
		let mut rng = gen_rng();
		let g = G::rand(&mut rng);
		let h = G::rand(&mut rng);
		let proto = ZkProd::<E,G>{
			g: g,
			h: h,
			_key: key
		};
		return proto;
	}
}

impl <E: PairingEngine, G: AffineCurve> ZkProd<E, G>{
	/// constructor
	pub fn new_with_generator(key: Rc<DisKey<E>>, g: G, h: G) -> Self{
		let proto = ZkProd::<E,G>{
			g: g,
			h: h,
			_key: key
		};
		return proto;
	}
}
