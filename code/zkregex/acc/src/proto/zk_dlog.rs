/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 11/23/2022
	Completed: 11/23/2022
*/

/// This module defines the standard DLOG (Schnorr) protocol
/// Given y = g^x proves the knowledge of secret x
///
/// Performance: prove: 0ms, verification 252us
/// Size: 64 bytes.

extern crate ark_ff;
extern crate ark_serialize;

use proto::*;
use tools::*;
use self::ark_ec::{AffineCurve, ProjectiveCurve};
use self::ark_ff::{UniformRand};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::profiler::config::*;
use self::ark_ec::msm::{VariableBaseMSM};

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// --------------------------------------------------- 
//  Data Structures: zkSame Claim, Proof, and Input
// --------------------------------------------------- 
/// The input that are used to generate claim and proof
#[derive(Clone)]
pub struct ZkDLOGInput<G: AffineCurve> where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// the given base
	pub g: G, 
	/// the secret component
	pub x: G::ScalarField,
}

/// Built from Schnorr's DLOG protocol. It consists of random commits
/// sent in the first round, and the responses sent in the 2nd round.
#[derive(Clone)]
pub struct ZkDLOGProof<G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// the random commit in 1st round
	pub commit: G,
	/// the response in the last round
	pub response: G::ScalarField,
}

#[derive(Clone)]
pub struct ZkDLOGClaim<G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// y = g^x
	pub g: G, 
	pub y: G,
}

/// The ZkDLOG protocol 
#[derive(Clone)]
pub struct ZkDLOG<E: PairingEngine, G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// base
	pub g: G,
	/// This is a parameter vector, never used.
	pub _key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <G:AffineCurve> ProverInput for ZkDLOGInput<G>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <G:AffineCurve> ProtoObj for ZkDLOGProof<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		//1. get the length pack 
		// [len(responds), len(commits), len(responds[0]), ....len(responds[n])
		let mut b1: Vec<u8> = vec![];
		G::serialize(&self.commit, &mut b1).unwrap();
		G::ScalarField::serialize(&self.response, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut b1 = &v[..];
		let gcommit = G::deserialize(&mut b1).unwrap();
		let response = G::ScalarField::deserialize(&mut b1).unwrap();
		let res = ZkDLOGProof::<G>{
			commit: gcommit,
			response: response
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} ZkDLOGProof: commit: {}, response: {}", prefix, self.commit, self.response);
	} 

}

impl <G:AffineCurve> Proof for ZkDLOGProof<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.commit = res.commit.clone();
		self.response= res.response.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkDLOGProof::<G> = other.as_any().
			downcast_ref::<ZkDLOGProof<G>>().unwrap();
		return self.commit==obj.commit && self.response==obj.response;
	}
}

impl <G:AffineCurve> ProtoObj for ZkDLOGClaim<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		G::serialize(&self.g, &mut b1).unwrap();
		G::serialize(&self.y, &mut b1).unwrap();
		return b1;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		let mut b1 = &v[..];
		let g = G::deserialize(&mut b1).unwrap();		
		let y = G::deserialize(&mut b1).unwrap();		
		let res = ZkDLOGClaim::<G>{ g: g, y: y };
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkDLOGClaim g: {}, y: {})", prefix, self.g, self.y);
	} 
}

impl <G:AffineCurve> Claim for ZkDLOGClaim<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.g= res.g.clone();
		self.y= res.y.clone();
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkDLOGClaim::<G> = obj.as_any().
			downcast_ref::<ZkDLOGClaim<G>>().unwrap();
		return self.y==other.y && self.g==other.g;
	}
}

impl <E: PairingEngine, G: AffineCurve> Protocol<E> for ZkDLOG<E, G>
where
E: PairingEngine<G1Affine=G>,
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// return the name
	fn name(&self)->&str{
		return "ZkDLOG";
	}

	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//1. cast input
		let sinp:&mut ZkDLOGInput<G> = inp.as_any_mut().
			downcast_mut::<ZkDLOGInput<G>>().unwrap();

		//2. generate the random commitments for each base signature
		let g = sinp.g.clone();
		let mut rng = gen_rng_from_seed(12312312312u128);
		let r = G::ScalarField::rand(&mut rng);
		let commit = g.mul(r).into_affine();

		//3. generate the random challenge as hash of all sigs
		let b8 = to_vecu8(&vec![commit]);
		let c = hash::<G::ScalarField>(&b8);

		//4. generate the responses
		let response = c*sinp.x + r;

		//5. build up the proof 
		let prf = ZkDLOGProof::<G>{
			commit: commit,
			response: response
		};
		return Box::new(prf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkDLOGInput::<G> = inp.as_any_mut().
			downcast_mut::<ZkDLOGInput<G>>().unwrap();
		let y = kinp.g.mul(kinp.x).into_affine();
		let claim = ZkDLOGClaim::<G>{ g: kinp.g.clone(), y : y };
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let s_claim:&ZkDLOGClaim::<G> = claim.as_any().
			downcast_ref::<ZkDLOGClaim<G>>().unwrap();
		let s_proof:&ZkDLOGProof::<G> = proof.as_any().
			downcast_ref::<ZkDLOGProof<G>>().unwrap();

		//1. compute the challenge c
		let b8 = to_vecu8(&vec![s_proof.commit]);
		let c = hash::<G::ScalarField>(&b8);

		//2. check for each i:
		//  y^c * commit = g^response
		let left = s_claim.y.mul(c).into_affine() + s_proof.commit;
		let right = s_claim.g.mul(s_proof.response).into_affine();
		let res = left==right; //ONLY returns true in node 0
		return res;
	}

	/// generate a random instance. n is the number of group elements
	/// in claim.y vector.
	/// seed uniquely determines the instance generated
	fn rand_inst(&self, _n_proposed: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		//1. generate the protocol
		let mut rng = gen_rng_from_seed(seed);
		let g = key.g.clone().into_affine();
		let x = G::ScalarField::rand(&mut rng);
		let mut inp = ZkDLOGInput::<G> {x: x, g: g};	
		let proto = Self::new_with_base(g, key);
		let mut claim = proto.claim(&mut inp);
		let prf = proto.prove(&mut inp);

		//3. introduce error
		if b_set_err{
			let one: G = G::rand(&mut rng);
			let sclaim:&ZkDLOGClaim::<G> = claim.as_any().
				downcast_ref::<ZkDLOGClaim<G>>().unwrap();
			let new_y = sclaim.y + one;
			let bad_claim: ZkDLOGClaim<G> = 
				ZkDLOGClaim {g: sclaim.g.clone(), y: new_y};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	/// factory method.  ONLY USED FOR testing purpose as bases are
	/// generated
	fn new(key: Rc<DisKey<E>>) -> Self{
		let s_proto = Self::new_with_base(key.g.clone().into_affine(), key);
		return s_proto;
	}
}

impl <E:PairingEngine, G: AffineCurve> ZkDLOG<E,G>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// Constructor. real constructor used. 
	pub fn new_with_base(base: G, key: Rc<DisKey<E>>)->Self{
		let proto = ZkDLOG{
			g: base,
			_key : key
		};
		return proto;
	}
}
