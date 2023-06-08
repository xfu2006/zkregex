
/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/11/2022
	Completed: 07/15/2022
*/

extern crate ark_ec;

use std::any::Any;
use std::rc::Rc;
use crate::poly::dis_key::*;
use self::ark_ec::{PairingEngine};

// test and profiler functions. Note profiler in profiler/profile_proto.rs
pub mod proto_tests;
// non-zk protocols
pub mod kzg;
pub mod subset;
pub mod nonzk_sigma;
// zk-protocols
pub mod zk_same;
pub mod zk_prod;
pub mod zk_poly;
pub mod zk_kzg;
pub mod zk_kzg_v2;
pub mod zk_subset;
pub mod zk_subset_v2;
pub mod zk_subset_v3;
pub mod zk_sigma;
pub mod zk_kzg_vsql;
pub mod zk_dlog;
pub mod ripp_driver;
pub mod zk_conn;

/// Serialization interface. Claim and Proof need to implement it.
pub trait ProtoObj{
	/// need for downcasting when used as params
	fn as_any(&self) -> &dyn Any;

	/// serialization
	fn to_bytes(&self)->Vec<u8>;

	/// deserialization (static version), needed in other protocols
	fn static_from_bytes(v: &Vec<u8>)->Box<Self> where Self: Sized; 

	/// dump
	fn dump(&self, prefix: &str);
}

/// Prover's Input (including both public i/o and private witness) of a prover 
/// Visible to prover only.
pub trait ProverInput{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any;
	fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Represents a CLAIM of the (non or zk)-Proof, need serialization
/// This is visible to the world.
pub trait Claim: ProtoObj{ 
	/// deserialization, changes itself. Needed in profiler
	fn from_bytes(&mut self, v: &Vec<u8>);

	/// equality check
	fn equals(&self, obj: &dyn Claim)->bool;
} 

/// The proof, need serialization 
pub trait Proof: ProtoObj{
	/// deserialization. Changes itself. Needed in profiler.
	fn from_bytes(&mut self, v: &Vec<u8>);

	/// check equals
	fn equals(&self, obj: &dyn Proof)->bool;
}

/// A protocol represents a Sigma protocol (maybe non-zk).
///
/// It uses the Fiat-Shamir heuristics that provides a proof.
/// It provides functions for generating a proof for a prover input
/// and also it provides functions for verifying a proof.
/// The protocol encapsulates prover/verfier key. For a remote
/// verifier to verify a claim and a proof, they need to build 
/// the protocol first. We assume that given that same seed (in rand_inst),
/// the protocol built will be always having the same prover/verifier key.
/// We also assume that when a smaller capacity (n in rand_inst) is used,
/// the prover key is a sub-sequence of a protocol generated using a larger
/// capacity. 
pub trait Protocol<E:PairingEngine>{
	/// return the name
	fn name(&self) -> &str;

	/// generate the proof. 
	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof>;

	/// generate the claim (given the secret witness input). 
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim>;

	/// verify if the the proof indeed proves the claim.
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool;

	/// static factory method: passing the prover key
	fn new(key: Rc<DisKey<E>>) -> Self where Self: Sized;

	/// generate a random test case. the semantics of n is instance specific
	/// always generate the same instance given the same seed
	/// if b_set_err is true, introduce an error into proof, input or claim
	/// the key is the prover key passed. Each implementation should
	/// check if the key size is large enough for supporting the case
	/// size n.
	fn rand_inst(&self, n: usize, seed: u128, b_set_err: bool, 
		key: Rc<DisKey<E>>) -> 
		(Box<dyn Protocol<E>>, Box<dyn ProverInput>,
		Box<dyn Claim>, Box<dyn Proof>);

}

