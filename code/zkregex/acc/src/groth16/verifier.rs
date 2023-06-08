/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created 10/16/2022
	Completed 10/17/2022
	
	Provides verifier (note: no difference between serial and distributed)

*/

/// Verifier
///
/// Ref: Groth'16: J. Groth, "On the Size of Pairing-Based Non-Interactive
/// Arguments", EUROCRYPT16. https://eprint.iacr.org/2016/260.pdf
/// Ref2: DIZK: H. Wu et al, "DIZK: Distributed Zero Knowledge Proof system",
/// https://www.usenix.org/conference/usenixsecurity18/presentation/wu
/// NOTE: our variable naming convention simulates the source code of DIZK
/// The serial QAP is used for functional testing of distributed QAP.
///
/// We used most of the variation notations from DIZK and its arch design.
/// The revised part is: The proof is split into two halves, using
/// the 2-stage Groth'16 scheme in our zk-regex paper.

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

//use self::ark_ff::{Zero,UniformRand};
use self::ark_ec::{PairingEngine,AffineCurve};
//use self::ark_ec::msm::{VariableBaseMSM};
//use tools::*;
//use poly::dis_key::*;
//use groth16::serial_qap::*;
use groth16::serial_prove_key::*;
//use groth16::common::*;
use groth16::serial_prover::*;
//use profiler::config::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Verify the proof is correct. NOTE: the statement (i/o part
/// of the witness is contained in ProofPart2.io
pub fn verify<PE:PairingEngine>(p1: &ProofPart1<PE>, p2: &ProofPart2<PE>, key: &VerifierKey<PE>) 
	-> bool{
	//1. compute LHS
	let lhs = PE::pairing(p2.a, p2.b);
	//2. compute the RHS
	let gamma_abc = &key.gamma_abc_g1;
	let mut abc_io = gamma_abc[0].mul(p2.io[0]);
	for i in 1..gamma_abc.len(){
		abc_io = abc_io + gamma_abc[i].mul(p2.io[i]);
	}
	let paired_abc_io = PE::pairing(abc_io, key.gamma_g2);
	let mut c = p1.arr_c.clone();
	let mut arrc2 = p2.arr_c.clone();
	c.append(&mut arrc2);
	c.push(p2.last_c);
	let mut c_delta = PE::pairing(c[0], key.delta_g2[0]);
	for i in 1..c.len(){
		let item = PE::pairing(c[i], key.delta_g2[i]);
		c_delta = c_delta * item;
	}
	let rhs =  key.alpha_g1_beta_g2 * paired_abc_io * c_delta;
	let bres = lhs == rhs;

	return bres;
}
