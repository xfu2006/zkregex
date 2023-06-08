/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created 10/15/2022
	Completed 10/15/2022

	This file serial version of the prover and verifier keys of modified
	groth'16
*/

/// Serial version of Prover and Verifier Keys
///
/// Ref: Groth'16: J. Groth, "On the Size of Pairing-Based Non-Interactive
/// Arguments", EUROCRYPT16. https://eprint.iacr.org/2016/260.pdf
/// Ref2: DIZK: H. Wu et al, "DIZK: Distributed Zero Knowledge Proof system",
/// https://www.usenix.org/conference/usenixsecurity18/presentation/wu
/// NOTE: our variable naming convention simulates the source code of DIZK
/// The serial QAP is used for functional testing of distributed QAP.
/// We used most of the variation notations from DIZK
///
/// The keys are enhanced with more elements from our modified
/// scheme (see zkregex paper)

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use self::ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use self::ark_ff::{Field,Zero,UniformRand};
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
//use r1cs::serial_r1cs::ark_std::rand::rngs::StdRng;
use tools::*;
use poly::dis_key::*;
//use profiler::config::*;
use groth16::serial_qap::*;
use groth16::common::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// QAPWitness struct
#[derive(Clone)]
pub struct SerialProverKey<PE:PairingEngine>{
	/// g^alpha in G1
	pub alpha_g1: PE::G1Affine, 
	/// g^beta in G1
	pub beta_g1: PE::G1Affine, 
	/// g^beta in G2
	pub beta_g2: PE::G2Affine, 
	/// g^delta in G1 (for each segment)
	pub delta_g1: Vec<PE::G1Affine>, 
	/// g^delta in G2 (for each segment)
	pub delta_g2: Vec<PE::G2Affine>, 
	/// g^{\frac{beta u_i(x) + alpha v_i(x) + w_i(x)}{\delta}} in G1
	/// for each segment
	pub delta_abc_g1: Vec<Vec<PE::G1Affine>>,
	/// g^{u_i(x)} in groth'16 paper
	pub query_a: Vec<PE::G1Affine>,
	/// g^{v_i(x)} in groth'16 paper over Group G2
	pub query_b: Vec<PE::G2Affine>,
	/// g^{v_i(x)} in groth'16 paper over group G1
	pub query_b1: Vec<PE::G1Affine>,
	/// g^{(x^i t(x))/last_delta} for each i groth'16 paper
	pub query_h: Vec<PE::G1Affine>,
}

/// verifier key (this is common for both Serial and Distributed)
pub struct VerifierKey<PE:PairingEngine>{
	/// alpha (alpha and beta are used for computing aggregate_prf)
	pub alpha_g1: PE::G1Affine,
	/// beta
	pub beta_g2: PE::G2Affine,
	/// pairing(g1^alpha, g^beta) 
	pub alpha_g1_beta_g2: PE::Fqk,
	/// g^gamma over G2
	pub gamma_g2: PE::G2Affine,
	/// g^delta over G2 (one for each segment)
	pub delta_g2: Vec<PE::G2Affine>,
	/// (beta u_i(x) + alpha v_i(x) + w_i(x))/gamma for i=0 to l
	pub gamma_abc_g1: Vec<PE::G1Affine>
}

impl <PE:PairingEngine> VerifierKey <PE>{
	pub fn to_bytes(&self) -> Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		self.alpha_g1.serialize(&mut b1).unwrap();
		self.beta_g2.serialize(&mut b1).unwrap();
		self.alpha_g1_beta_g2.serialize(&mut b1).unwrap();
		self.gamma_g2.serialize(&mut b1).unwrap();
		self.delta_g2.serialize(&mut b1).unwrap();
		self.gamma_abc_g1.serialize(&mut b1).unwrap();
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>) -> Self{
		let mut v1 = &v[..];
		let alpha_g1= PE::G1Affine::deserialize(&mut v1).unwrap(); 	
		let beta_g2= PE::G2Affine::deserialize(&mut v1).unwrap(); 	
		let alpha_g1_beta_g2 = PE::Fqk::deserialize(&mut v1).unwrap(); 	
		let gamma_g2 = PE::G2Affine::deserialize(&mut v1).unwrap();
		let delta_g2 = Vec::<PE::G2Affine>::deserialize(&mut v1).unwrap();
		let gamma_abc_g1 = Vec::<PE::G1Affine>::deserialize(&mut v1).unwrap();
		let res = Self{
			alpha_g1: alpha_g1,
			beta_g2: beta_g2,
			alpha_g1_beta_g2: alpha_g1_beta_g2,
			gamma_g2: gamma_g2,
			delta_g2: delta_g2,
			gamma_abc_g1: gamma_abc_g1
		};
		return res;
	}
}


/// generate the prover and verifier keys
pub fn serial_setup<PE:PairingEngine>(seed: u128, qap: &QAP<PE::Fr>, key: &DisKey<PE>) ->
	(SerialProverKey<PE>, VerifierKey<PE>) where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. generate the random values (for sake of later converetd to dis
	//version, we just manually create these values) - so that all nodes
	//could be consistent. improve later
	let mut rng = gen_rng_from_seed(seed);
	let alpha = PE::Fr::rand(&mut rng);
	let beta = PE::Fr::rand(&mut rng);
	let gamma = PE::Fr::rand(&mut rng);
	let init_delta = PE::Fr::rand(&mut rng);
	let inverse_gamma = gamma.inverse().unwrap();
	let mut delta = vec![init_delta; qap.num_segs];
	let mut inverse_delta = vec![init_delta; qap.num_segs];
	for i in 0..qap.num_segs{
		delta[i] = PE::Fr::rand(&mut rng);
		inverse_delta[i] = delta[i].inverse().unwrap();
	} 
	let g1 = key.g.into_affine();
	let g1_proj = key.g;
	let g2 = key.g_g2;
	let g2_proj = key.g_g2.into_projective();

	//2. compute (beta*u_i(x) + alpha*v_i(x) + w_i(x))/gamma
	let mut gamma_abc = vec![PE::Fr::zero(); qap.num_inputs];
	for i in 0..qap.num_inputs{
		let vsum = beta*qap.at[i]+alpha*qap.bt[i]+qap.ct[i];
		gamma_abc[i] = vsum*inverse_gamma;
	}

	//3. compute (beta*u_j(x) + alapha*v_j(x) + w_j(x))/delta_i
	//for each segment
	let mut start_pos = qap.num_inputs;
	let mut delta_abc = vec![vec![]; qap.num_segs];
	for i in 0..qap.num_segs{
		delta_abc[i] = vec![PE::Fr::zero(); qap.seg_size[i]];
		for j in 0..qap.seg_size[i]{
			let idx = j + start_pos; 
			delta_abc[i][j]= (beta*qap.at[idx]+alpha*qap.bt[idx]+qap.ct[idx]) * inverse_delta[i];
		}
		start_pos += qap.seg_size[i];
	}
	assert!(start_pos==qap.num_vars, "start_pos: {} != num_vars: {}", start_pos, qap.num_vars);

	//4. generating raised powers
	let alpha_g1 = g1.mul(alpha).into_affine();
	let beta_g1 = g1.mul(beta).into_affine();
	let beta_g2 = g2.mul(beta).into_affine();
	let gamma_g2 = g2.mul(gamma).into_affine();
	let mut delta_g1 = vec![g1; qap.num_segs];
	let mut delta_g2 = vec![g2; qap.num_segs];
	let mut delta_abc_g1= vec![vec![]; qap.num_segs];
	for i in 0..qap.num_segs{
		delta_g1[i] = g1.mul(delta[i]).into_affine();
		delta_g2[i] = g2.mul(delta[i]).into_affine();
		delta_abc_g1[i] = msm_g1::<PE>(g1_proj, &delta_abc[i]);
	}
	let query_a = msm_g1::<PE>(g1_proj, &qap.at);
	let query_b = msm_g2::<PE>(g2_proj, &qap.bt);
	let query_b1 = msm_g1::<PE>(g1_proj, &qap.bt);
	let gamma_abc_g1= msm_g1::<PE>(g1_proj, &gamma_abc);

	//5. generating the query_h
	let inv_deltaz= inverse_delta[qap.num_segs-1] * qap.zt;
	let mut new_ht = qap.ht.clone();
	let new_ht_len = new_ht.len();
	for i in 0..new_ht_len{
		new_ht[i] = new_ht[i] * inv_deltaz;
	}
	let query_h = msm_g1::<PE>(g1_proj, &new_ht);

	//6. assembly the keys
	let spk = SerialProverKey::<PE>{
		alpha_g1: alpha_g1.clone(),
		beta_g1: beta_g1,
		beta_g2: beta_g2.clone(),
		delta_g1: delta_g1,
		delta_g2: delta_g2.clone(),
		delta_abc_g1: delta_abc_g1,
		query_a: query_a,
		query_b: query_b,
		query_b1: query_b1,
		query_h: query_h
	};

	let svk = VerifierKey{
		alpha_g1: alpha_g1,
		beta_g2: beta_g2,
		alpha_g1_beta_g2: PE::pairing(alpha_g1, beta_g2),
		gamma_g2: gamma_g2,
		delta_g2: delta_g2,
		gamma_abc_g1: gamma_abc_g1,
	};
	
	return (spk, svk);	
}
