/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 03/30/2023

	Aggregate for extended Groth'16 system
	Mainly implementing the scheme givein in "Proofs for Inner Pairing
	Product and Its Applications"
	https://eprint.iacr.org/2019/1177.pdf
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
//use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
//use self::ark_ff::{Zero,One};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
//use self::ark_ff::UniformRand;
use self::ark_inner_products::{ExtensionFieldElement};
use proto::ripp_driver::*;
use zkregex::prover::CRS;

//use std::any::Any;
use std::rc::Rc;

//use poly::dis_poly::*;
//use poly::dis_key::*;
//use proto::zk_poly::*;
//use proto::zk_same::*;
use tools::*;
use groth16::serial_prover::*;


use crate::profiler::config::*;

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// aggregated claim; the other relevant information such as
/// commitments to alpha, beta, gamma, delta_k are saved in setup
#[derive(Clone)]
pub struct Groth16AggClaim<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many segments (not to be consistent for ALL proofs)
	pub num_segs: usize,
	/// commitments to IO: a_i((beta u_i(x) + alpha v_i(x) + w_i(x)/delta_i))
	pub c_io: ExtensionFieldElement<E>,
}

/// aggregated proof 
#[derive(Clone)]
pub struct Groth16AggProof<E: PairingEngine> where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>
{
	/// how many proofs are aggregated
	pub size: usize,
	/// how many proofs are aggregated
	pub num_segs: usize,
	/// the random challenge
	pub r: E::Fr,
	/// commitments to v_g1. 6 elements for zkregex 3 segement systems
	pub v_cg1: Vec<ExtensionFieldElement<E>>, 
	/// commitment to v_g2
	pub v_cg2: Vec<ExtensionFieldElement<E>>, 
	/// z values for tipp proofs
	pub v_z: Vec<ExtensionFieldElement<E>>,
	/// prf of TIPP 2 elmenets
	pub v_prf: Vec<MyTIPAProof<E>>,
}

/// aggregate prove (ProofPart2 has the i/o)
/// Assuming gipa has properly set up (by taking the Groth16 verifier keys
/// from vec(CRS_verifier) when it's set up
/// vec_crs: vec of CRS (for verifier only)
pub fn groth16_agg_prove<E:PairingEngine>(v_prf1: &Vec<ProofPart1<E>>, v_prf2: &Vec<ProofPart2<E>>, gipa: &GIPA<E>, vec_crs: &Vec<Rc<CRS<E>>>) -> (Groth16AggClaim<E>,Groth16AggProof<E>)
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let mut t1 = Timer::new();
	t1.start();
	//0. check data
	let n = v_prf1.len();
	assert!(n.is_power_of_two(), "n: {} is not power of 2!", n);

	//1. build the vector of g1 elements
	let mut vec_a = vec![];
	let mut vec_b = vec![];
	let mut vec_io = vec![];
	let mut vec_gamma = vec![];
	let mut vec_alpha = vec![];
	let mut vec_beta = vec![];
	let num_seg = gipa.num_seg;  
	let mut v2d_cs = vec![vec![]; num_seg];
	let mut v2d_delta = vec![vec![]; num_seg];
	for i in 0..v_prf1.len(){
		let prf1 = &v_prf1[i];
		let prf2 = &v_prf2[i];
		vec_a.push(prf2.a);		
		vec_b.push(prf2.b);

		let vkey = &vec_crs[i].verifier_key;
		let gamma_abc = vkey.gamma_abc_g1.clone();
		let mut abc_io = gamma_abc[0].mul(prf2.io[0]);
		for i in 1..gamma_abc.len(){
			abc_io = abc_io + gamma_abc[i].mul(prf2.io[i]);
		}
		vec_io.push(abc_io.into_affine());
		vec_gamma.push(vkey.gamma_g2.clone());

		vec_alpha.push(vkey.alpha_g1.clone());
		vec_beta.push(vkey.beta_g2.clone());
		
		let mut vc = prf1.arr_c.clone();
		let mut vc2 = prf2.arr_c.clone();
		vc.append(&mut vc2);
		vc.push(prf2.last_c);
		assert!(vc.len()==num_seg, "vc.len() != num_seg");
		for j in 0..num_seg{
			v2d_cs[j].push(vc[j].clone());
			v2d_delta[j].push(vkey.delta_g2[j]);
		}
	}
	let mut v_g1 = vec![
		vec_a, vec_io.clone(), vec_alpha,
	];	
	let mut v_g2 = vec![
		vec_b, vec_gamma, vec_beta,
	];	
	for i in 0..num_seg{
		v_g1.push(v2d_cs[i].clone());
		v_g2.push(v2d_delta[i].clone());
	}

	//2. build the commitments
	let v_g1_proj = v2d_affine_to_proj::<E>(&v_g1);
	let v_g2_proj = v2d_affine2_to_proj::<E>(&v_g2);
	let mut v_cg1 = vec![];	
	let mut v_cg2 = vec![];
	for i in 0..v_g1.len(){
		v_cg1.push(gipa.cm1(&v_g1_proj[i]));
		v_cg2.push(gipa.cm2(&v_g2_proj[i]));
	}

	//3. generate the proofs
	let mut b1 = vec![];
	for i in 0..v_g1.len(){
		ExtensionFieldElement::<E>::serialize(&v_cg1[i], &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&v_cg2[i], &mut b1).unwrap();
	}
	let r = hash::<E::Fr>(&b1); 
	let mut v_z = vec![];
	let mut v_prf = vec![];
	for i in 0..v_g1_proj.len(){
		let (prf, z) = gipa.tipp_prove(&v_g1_proj[i], &v_g2_proj[i], &r);
		v_z.push(z);
		v_prf.push(prf);	
	}

	//4. build the IO
	let c_io = gipa.cm1(&vec_affine_to_proj::<E>(&vec_io));
	let aclaim = Groth16AggClaim::<E>{
		num_segs: num_seg,
		c_io: c_io,
	};
	let aprf = Groth16AggProof::<E>{
		size: n,
		num_segs: num_seg,
		r: r,
		v_cg1: v_cg1,  
		v_cg2: v_cg2,
		v_z: v_z,
		v_prf: v_prf,
	};
	if b_perf {log_perf(LOG1,&format!("----- Groth Proof Time: "), 
			&mut t1);}
	return (aclaim, aprf);
}

/// aggregate verify
pub fn groth16_agg_verify<E:PairingEngine>(agg_claim: &Groth16AggClaim<E>, 
	agg_prf: &Groth16AggProof<E>, gipa: &GIPA<E>) ->bool
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let mut t1 = Timer::new();
	t1.start();

	//C0: check or take data from claim
	let num_segs = agg_claim.num_segs;

	//C1: check data consistency between proof and key
	if agg_prf.v_cg1[1] != agg_claim.c_io{
		log(LOG1, &tos("claim.c_io does not match prf.v_cg1[1]"));
		return false;
	}
	if agg_prf.v_cg2[1] != gipa.c_gamma{
		log(LOG1, &tos("key.c_gamma does not match prf.v_cg2[1]"));
		return false;
	}
	if agg_prf.v_cg1[2] != gipa.c_alpha{
		log(LOG1, &tos("WARN: key.c_alpha != prf.v_cg1[2]"));
		return false;
	}
	if agg_prf.v_cg2[2] != gipa.c_beta{
		log(LOG1, &tos("WARN: key.c_beta != prf.v_cg1[2]"));
		return false;
	}
	for i in 0..num_segs{
		if agg_prf.v_cg2[3+i] != gipa.v_c_delta_g2[i]{
			log(LOG1, &tos("WARN: key.c_delta[i] != prf.v_cg2[3+i]"));
			return false;
		}
	}

	//C2. run the check on Groth16 equation
	let lhs = agg_prf.v_z[0].clone();
	let mut rhs = agg_prf.v_z[1].clone();
	for i in 2..num_segs+3{//e.g. 2,3,4,5 for 3-segment systems in zkregex
		rhs = rhs + agg_prf.v_z[i].clone();
	}
	if lhs!=rhs{
		log(LOG1, &tos("WARN: fails groth16 equation"));
		return false;
	}

	//C3. run on tipa proofs
	for i in 0..agg_prf.v_z.len(){
		if !gipa.tipp_verify(&agg_prf.v_cg1[i], &agg_prf.v_cg2[i],
			&agg_prf.r, &agg_prf.v_z[i], &agg_prf.v_prf[i]){
			log(LOG1, &format!("WARN on tipp prf {}", i));
			return false;	
		}
	}

	if b_perf {log_perf(LOG1,&format!("----- Groth AggVer Time: "), 
			&mut t1);}
	return true;
}

impl <E:PairingEngine> Groth16AggClaim<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.num_segs, &mut b1).unwrap();
		ExtensionFieldElement::<E>::serialize(&self.c_io, &mut b1).unwrap();
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let mut v1 = &v[..];
		let num_segs = usize::deserialize(&mut v1).unwrap();		
		let c_io = ExtensionFieldElement::<E>::deserialize(&mut v1).unwrap();
		let res = Self{num_segs: num_segs, c_io: c_io};
		return res;
	}
}

impl <E:PairingEngine> Groth16AggProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b1).unwrap();
		usize::serialize(&self.num_segs, &mut b1).unwrap();
		E::Fr::serialize(&self.r, &mut b1).unwrap();
		for i in 0..self.num_segs + 3{
			ExtensionFieldElement::<E>::serialize(&self.v_cg1[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&self.v_cg2[i], &mut b1).unwrap();
			ExtensionFieldElement::<E>::serialize(&self.v_z[i], &mut b1).unwrap();	
			MyTIPAProof::<E>::serialize(&self.v_prf[i], &mut b1).unwrap();
		}
		return b1;
	}
	pub fn from_bytes(v: &Vec<u8>, _ripp: &GIPA<E>)->Self{
		let mut b1 = &v[..];
		let size= usize::deserialize(&mut b1).unwrap();		
		let num_segs = usize::deserialize(&mut b1).unwrap();
		let r = E::Fr::deserialize(&mut b1).unwrap();
		let mut v_cg1 = vec![];
		let mut v_cg2 = vec![];
		let mut v_z= vec![];
		let mut v_prf= vec![];
		
		for _i in 0..num_segs+3{
			v_cg1.push(
				ExtensionFieldElement::<E>::deserialize(&mut b1).unwrap());	
			v_cg2.push(
				ExtensionFieldElement::<E>::deserialize(&mut b1).unwrap());	
			v_z.push(ExtensionFieldElement::<E>::deserialize(&mut b1).unwrap());	
			v_prf.push(MyTIPAProof::<E>::deserialize(&mut b1).unwrap());
		}
		let res = Self{size: size, num_segs: num_segs, r: r,
			v_cg1: v_cg1, v_cg2: v_cg2,
			v_z: v_z, v_prf: v_prf
		};
		return res;
	}
}

