/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 03/11/2023

	Wrapper/driver of RIPP (GIPA) Inner Product Library from arkworks
	This code borrows and adapts MANY code from ripp/ip_proofs/src/applications/groth16_aggregtion.ars
*/

/// See the "Inner Product Pairing and Applications" Paper
/// Wrapper of GIPA (TIPA and MIPPu) related operations
extern crate ark_ec;
extern crate ark_ff;
extern crate ark_ip_proofs; 
extern crate ark_inner_products; 
extern crate ark_dh_commitments; 
extern crate blake2; 
extern crate ark_std;
extern crate ark_serialize;

use self::ark_std::rand::{rngs::StdRng, SeedableRng};
use self::blake2::Blake2b;
use self::ark_ec::{PairingEngine,ProjectiveCurve,AffineCurve};
use self::ark_ff::{PrimeField,Field,One};
use self::ark_ip_proofs::tipa::{
        structured_scalar_message::{structured_scalar_power},
        TIPAProof, SRS, TIPA,
};
use self::ark_dh_commitments::{
	DoublyHomomorphicCommitment,
    afgho16::{AFGHOCommitmentG1, AFGHOCommitmentG2},
    pedersen::PedersenCommitment,
    identity::{HomomorphicPlaceholderValue, IdentityCommitment, IdentityOutput},
};
use self::ark_inner_products::{
    ExtensionFieldElement, InnerProduct, MultiexponentiationInnerProduct, PairingInnerProduct,
};
//use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use proto::ark_ec::msm::VariableBaseMSM;
use tools::*;
use poly::dis_key::*;
use profiler::config::*;
use std::rc::Rc;
//use std::fs;
//use std::{marker::PhantomData, ops::MulAssign};
use std::{ops::MulAssign};
use zkregex::prover::{CRS, zk_setup};
use groth16::dis_prove_key::dis_setup;
use groth16::new_dis_qap::DisQAP;

/// cusotmized TIPA use Blake2b directly
/// P is the Pairing Engine such as Bls12381
pub type MyTIPA<P> = TIPA<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    Blake2b,
>;

pub type MyTIPAProof<P> = TIPAProof<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    Blake2b,
>;

/// MIPP_u (for unknown vector)
// check fn multiexponentiation_inner_product_test() 
// in dependency/ripp/ip_proofs/src/tipp/mod.rs
pub type MyMIPP<P>= TIPA<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    PedersenCommitment<<P as PairingEngine>::G1Projective>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    Blake2b,
>;

pub type MyMIPPProof<P> = TIPAProof<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    PedersenCommitment<<P as PairingEngine>::G1Projective>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    Blake2b,
>;

/// GIPA is a wrapper object of the TIPA, MIPPu functions
/// NOTE: here we took "convenience" of generating g5s and g10s
/// by directly extracting the bases (G1) elements from the ProcessJob
/// Theoretically, the number of bases (for each groth16) should be
/// decided by "statistical" distribution of many runs and set to the
/// UPPER limit of each kind of bases needed for each groth16 system 
/// based on the distribution of file sizes. Then given the real input.
/// typically these arrays will be padded to such UPPER Limit.
/// But in general (in summary), we regard such bases for various
/// Groth16 circuit sizes as FIXED and CONSTANT and can be generated in
/// the set up process.
pub struct GIPA<E:PairingEngine>
where <E as PairingEngine>::G1Projective: VariableBaseMSM<MSMBase=<E as PairingEngine>::G1Affine, Scalar=<E as PairingEngine>::Fr>,
<E as PairingEngine>::G2Projective: VariableBaseMSM<MSMBase=<E as PairingEngine>::G2Affine, Scalar=<E as PairingEngine>::Fr>
{
	// the size of key (the UPPER LIMIT number of proofs to aggregate)
	pub n: usize,
	// structured key
	pub srs: SRS<E>,
	// commitment key for G1 
	pub ck1: Vec<E::G2Projective>,
	// commitment key for G2
	pub ck2: Vec<E::G1Projective>,
	// key for MIPP 
	pub srs_mipp: SRS<E>, 
	// 2nd part of key for MIPP
	pub ck_t: Box<dyn MulAssign<E::Fr>>,
	//ck1 for MIPP
	pub ck1_mipp: Vec<E::G2Projective>,
	//ck2 for MIPP
	pub ck2_mipp: Vec<E::G1Projective>,
	//Commit to [Fr::one(); n]
	pub c_z1: E::G1Projective,
	//Commit to [g; n]
	pub c_vg: ExtensionFieldElement<E>,
	//Commit to [h;n]
	pub c_vh: ExtensionFieldElement<E>,
	//Commit to [gh;n]
	pub c_vgh: ExtensionFieldElement<E>,
	//Commit to [g_alpha;  n]
	pub c_v_g_alpha: ExtensionFieldElement<E>,
	//Commits to g1 in CRS veriifer key (and so on for g5)
	pub c_g1: ExtensionFieldElement<E>,
	//Commits to g2 in CRS veriifer key (and so on for g5)
	pub c_g2: ExtensionFieldElement<E>,
	//Commits to g3 in CRS veriifer key (and so on for g5)
	pub c_g3: ExtensionFieldElement<E>,
	//Commits to g4 in CRS veriifer key (and so on for g5)
	pub c_g4: ExtensionFieldElement<E>,
	//Commits to g5 in CRS veriifer key (and so on for g5)
	pub c_g5: ExtensionFieldElement<E>,
	//Commitments to g1 to g10 for connector proof
	pub vec_c_conn_gs: Vec<ExtensionFieldElement<E>>,
	//Commits to vec of alpha_g1 from crs
	pub c_alpha: ExtensionFieldElement<E>,
	//Commits to vec of beta_g2 from crs
	pub c_beta: ExtensionFieldElement<E>,
	//Commits to vec of gamma_g1 from crs
	pub c_gamma: ExtensionFieldElement<E>,
	//number of segments
	pub num_seg: usize,
	//Vector of commits to delta_g2 (size: num_seg)
	pub v_c_delta_g2: Vec<ExtensionFieldElement<E>>,	
	//commitment of n kzg_all
	pub c_kzg_all: ExtensionFieldElement<E>
}


impl <E:PairingEngine> GIPA<E>
where <E as PairingEngine>::G1Projective: VariableBaseMSM<MSMBase=<E as PairingEngine>::G1Affine, Scalar=<E as PairingEngine>::Fr>,
<E as PairingEngine>::G2Projective: VariableBaseMSM<MSMBase=<E as PairingEngine>::G2Affine, Scalar=<E as PairingEngine>::Fr>{
	/** the vec_g5s is a 2d vec of size n, each elelement is a vec
		of n G1 elements (g1 to g5's taken from CRS for each instance).
		Note: we allow MULTIPLE qap/circ instances, but 
		their order/type should be fixed.
		need the ac_dir (signature dir) for reading the kzg_all
	*/
	pub fn setup(n: usize, sigkey: &Rc<DisKey<E>>, 
		vec_g5s: &Vec<Vec<E::G1Affine>>, vec_crs: &Vec<Rc<CRS<E>>>,
		vec_g10s: &Vec<Vec<E::G1Affine>>, ac_dir: &str) 
		-> Self{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();

		//1. set up the init instance
		assert!(vec_g10s[0].len()==vec_g5s[0].len(), "v10s.len != v5s");
		let seed = 11231271u64;
    	let mut rng = StdRng::seed_from_u64(seed);
		let srs = MyTIPA::<E>::setup(&mut rng, n).unwrap().0;
		let (c1, c2) = srs.get_commitment_keys();

    	let mut rng = StdRng::seed_from_u64(seed); //using the same
		//this same seed ensures c1_mipp and c1 are the SAME
		//so cm1 generates the same
		let (srs_mipp, ck_t) = MyMIPP::<E>::setup(&mut rng, n).unwrap();
		let (c1_mipp, c2_mipp) = srs_mipp.get_commitment_keys();
		assert!(c1==c1_mipp, "c1!=c1mipp!");

		//let np = RUN_CONFIG.my_rank;
		let exf0 = E::Fqk::from(0u32);
		let mut inst = Self{
			n: n,
			srs: srs,
			ck1: c1,
			ck2: c2,
			srs_mipp: srs_mipp,
			ck_t: Box::new(ck_t),
			ck1_mipp: c1_mipp,
			ck2_mipp: c2_mipp,
			c_vgh: ExtensionFieldElement(exf0.clone()),
			c_v_g_alpha: ExtensionFieldElement(exf0.clone()),
			c_z1: sigkey.g.clone(), //change later
			c_vg: ExtensionFieldElement(exf0.clone()), //change later
			c_vh: ExtensionFieldElement(exf0.clone()), //change later
			c_g1: ExtensionFieldElement(exf0.clone()), //change later
			c_g2: ExtensionFieldElement(exf0.clone()), //change later
			c_g3: ExtensionFieldElement(exf0.clone()), //change later
			c_g4: ExtensionFieldElement(exf0.clone()), //change later
			c_g5: ExtensionFieldElement(exf0.clone()), //change later
			c_alpha: ExtensionFieldElement(exf0.clone()), //change later
			c_beta: ExtensionFieldElement(exf0.clone()), //change later
			c_gamma: ExtensionFieldElement(exf0.clone()), //change later
			num_seg: 0, //change later
			v_c_delta_g2: vec![], //change later
			vec_c_conn_gs: vec![], //change later
			c_kzg_all: ExtensionFieldElement(exf0.clone()),
		};

		//2. reset last 3 members
		let h = sigkey.h;
		let g = sigkey.g.into_affine();
		let gh = sigkey.gh;
		let g_alpha = sigkey.g_alpha;
		let v_1 = vec![E::Fr::one(); n];
		let c_z1 = inst.cmz(&v_1);
		let c_vg = inst.cm1(&vec![g.into_projective(); n]);
		let c_vh = inst.cm1(&vec![h.into_projective(); n]);
		let c_vgh = inst.cm1(&vec![gh.into_projective(); n]);
		let c_v_g_alpha= inst.cm1(&vec![g_alpha.into_projective(); n]);
		inst.c_z1 = c_z1;
		inst.c_vg = c_vg;
		inst.c_vh = c_vh;
		inst.c_g1 = inst.cm1(&vec_affine_to_proj::<E>(&vec_g5s[0]));//for g1
		inst.c_g2 = inst.cm1(&vec_affine_to_proj::<E>(&vec_g5s[1]));//for g2
		inst.c_g3 = inst.cm1(&vec_affine_to_proj::<E>(&vec_g5s[2]));//for g3
		inst.c_g4 = inst.cm1(&vec_affine_to_proj::<E>(&vec_g5s[3]));//for g4
		inst.c_g5 = inst.cm1(&vec_affine_to_proj::<E>(&vec_g5s[4]));//for g5
		let mut vec_c_conn_gs = vec![];
		assert!(vec_g10s.len()==10, "vec_g10s len != 10");
		for i in 0..vec_g10s.len(){
			vec_c_conn_gs.push(inst.
				cm1(&vec_affine_to_proj::<E>(&vec_g10s[i])));
		}
		inst.c_vgh = c_vgh;
		inst.c_v_g_alpha= c_v_g_alpha;
		inst.vec_c_conn_gs = vec_c_conn_gs;

		//3. build up the members for groth keys
		let num_seg = vec_crs[0].verifier_key.delta_g2.len();
		let mut vec_alpha = vec![];
		let mut vec_beta = vec![];
		let mut vec_gamma= vec![];
		let mut v2d_delta_g2 = vec![vec![]; num_seg];
		for i in 0..vec_crs.len(){
			let vkey = &vec_crs[i].verifier_key;
			vec_alpha.push(vkey.alpha_g1.clone());
			vec_beta.push(vkey.beta_g2.clone());
			vec_gamma.push(vkey.gamma_g2.clone());
			assert!(num_seg== vkey.delta_g2.len(), "num_seg wrong!");
			for j in 0..num_seg{
				v2d_delta_g2[j].push(vkey.delta_g2[j]);
			}
		}
		inst.c_alpha = inst.cm1(&vec_affine_to_proj::<E>(&vec_alpha));
		inst.c_beta= inst.cm2(&vec_affine2_to_proj::<E>(&vec_beta));
		inst.c_gamma= inst.cm2(&vec_affine2_to_proj::<E>(&vec_gamma));
		inst.v_c_delta_g2 = vec![];
		inst.num_seg = num_seg;
		let kzg_all = read_ge::<E::G1Affine>(&format!("{}/st_kzg.dat", ac_dir));
		let vec_kzg = vec![kzg_all; n];
		inst.c_kzg_all =inst.cm1(&vec_affine_to_proj::<E>(&vec_kzg));
		for i in 0..num_seg{
			inst.v_c_delta_g2.push(
				inst.cm2(&vec_affine2_to_proj::<E>(&v2d_delta_g2[i]))
			);
		}
	
	
		if b_perf {log_perf(LOG1, &format!("GIPA setup: size: {}", n), 
			&mut t1);}
		return inst;
	}

	/// commit vector of G1 elements 
	pub fn cm1(&self, vg1: &Vec<E::G1Projective>) -> ExtensionFieldElement<E>{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let res = PairingInnerProduct::<E>::
				inner_product(&vg1, &self.ck1).unwrap(); 
		if b_perf {log_perf(LOG1, &format!("GIPA cm1: size: {}", vg1.len()), 
&mut t1);}
		return res;
	}

	/// commit vector of G2 elements 
	pub fn cm2(&self, vg2: &Vec<E::G2Projective>) -> ExtensionFieldElement<E>{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let res = PairingInnerProduct::<E>::
				inner_product(&self.ck2, vg2).unwrap(); 
		if b_perf {log_perf(LOG1, &format!("GIPA cm2: size: {}", vg2.len()), 
			&mut t1);}
		return res;
	}

	/// commit to vector of Fr elements
	pub fn cmz(&self, vg: &Vec<E::Fr>) -> E::G1Projective{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let cm = PedersenCommitment::<E::G1Projective>::
			commit(&self.ck2_mipp, vg).unwrap();
		if b_perf {log_perf(LOG1, &format!("GIPA cmz: size: {}", vg.len()), 
			&mut t1);}
		return cm;
	} 

	/// genreate [r^0, ..., r^{n-1}]
	pub fn r_pows(&self, r: E::Fr, n: usize) -> Vec<E::Fr>{
		return structured_scalar_power(n, &r);
	}

	/// return vg1[i]*vexp[i] (treat G1 as additive group)
	pub fn vec_mul(&self, vg1: &Vec<E::G1Projective>, vexp: &Vec<E::Fr>)
		->Vec<E::G1Projective>{
    	let a_r = vg1 
				.iter()
				.zip(vexp)
				.map(|(a, r)| a.mul(r.into_bigint()))
				.collect::<Vec<E::G1Projective>>();
		return a_r;
	}

	/// generate TIPP proof for Zsum = \Sum pair(vg1[i]*r^i , vg2[i]) 
	/// return the (proof , ip_ab = sum (A[i]*r^i, B[i])
	pub fn tipp_prove(&self, vg1: &Vec<E::G1Projective>, vg2: &Vec<E::G2Projective>, r: &E::Fr) -> (MyTIPAProof<E>, ExtensionFieldElement<E>){
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let n = vg1.len();
		assert!(vg2.len()==n, "vg2.len() != n");
		let vec_r = self.r_pows(*r, n);
		let a_r = self.vec_mul(vg1, &vec_r);
    	let ip_ab = PairingInnerProduct::<E>::inner_product(&a_r, &vg2).unwrap();
    	let ck_1_r = self.ck1 .iter() .zip(&vec_r)
        	.map(|(ck, r)| ck.mul(&r.inverse().unwrap().into_bigint()))
        	.collect::<Vec<E::G2Projective>>();
		let prf = MyTIPA::<E>::prove_with_srs_shift(
			&self.srs,
			(&a_r, vg2),
			(&ck_1_r, &self.ck2, &HomomorphicPlaceholderValue),
			&r).unwrap();
		if b_perf {log_perf(LOG1, &format!("TIPP proof: size: {}", vg1.len()), 
			&mut t1);}
		return (prf, ip_ab);	
	}

	/// verify that the A hiding behind com_a and B behind com_b, given
	/// r. \sum pair(A[i]^r^i, B_i) is z_ab
	pub fn tipp_verify(&self, com_a: &ExtensionFieldElement<E>, com_b: &ExtensionFieldElement<E>, r: &E::Fr, z_ab: &ExtensionFieldElement<E>, prf: &MyTIPAProof<E>) -> bool{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let res = MyTIPA::<E>::verify_with_srs_shift(
			&self.srs.get_verifier_key(),
        	&HomomorphicPlaceholderValue,
        	( com_a, com_b, &IdentityOutput(vec![z_ab.clone()])),
        	prf,
        	r,
		).unwrap();
		if b_perf {log_perf(LOG1, &format!("TIPA verify: "), 
			&mut t1);}
		return res;
	}

	/// generate MIPP_u (u stands for unkonwn vector of vg2)
	/// proof for Zsum = \Sum vg1[i]*(r^i + b[i])
	/// return the (proof , Zsum)
	pub fn mipp_prove(&self, vg1: &Vec<E::G1Projective>, vg2: &Vec<E::Fr>, r: &E::Fr) -> (MyMIPPProof<E>, E::G1Projective){
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let n = vg1.len();
		assert!(vg2.len()==n, "vg2.len() != n");
		let vec_r = self.r_pows(*r, n);
		let a_r = self.vec_mul(vg1, &vec_r);
    	let ip_ab = MultiexponentiationInnerProduct::<E::G1Projective>
			::inner_product(&a_r, &vg2).unwrap();
    	let ck_1_r = self.ck1_mipp .iter() .zip(&vec_r)
        	.map(|(ck, r)| ck.mul(&r.inverse().unwrap().into_bigint()))
        	.collect::<Vec<E::G2Projective>>();

        let prf = MyMIPP::prove_with_srs_shift(
			&self.srs_mipp, 
			(&a_r, vg2), 
			(&ck_1_r, &self.ck2_mipp, &HomomorphicPlaceholderValue),
			&r).unwrap();
		if b_perf {log_perf(LOG1, &format!("MIPP_u proof: size: {}", 
			vg1.len()), &mut t1);}
		return (prf, ip_ab);	
	}

	/// verify that the A hiding behind com_a and B behind com_b, given
	/// r. \sum A_i*{B[i]*r^i] is z_ab
	pub fn mipp_verify(&self, com_a: &ExtensionFieldElement<E>, com_b: &E::G1Projective, r: &E::Fr, z_ab: &E::G1Projective, prf: &MyMIPPProof<E>) -> bool{
		let b_perf = false;
		let mut t1 = Timer::new();
		t1.start();
		let res = MyMIPP::<E>::verify_with_srs_shift(
			&self.srs_mipp.get_verifier_key(),
        	&HomomorphicPlaceholderValue,
        	(com_a, com_b, &IdentityOutput(vec![z_ab.clone()])),
        	prf,
        	r,
		).unwrap();
		if b_perf {log_perf(LOG1, &format!("MIPP_u verify: "), 
			&mut t1);}
		return res;
	}
}

/** create a vector of verifier CRS */
pub fn create_vec_crs_verifier<E:PairingEngine>(size: usize)->Vec<Rc<CRS<E>>>
	where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
	<<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{ 
	let np = RUN_CONFIG.n_proc;
	let n = np * 16;
	let degree = n - 2; //degree+2 must be power of 2	
	let num_inputs = 2;
	let num_vars = n;
	let seed = 1122u128;
	let (qap, _qw) = DisQAP::<E::Fr>::rand_inst(seed, num_inputs, num_vars,degree, true);

	let diskey = DisKey::<E>::gen_key1(32); 	
	let (dkey, vkey) = dis_setup(234234234u128, &qap, &diskey);
	let (_, crs_v) = zk_setup(32, Rc::new(dkey), Rc::new(vkey), 2016, 10, &qap);

	let mut vec = vec![];
	let rc_crs = Rc::new(crs_v);
	for _i in 0..size{ vec.push(rc_crs.clone()); }
	return vec;
}

pub fn extract_g5s<E:PairingEngine>(vcrs: &Vec<Rc<CRS<E>>>)
->Vec<Vec<E::G1Affine>>{
	let mut vg1 = vec![];
	for i in 0..vcrs.len(){
		vg1.push(vcrs[i].g1.clone());
	}
	let mut vg2 = vec![];
	for i in 0..vcrs.len(){
		vg2.push(vcrs[i].g2.clone());
	}
	let mut vg3 = vec![];
	for i in 0..vcrs.len(){
		vg3.push(vcrs[i].g3.clone());
	}
	let mut vg4 = vec![];
	for i in 0..vcrs.len(){
		vg4.push(vcrs[i].g4.clone());
	}
	let mut vg5 = vec![];
	for i in 0..vcrs.len(){
		vg5.push(vcrs[i].g5.clone());
	}
	return vec![vg1, vg2, vg3, vg4, vg5];
}



