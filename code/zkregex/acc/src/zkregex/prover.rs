/** 
	Copyright Dr. CorrAuthor
	Author: Dr. CorrAuthor 
	Created: 11/21/2022
	Completed: 11/25/2022
*/

/* ****************************************************************
This file contains prover related function and data structures
NOTE: the prove function is DEPRECATED.
Use BatchProver instead in batch.rs (however, some utility
function in this file are used - DO NOT REMOVE)
--- DEPRECATED but DO NOT REMOVE ---
**************************************************************** */

extern crate ark_ec;
extern crate ark_ff;
extern crate mpi;
extern crate ark_serialize;
use self::ark_ec::{PairingEngine,AffineCurve};
use self::ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::{Field};
use std::rc::Rc;
//use self::mpi::traits::*;
//use self::mpi::environment::*;

use tools::*;
use profiler::config::*;
//use jsnark_driver::r1cs_gen::*;
use poly::dis_key::*;
//use poly::common::*;
//use poly::dis_vec::*;
//use poly::serial::*;
use poly::dis_poly::*;
//use r1cs::dis_r1cs::*;
use proto::*;
//use proto::zk_subset_v2::*;
use proto::zk_subset_v3::*;
use proto::zk_kzg_v2::*;
use proto::zk_kzg::*;
use proto::zk_dlog::*;
//use jsnark_driver::new_r1cs_gen::*;
use groth16::new_dis_qap::*;
use groth16::dis_prove_key::*;
use groth16::serial_prover::*;
use groth16::serial_prove_key::*;
use groth16::verifier::*;

/// contains the Aux info for kzg and suset
#[derive(Clone)]
pub struct ZkregexAux<PE:PairingEngine> where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// aux info of subset1 prf
	pub aux_subset1: ZkSubsetV3Aux<PE>,
	/// aux info of subset2 prf
	pub aux_subset2: ZkSubsetV3Aux<PE>,
	/// aux info of kzg prf
	pub aux_kzg: ZkKZGV2Aux<PE>,
}

impl <E:PairingEngine> ZkregexAux <E> 
where 
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{

	/// serialization
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b1 = self.aux_subset1.to_bytes();
		let mut b2 = self.aux_subset2.to_bytes();
		let mut b3 = self.aux_kzg.to_bytes();
		b1.append(&mut b2);
		b1.append(&mut b3);	
		return b1;
	}

	/// deserialization
	pub fn from_bytes(v: &Vec<u8>)->Self{
		let v1 = &v[..];
		let aux_subset1 = ZkSubsetV3Aux::<E>::from_bytes(&v1.to_vec());
		let size_set1 = aux_subset1.to_bytes().len();
		let v2 = &v[size_set1..];
		let aux_subset2 = ZkSubsetV3Aux::<E>::from_bytes(&v2.to_vec());
		let v3 = &v[2*size_set1..];
		let aux_kzg= ZkKZGV2Aux::<E>::from_bytes(&v3.to_vec());
		let res = ZkregexAux{
			aux_subset1: aux_subset1, 
			aux_subset2: aux_subset2,
			aux_kzg: aux_kzg,
		};
		return res;
	}
	pub fn dummy() -> Self{
		return Self{
			aux_subset1: ZkSubsetV3Aux::<E>::dummy(),
			aux_subset2: ZkSubsetV3Aux::<E>::dummy(),
			aux_kzg: ZkKZGV2Aux::<E>::dummy(),
		}
	}

	pub fn is_dummy(&self) -> bool{
		return self.aux_subset1.is_dummy() &&
		self.aux_subset2.is_dummy() &&
		self.aux_kzg.is_dummy();
	}
}


/** hybrid proof: one sigma and one Groth'16 */
#[derive(Clone)]
pub struct ZkregexProof<PE:PairingEngine> where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	// Groth'16 proof
	pub a: PE::G1Affine,  
	pub b: PE::G2Affine, 
	pub c1: PE::G1Affine,  
	pub c2: PE::G1Affine,  
	pub c3: PE::G1Affine,  

	// Sigma proof
	/** zk-vpd commitment of the selected subset */
	pub c_subset: PE::G1Affine,
	/** zk-vpd of the state and transition set */
	pub c_st: PE::G1Affine,
	/** proof for the c_subset is subset of the entire */
	pub subset1_prf: ZkSubsetV3Proof<PE>,
	/** proof for the c_st is subset of the c_subset*/
	pub subset2_prf: ZkSubsetV3Proof<PE>,
	/** proof for the zk-kzg connecting */
	pub kzg_prf: ZkKZGV2Proof<PE>,
	/** the random nonce used as challenge */
	pub r: PE::Fr,

	/// aux info will be serialized SEPARATELY!
	pub aux: ZkregexAux<PE>
}

impl <PE:PairingEngine> ZkregexProof<PE> where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn save_to(&self, dir: &str){
		log(LOG1, &format!("proof saved to: {}", dir));
		let mut b:Vec<u8> = vec![];
		PE::G1Affine::serialize(&self.a, &mut b).unwrap();
		PE::G2Affine::serialize(&self.b, &mut b).unwrap();
		PE::G1Affine::serialize(&self.c1, &mut b).unwrap();
		PE::G1Affine::serialize(&self.c2, &mut b).unwrap();
		PE::G1Affine::serialize(&self.c3, &mut b).unwrap();
		PE::G1Affine::serialize(&self.c_subset, &mut b).unwrap();
		PE::G1Affine::serialize(&self.c_st, &mut b).unwrap();
		PE::Fr::serialize(&self.r, &mut b).unwrap();
		
		let mut bs1 = self.subset1_prf.to_bytes();
		b.append(&mut bs1);
		let mut bs2 = self.subset2_prf.to_bytes();
		b.append(&mut bs2);
		let mut bs3 = self.kzg_prf.to_bytes();
		b.append(&mut bs3);

		let fname = format!("{}/proof.dat", dir);
		write_vecu8(&b, &fname);	

		//2. save aux info
		assert!(!self.aux.is_dummy(), "ERROR: AUX is dummy!");
		let faux = format!("{}/aux.dat", dir);
		let b2 = self.aux.to_bytes();
		write_vecu8(&b2, &faux);
	}

	pub fn load_from(dir: &str) -> Self{
		let fpath = format!("{}/proof.dat", dir);
		let b = read_vecu8(&fpath);
		let mut b1= &b[..];
		let a = PE::G1Affine::deserialize(&mut b1).unwrap();
		let b = PE::G2Affine::deserialize(&mut b1).unwrap();
		let c1 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let c2 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let c3 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let c_subset = PE::G1Affine::deserialize(&mut b1).unwrap();
		let c_st = PE::G1Affine::deserialize(&mut b1).unwrap();
		let r = PE::Fr::deserialize(&mut b1).unwrap();
		
		let mut subset1_prf = ZkSubsetV3Proof::<PE>::static_from_bytes(
			&b1.to_vec());
		let subsetprf_size = subset1_prf.to_bytes().len();
		let mut b2 = b1[subsetprf_size..].to_vec();
		let mut subset2_prf = ZkSubsetV3Proof::<PE>::static_from_bytes(&mut b2);
		let mut b3 = b2[subsetprf_size..].to_vec();
		let mut kzg_prf = ZkKZGV2Proof::<PE>::static_from_bytes(&mut b3);

		//2. save aux info
		let faux = format!("{}/aux.dat", dir);
		let b2 = read_vecu8(&faux);
		let aux = ZkregexAux::<PE>::from_bytes(&b2);
		subset1_prf.set_aux(aux.aux_subset1.clone());	
		subset2_prf.set_aux(aux.aux_subset2.clone());	
		kzg_prf.set_aux(aux.aux_kzg.clone());	
		assert!(!subset1_prf.aux.is_dummy(), "ERROR subset1 aux is dummy");
		assert!(!subset2_prf.aux.is_dummy(), "ERROR subset2 aux is dummy");
		assert!(!kzg_prf.aux.is_dummy(), "ERROR kzg aux is dummy");
		assert!(!aux.is_dummy(), "ERROR ZkregexAux is dummy");
		let res = Self{
			a: a, b: b, c1: c1, c2: c2, c3: c3, c_subset: c_subset, c_st: c_st, r: r, subset1_prf: *subset1_prf, subset2_prf: *subset2_prf, kzg_prf: *kzg_prf,
aux: aux
		};
		return res;
	}
}

/** claim: a secret file after encryption and hash generates the 
hash in the claim and its final state is in [0..final_max], its
transition/state set is a subset of the given KZG signature of
the AC-DFA automata.

It includes the verification keys
*/
#[derive(Clone)]
pub struct ZkregexClaim<PE:PairingEngine>{
	/** Hash of the encrypted file */
	pub hash: <<PE as PairingEngine>::G1Affine as AffineCurve>::ScalarField,
	/** KZG signature of the entire state + transition set */
	pub kzg_all: PE::G1Affine,	
	
}

impl <PE:PairingEngine> ZkregexClaim<PE> where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn save_to(&self, dir: &str){
		log(LOG1, &format!("claim saved to: {}", dir));
		let mut b:Vec<u8> = vec![];
		PE::Fr::serialize(&self.hash, &mut b).unwrap();
		PE::G1Affine::serialize(&self.kzg_all, &mut b).unwrap();
		let fname = format!("{}/claim.dat", dir);
		write_vecu8(&b, &fname);	
	}

	pub fn load_from(dir: &str) -> Self{
		let b = read_vecu8(&format!("{}/claim.dat", dir));
		let mut b1= &b[..];
		let hash = PE::Fr::deserialize(&mut b1).unwrap();	
		let kzg_all = PE::G1Affine::deserialize(&mut b1).unwrap();	
		let res = Self{
			hash: hash,
			kzg_all: kzg_all,
		};
		return res;
	}
}

/** set up structure */
pub struct CRS<PE:PairingEngine>{
	pub b_prover: bool, //if it is prover CRS
	pub file_size: usize, //file size upper limit -> determines groth key size
	pub subset_id: usize, //the id of the subset of states/trans set to use 
	pub sigma_key: Rc<DisKey<PE>>, //for sigma protocol
	pub prover_key: Rc<DisProverKey<PE>>,			//for groth16 
	pub verifier_key: Rc<VerifierKey<PE>>,		//for groth16
	pub g1: PE::G1Affine, //taken from prover_key.get_g1_key(1,0)
	pub g2: PE::G1Affine, //get_g1_key(1,1)
	pub g3: PE::G1Affine, //get_g1_key(1,2)
	pub g4: PE::G1Affine, //get_g1_key(1,3)
	pub g5: PE::G1Affine, //prover_key.delta_g1[2]]. These are used for zk_same
}

/// convert slice to array of 8 element
fn toa(v: &Vec<u8>) -> [u8; 8]{
	assert!(v.len()==8, "vec2arr8 ERROR len!=8");	
	let mut arr: [u8; 8] = [0u8; 8];
	for i in 0..8{
		arr[i] = v[i];
	}
	return arr;
}


impl <PE:PairingEngine> CRS<PE>{
	/** only VERIFIER instance can be saved 
		the name will be crs_filesize_subsetid.dat
		ONLY saves: verifier_key and
		prover_key (groth16): skip because it's dummy for verifier_CRS
		sigma_key: skip because it can be easily regenerated
	*/
	pub fn save_to(&self, dir: &str){
		assert!(!self.b_prover, "save_to can only be called for VERIFIER crs");
		let fname = format!("{}/crs_{}_{}.dat", dir, 
			self.file_size, self.subset_id);
		let mut b1: Vec<u8> = vec![];
		PE::G1Affine::serialize(&self.g1, &mut b1).unwrap();
		PE::G1Affine::serialize(&self.g2, &mut b1).unwrap();
		PE::G1Affine::serialize(&self.g3, &mut b1).unwrap();
		PE::G1Affine::serialize(&self.g4, &mut b1).unwrap();
		PE::G1Affine::serialize(&self.g5, &mut b1).unwrap();

		let mut bf = self.file_size.to_le_bytes().to_vec();
		let mut bs = self.subset_id.to_le_bytes().to_vec();
		let mut b3 = self.verifier_key.to_bytes();
		let b3_len = b3.len();
		let mut b_b3len = b3_len.to_le_bytes().to_vec();
		assert!(bf.len()==8 && bs.len()==8 && b_b3len.len()==8, "usize serialization len() not right");
		b1.append(&mut bf);
		b1.append(&mut bs);
		b1.append(&mut b_b3len);
		b1.append(&mut b3);
		log(LOG1, &format!("crs saved to: {}, size: {}", &fname, b1.len()));
		write_vecu8(&b1, &fname);	
	}
	/** construct VERIFIER instance */
	pub fn load_from(fpath: &str)->Self{
		let b = read_vecu8(&tos(fpath));
		let mut b1= &b[..];
		let g1 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let g2 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let g3 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let g4 = PE::G1Affine::deserialize(&mut b1).unwrap();
		let g5 = PE::G1Affine::deserialize(&mut b1).unwrap();

		let bf = b1[0..8].to_vec();
		let bs = b1[8..16].to_vec();
		let b_b3len = b1[16..24].to_vec();
		let file_size = usize::from_le_bytes(toa(&bf));
		let subset_id = usize::from_le_bytes(toa(&bs));
		let b3len = usize::from_le_bytes(toa(&b_b3len));
		let b3 = b1[24..24+b3len].to_vec(); 
		let verifier_key = VerifierKey::<PE>::from_bytes(&b3);
		let min_key_size = RUN_CONFIG.n_proc * 1;
		let sigkey = Rc::new(DisKey::<PE>::gen_key1(min_key_size));
		let res = Self{
			b_prover: false,
			file_size: file_size,
			subset_id: subset_id,
			sigma_key: sigkey,
			prover_key: Rc::new( DisProverKey::<PE>::get_dummy() ),
			verifier_key: Rc::new(verifier_key),
			g1: g1,
			g2: g2,
			g3: g3,
			g4: g4,
			g5: g5
		};
		return res;
	}
}

/** generate the setup
	return (crs_prover, crs_verifier)
	file_size is the upper limit of the file size to be supported by the circ.
	subset_id is the id of the subset of state/trans used
 */
pub fn zk_setup<PE:PairingEngine>(n_sigkey_size: usize, pkey: Rc<DisProverKey<PE>>, vkey: Rc<VerifierKey<PE>>, file_size: usize, subset_id: usize, dis_qap: &DisQAP::<PE::Fr>) -> (CRS<PE>, CRS<PE>)
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let key = Rc::new(DisKey::<PE>::gen_key1(n_sigkey_size));
	let min_key_size = RUN_CONFIG.n_proc * 1;
	let key_simple = Rc::new(DisKey::<PE>::gen_key1(min_key_size));
	let pkey_dummy = Rc::new(DisProverKey::<PE>::get_dummy());
	let g1 = pkey.get_g1_key(1, 0, &dis_qap); 
	let g2 = pkey.get_g1_key(1, 1, &dis_qap); 
	let g3 = pkey.get_g1_key(1, 2, &dis_qap); 
	let g4 = pkey.get_g1_key(1, 3, &dis_qap); 
	let g5= pkey.delta_g1[2]; 
	let crs = CRS::<PE>{b_prover: true, sigma_key: key, prover_key: pkey, verifier_key: vkey.clone(), file_size: file_size, subset_id: subset_id, g1: g1, g2: g2, g3: g3, g4: g4, g5: g5};
	let crs_verifier = CRS::<PE>{b_prover: false, sigma_key: key_simple, prover_key: pkey_dummy, verifier_key: vkey, file_size: file_size, subset_id: subset_id,g1: g1, g2: g2, g3: g3, g4: g4, g5: g5};
	return (crs, crs_verifier);
}


/** generate the zero knowledge proof.
	This functio is to be called in MPI mode.
	ac_dir: containing AC-DFA data
	poly_dir: containing polynomial evidence data set
	curve_type: either BN254 or BLS12-381
	subset_id: see paper (a subset of transition set of AC-DFA).
	nodes_file: the list of nodes MPI (the first one must be 
		127.0.0.1)
	REMOVE LATER: the DisPoly in return
 */
pub fn zk_prove<PE:PairingEngine>(_ac_dir: &str, _poly_dir: &str, _subset_id: usize, _setup: &CRS<PE>, _curve_type: &str, _nodes_file: &str, _max_final_states: usize)->(ZkregexProof<PE>, ZkregexClaim<PE>, DisPoly::<PE::Fr>)
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	unimplemented!("ZK PROVE outdated. Call BatchProve");
/*
	log(LOG1, &format!("========================================\n zk_prove v1: ac_dir: {}, poly_dir: {}, subset_id: {}, max_final_states: {}\n ===================================================", ac_dir, poly_dir, subset_id, max_final_states)); 
	if 1>0 {panic!("DEPRECATED. Do not call. Use Batch_prover instead!");}

	//1. run jsnark concurrently and generate distributed R1CS
	let fd_log = &mut new_file_append(&format!("/tmp/dump.txt"));
	let mut timer = Timer::new();
	let mut timer2 = Timer::new();
	timer.start();
	timer2.start();
	let seed = 129234234u128;
	let netarch = get_network_arch(&nodes_file.to_string());
	let (dis_r1cs, dis_inst, _) = gen_dis_r1cs::<PE>(0, ac_dir, poly_dir, curve_type, &netarch, max_final_states, fd_log);	
	log_perf(LOG1, "Step 1: Generating Distributed R1CS.", &mut timer);


	//2. feed distributed R1CS to Groth'16 prover Stage 1, generate
	// the two commitments
	//assert!(dis_r1cs.num_segs==3, "groth16_stage1: dis_r1cs.num_segs!=3!");
	let mut rng = gen_rng_from_seed(seed);
	let t = PE::Fr::rand(&mut rng);
	let dis_qap = dis_r1cs.to_qap(&t);
	let qw = dis_r1cs.to_qap_witness(dis_inst);
	let np = RUN_CONFIG.n_proc;
	let diskey = DisKey::<PE>::gen_key1(32*np); 	 //just a small one
	let (dkey, _vkey) =dis_setup::<PE>(seed, &dis_qap, &diskey); //circuit specific
	let num_segs = dis_qap.num_segs;
	let dprover = DisProver::<PE>::new(num_segs, seed, dis_qap.seg_size.clone());	
	log_perf(LOG1, "Step 2: Key Setup for Groth16.", &mut timer);
	let p1 = dprover.prove_stage1(&dkey, &qw);
	let _io = p1.io;
	let (c1, c2) = (p1.arr_c[0], p1.arr_c[1]);
	log_perf(LOG1, "Step 3: Modified Groth16 Stage 1.", &mut timer);

	//3. hash c1 and c2 -> applying Fiat-Shamir for r
	let vecu8 = to_vecu8(&vec![c1, c2]);
	let r = hash::<PE::Fr>(&vecu8); 
	let r_inv = r.inverse().unwrap();
	let vdata = vec![r, r_inv];
	let mut vu8 = to_vecu8(&vdata);
	let world = RUN_CONFIG.univ.world();
	let root_proc = world.process_at_rank(0);
	root_proc.broadcast_into(&mut vu8);
	let v_r = from_vecu8(&vu8, PE::Fr::zero());
	let r = v_r[0];
	let r_inv = v_r[1];
			

	//4. regenerate the R1CS instance (statement + witness)
	let mut arr_r = read_arr_fe_from(&format!("{}/r.dat", poly_dir)); 
	//r, r_inv, z, r1, r2, key, r, r_inv
	arr_r[0] = r;
	arr_r[1] = r_inv;
	let z = arr_r[2];
	let r1 = arr_r[3];
	let r2 = arr_r[4];
	let _seckey = arr_r[5];
	arr_r[6] = r; //kind of waste 2 elements, improve later (see AccDriver.java)
	arr_r[7] = r_inv; 
	let (_dis_r1cs2, dis_inst2, _) = gen_dis_r1cs::<PE>(0, ac_dir, poly_dir, curve_type, &netarch, max_final_states, fd_log);
	let qw2 = dis_r1cs.to_qap_witness(dis_inst2);
	log_perf(LOG1, "Step 4: Generating QAP again.", &mut timer);

	let p2 = dprover.prove_stage2(&dkey, &qw2);
	let (a,b,c3) = (p2.a, p2.b, p2.last_c);
	let z_g = dkey.get_g1_key(1, 0, &dis_qap); //z's key
	let z_h = dkey.get_g1_key(1, 1, &dis_qap); //r2's key
	let delta_k = dkey.delta_g1[num_segs-1]; 
	let ri_1 = dprover.r_i[1]; //used as the part2 in prove_stage1 for seg #1
	log_perf(LOG1, "Step 5: Groth16 Stage 2", &mut timer);


	//REMOVE LATER -------
	//let p1_2 = dprover.prove_stage1(&dkey, &qw2);
	//let (c1_2, c2_2) = (p1_2.arr_c[0], p1_2.arr_c[1]);
	//assert!(c1==c1_2, "c1!=c1_2");
	//assert!(c2==c2_2, "c2!=c2_2");
	//REMOVE LATER ------- ABOVE
	

	//5. generate the 1st subset proof (subset_id \subset TOTAL)
	let gamma = PE::Fr::rand(&mut rng);
	let (prf_subset1, claim_subset1) = build_subset1_proof::<PE>(ac_dir, subset_id, &setup.sigma_key, gamma, r1); 
	log_perf(LOG1, "Step 6: build_subset_proof1.", &mut timer);

	//6. generate the 2nd subset proof (trace set \subset subset_id)
	let (prf_subset2, claim_subset2, dp_st, s2_gamma, s2_r1) = build_subset2_proof::<PE>(ac_dir, subset_id, poly_dir, &setup.sigma_key, gamma, r1); 
	let dp_st2 = dp_st.clone();
	log_perf(LOG1, "Step 7: build_subset_proof2.", &mut timer);
	if RUN_CONFIG.my_rank==0{
		assert!(claim_subset1.kzg_subset==claim_subset2.kzg_superset, "!subset1.subset==subset2.superset!");
	}

	//7. generate the blindeval proof
	let (prf_kzg, claim_kzg) = build_blindeval_proof::<PE>(dp_st, &setup.sigma_key, &claim_subset2, s2_gamma, s2_r1, r, z, r2, z_g, z_h); 
	log_perf(LOG1, "Step 8: blindeval proof.", &mut timer);
	if RUN_CONFIG.my_rank==0{
		assert!(claim_subset2.kzg_subset==claim_kzg.c_p, "!subset2.subset==blindeval.cp!");
	}

	//8. create the DLOG proof for delta_k^r1_1
	let (prf_dlog, _claim_dlog) = build_dlog_proof(&setup.sigma_key, delta_k, ri_1);
	log_perf(LOG1, "Step 9: DLOG proof", &mut timer);

	//8. assembly proof
	let id = 0usize;
	let prf = ZkregexProof::<PE>{
		id: id,
		kzg_subset: claim_subset2.kzg_superset,
		comm_subset_nonce: claim_subset2.comm_eta,
		kzg_st: claim_subset2.kzg_subset, 
		comm_st_nonce: claim_subset2.comm_gamma,
		subset1_prf: prf_subset1,
		subset2_prf: prf_subset2,
		blindeval_prf: prf_kzg, 
		ddlog_proof: prf_dlog,
		io: vec![], //INVALID - didn't refinedidn't refine  this function is not used anymore
		a: a,
		b: b,
		c1: c1,
		c2: c2,
		c3: c3
	};
	let claim = ZkregexClaim::<PE>{
		id: id,
		kzg_all: claim_subset1.kzg_superset,
	};
	timer2.stop();
	if RUN_CONFIG.my_rank==0{
		println!(" ***** ZK PROVE DONE! ******. Total: {} ms. Node: {}", timer2.time_us/1000, RUN_CONFIG.my_rank);
	}
	return (prf, claim, dp_st2);
*/
}

/**
  Given the Claim: hash of the encrypted file, and bilinear accumulator
	of all, verify that the hidden file is malware free (a member
		of the language defined by the AC-DFA encoded)
*/
pub fn zk_verify<PE:PairingEngine>(claim: &ZkregexClaim<PE>, prf: &ZkregexProof<PE>, crs: &CRS<PE>)-> bool
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = false;
	let b_debug = false;
	let key = &crs.sigma_key;
	//let zero = PE::Fr::zero();
	//let one = key.g.into_affine().mul(zero).into_affine();
	let mut t1= Timer::new();
	let mut t2= Timer::new();
	t1.start();
	t2.start();
	//1. verify stage 1 and stage 2
	let one = PE::Fr::from(1u32);
	let r = prf.r;
	let r_inv = r.inverse().unwrap();
	let io = vec![one, claim.hash, r, r_inv];
	let p1 = ProofPart1::<PE>{arr_c: vec![prf.c1], io: io.clone()}; 
	let p2 = ProofPart2::<PE>{a: prf.a, b: prf.b, last_c: prf.c3, io:io, arr_c: vec![prf.c2]};
	let b_groth = verify(&p1, &p2, &crs.verifier_key);
	if b_debug && !b_groth {log(LOG1, &tos("ZkVerify: WARN: Groth16 Failed"));}
	if b_perf {log_perf(LOG1, "PERF_USE_ZkVerify Step1: Groth16", &mut t1);}

	//2. verify that the r is the hash of (c_st, c1)
	let vecu8 = to_vecu8(&vec![prf.c_st, prf.c1]);
	let expected_r = hash::<PE::Fr>(&vecu8); 
	let b_hash = expected_r==prf.r;
	if b_debug && !b_hash {log(LOG1, &tos("ZkVerify: WARN: Check Hash "));}
	if b_perf {log_perf(LOG1, "PERF_USE_Verify_IO2_HASH", &mut t1);}

	//3. verify subset1 proof
	let subset1_claim = ZkSubsetV3Claim::<PE>{
		c_p: claim.kzg_all,
		c_q: prf.c_subset,
	};
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	let b_subset1 = zk.verify(&subset1_claim, &prf.subset1_prf);
	if b_debug && !b_subset1{log(LOG1, &tos("ZkVerify: WARN: subset1 fails"));}
	if b_perf {log_perf(LOG1, "PERF_USE_Verify_Subset1", &mut t1);}

	let subset2_claim = ZkSubsetV3Claim::<PE>{
		c_p: prf.c_subset,
		c_q: prf.c_st,
	};
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	let b_subset2 = zk.verify(&subset2_claim, &prf.subset2_prf);
	if b_debug && !b_subset2{log(LOG1, &tos("ZkVerify: WARN: subset2 fails"));}
	if b_perf {log_perf(LOG1, "PERF_USE_Verify_Subset2", &mut t1);}

	//5. verify zk_kzg
	let kzg_claim = ZkKZGV2Claim::<PE>{
		c_p : prf.c_st,
		c_z: prf.c2,
		r: prf.r,
		g1: crs.g1,
		g2: crs.g2,
		g3: crs.g3,
		g4: crs.g4,
		g5: crs.g5 
	};
	let zk = ZkKZGV2::<PE>::new(key.clone());
	let b_kzg = zk.verify(&kzg_claim, &prf.kzg_prf);
	if b_debug && !b_kzg{log(LOG1, &tos("ZKVerify: WARN KZG fails"));}
	if b_perf {log_perf(LOG1, "PERF_USE_Verify_KZG", &mut t1);}
	if b_perf {log_perf(LOG1, "PERF_USE_ZKVERIFY_TOTAL", &mut t2);}

	let bres = b_groth && b_subset1 && b_subset2 && b_hash && b_kzg; 
	return bres;

}

// --------------------------------------------------------------
//  *** Utility Functions Below ***********
// --------------------------------------------------------------


/** build the first subset proof: the indicated subset_i is a subset of
the total subset of all transitions+states */
pub fn build_subset1_proof<PE:PairingEngine>(_ac_dir: &str, _subset_id: usize, _key: &Rc<DisKey<PE>>, _r_q: PE::Fr, _r1: PE::Fr) -> (ZkSubsetV3Proof<PE>, ZkSubsetV3Claim<PE>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	unimplemented!("OUT DATED. use gen_subset_prf1() in BatchProver");
/*
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	let sdir = format!("{}/subset_{}", ac_dir, subset_id);
	let me = RUN_CONFIG.my_rank;
	let exp_size = PE::G1Affine::zero().uncompressed_size()* 4 + PE::G2Affine::zero().uncompressed_size() * 1;
	let mut barr:Vec<u8> = vec![0u8; exp_size];
	if me==0{
		barr = vec![];
		let g_superset = read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", ac_dir));
		let g_subset = read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", sdir));
		let g_subset_beta = read_ge::<PE::G1Affine>(&format!("{}/st_kzg_beta.dat", sdir));
		let g_wit= read_ge::<PE::G1Affine>(&format!("{}/st_proof.dat", sdir));
		let g_wit_beta= read_ge::<PE::G1Affine>(&format!("{}/st_proof_beta.dat", sdir));
		let g_wit_g2 = read_ge::<PE::G2Affine>(&format!("{}/st_proof_g2.dat", sdir));
		PE::G1Affine::serialize(&g_superset, &mut barr).unwrap();
		PE::G1Affine::serialize(&g_subset, &mut barr).unwrap();
		PE::G1Affine::serialize(&g_subset_beta, &mut barr).unwrap();
		PE::G1Affine::serialize(&g_wit, &mut barr).unwrap();
		PE::G1Affine::serialize(&g_wit_beta, &mut barr).unwrap();
		PE::G2Affine::serialize(&g_wit_g2, &mut barr).unwrap();
	}
	let world = RUN_CONFIG.univ.world();
	let sender_proc = world.process_at_rank(0);
	sender_proc.broadcast_into(&mut barr);
	let mut v2 = &barr[..];
	let g_superset = PE::G1Affine::deserialize(&mut v2).unwrap();		
	let g_subset= PE::G1Affine::deserialize(&mut v2).unwrap();		
	let g_subset_beta= PE::G1Affine::deserialize(&mut v2).unwrap();		
	let g_wit= PE::G1Affine::deserialize(&mut v2).unwrap();		
	let g_wit_beta= PE::G1Affine::deserialize(&mut v2).unwrap();		
	let g_wit_g2= PE::G2Affine::deserialize(&mut v2).unwrap();		


	let seed = 123321u64;
	let mut rng = gen_rng_from_seed(seed);
	let r_w = PE::Fr::rand(&mut rng); 
	let prf = zk.shortcut_prove(g_subset, g_subset_beta,
		g_wit, g_wit_beta, g_wit_g2, r_q, r_w).as_any().
		downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap().clone();
	let claim = zk.shortcut_claim(g_superset, g_subset, gamma, eta, r0, r1).
		as_any().downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap().clone();
	RUN_CONFIG.better_barrier("wait for proof generation");
	let bres = zk.verify(&claim, &prf);
	if RUN_CONFIG.my_rank==0 {assert!(bres, "1st subset proof failed");}
	return (prf, claim);	
*/
}


/** build the 2nd subset proof: acceptance path set +transition set 
belongs to subset claimed */
pub fn build_subset2_proof<PE:PairingEngine>(_ac_dir: &str, _subset_id: usize,_poly_dir: &str, _key: &Rc<DisKey<PE>>, _eta: PE::Fr, _r0: PE::Fr) -> (ZkSubsetV3Proof<PE>, ZkSubsetV3Claim<PE>, DisPoly<PE::Fr>, PE::Fr, PE::Fr) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	unimplemented!("OUTDATED. call gen_subset2_proof in BatchProver");
	/*
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	let supfile= format!("{}/subset_{}/st_coefs.dat", ac_dir, subset_id);
	let states_file= format!("{}/witness/S_P_GCD", poly_dir);
	let trans_file= format!("{}/witness/T_P_GCD", poly_dir);
	let zero = PE::Fr::zero();
	let mut dp_superset = DisPoly::<PE::Fr>::single_from_vec(0, 0, &vec![zero]);
	let mut dp_states= DisPoly::<PE::Fr>::single_from_vec(0, 0, &vec![zero]);
	let mut dp_trans= DisPoly::<PE::Fr>::single_from_vec(0, 0, &vec![zero]);
	dp_superset.read_coefs_from_file_new(&supfile);
	dp_states.read_coefs_from_file_new(&states_file);
	dp_trans.read_coefs_from_file_new(&trans_file);


	dp_states.dvec.set_real_len();
	dp_trans.dvec.set_real_len();

	let mut dp_subset = DisPoly::<PE::Fr>::mul(&mut dp_states, &mut dp_trans);
	dp_subset.dvec.set_real_len();
	if !dp_subset.dvec.b_in_cluster{
		dp_subset.dvec.to_partitions(&RUN_CONFIG.univ);
	}
	let g_subset = key.gen_kzg(&mut dp_subset)[0];
	let mut rng = gen_rng();
	let r1 = PE::Fr::rand(&mut rng);
	let gamma = PE::Fr::rand(&mut rng);
	let dp_st = dp_subset.clone();


	let mut inp:ZkSubsetV3Input<PE> = ZkSubsetV3Input{
		p: dp_superset, q: dp_subset, r_q: gamma, r_p: eta};

	let prf = zk.prove(&mut inp).
		as_any().downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap().clone();
	let sdir = format!("{}/subset_{}", ac_dir, subset_id);
	let me = RUN_CONFIG.my_rank;
	let exp_size = PE::G1Affine::zero().uncompressed_size();
	let mut barr:Vec<u8> = vec![0u8; exp_size];
	if me==0{
		barr = vec![];
		let g_superset = read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", sdir));
		PE::G1Affine::serialize(&g_superset, &mut barr).unwrap();
	}
	let world = RUN_CONFIG.univ.world();
	let sender_proc = world.process_at_rank(0);
	sender_proc.broadcast_into(&mut barr);
	let mut v2 = &barr[..];
	let g_superset = PE::G1Affine::deserialize(&mut v2).unwrap();		



	let claim = zk.shortcut_claim(g_superset, g_subset, gamma, eta, r0, r1).
		as_any().downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap().clone();
	let bres = zk.verify(&claim, &prf);
	assert!(bres, "2nd subset proof failed");
	RUN_CONFIG.better_barrier("subset2 proof");
	return (prf, claim, dp_st, gamma, r1);
	*/
}

/** build the blindeval proof: acceptance path set +transition set 
belongs to subset claimed
	all parameters are the ones needed for generating proof
	check src/proto/zk_kzg.rs for details.
 */
pub fn build_blindeval_proof<PE:PairingEngine>(_dp_subset: DisPoly<PE::Fr>, _key: &Rc<DisKey<PE>>, _claim_subset: &ZkSubsetV3Claim<PE>, _gamma: PE::Fr, _r1: PE::Fr, _r: PE::Fr, _z: PE::Fr, _r2: PE::Fr, _z_g: PE::G1Affine, _z_h: PE::G1Affine) -> (ZkKZGProof<PE>, ZkKZGClaim<PE>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	unimplemented!("buidl_blindeval_proof NOT DONE YET");
/*
	let zk = ZkKZG::<PE>{key: key.clone(), z_g: z_g, z_h: z_h};

	//1. generate proof
	let mut inp:ZkKZGInput<PE> = ZkKZGInput{
		p: dp_subset.clone(), gamma: gamma, r1: r1, r: r, z: z, r2: r2
	};
	let prf = zk.prove(&mut inp).
		as_any().downcast_ref::<ZkKZGProof<PE>>().unwrap().clone();

	//2. generate the claim
	let c_p = claim_subset.kzg_subset;
	let c_gamma = claim_subset.comm_gamma;
	let c_z= z_g.mul(z) + z_h.mul(r2);
	let o = z + dp_subset.eval(&r); 
	let claim = ZkKZGClaim::<PE>{c_p: c_p, c_gamma: c_gamma,
			c_z: c_z.into_affine(), o: o, r: r};


	let bres = zk.verify(&claim, &prf);
	assert!(bres, "blindeval proof failed");
	RUN_CONFIG.better_barrier("blindeval proof");
	return (prf, claim);	
*/
}

/// build the proof for y = g^x
pub fn build_dlog_proof<PE:PairingEngine>(key: &Rc<DisKey<PE>>, g:PE::G1Affine, x: PE::Fr) -> (ZkDLOGProof<PE::G1Affine>, ZkDLOGClaim<PE::G1Affine>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let zk = ZkDLOG::<PE,PE::G1Affine>::new_with_base(g, key.clone());

	//1. generate proof
	let mut inp:ZkDLOGInput<PE::G1Affine> = ZkDLOGInput{ g: g, x: x };
	let prf = zk.prove(&mut inp).
		as_any().downcast_ref::<ZkDLOGProof<PE::G1Affine>>().unwrap().clone();
	let claim =zk.claim(&mut inp);
	let dclaim = claim.as_any().downcast_ref::<ZkDLOGClaim<PE::G1Affine>>().unwrap().clone();

	let bres = zk.verify(&dclaim, &prf);
	assert!(bres, "DLOG proof failed");
	RUN_CONFIG.better_barrier("DLOG proof");
	return (prf, dclaim);	
}
