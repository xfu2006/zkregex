/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 02/2022
	Revised: 08/23/2022: Added functions for publisher

	This is the main commnd line console file for processing various 
application senarios (profiling, publisher, prover, verifier etc.)
*/
extern crate acc;
extern crate ark_ff;
extern crate ark_ec;
extern crate ark_poly;
extern crate ark_std;
extern crate ark_bls12_381;
extern crate ark_serialize;
extern crate ark_bn254;
extern crate mpi;

#[cfg(feature = "parallel")]
use self::ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::env;


//use self::mpi::traits::*;
use ark_ec::bls12::Bls12;
use ark_ec::ProjectiveCurve;

use acc::profiler::config::*;
use acc::profiler::profile_pairing::*;
use acc::profiler::profile_fft::*;
use acc::profiler::profile_poly::*;
use acc::profiler::profile_proto::*;
use acc::profiler::profile_r1cs::*;
use acc::profiler::profile_groth16::*;
use acc::profiler::profile_group::*;
use acc::poly::dis_poly::*;
use acc::poly::group_dis_vec::*;
use acc::poly::dis_vec::*;
use acc::poly::serial::*;
use acc::proto::*;
use acc::proto::zk_subset_v3::*;
use acc::proto::zk_kzg_v2::*;
use acc::proto::proto_tests::{get_max_test_size_for_key};
use acc::proto::nonzk_sigma::*;
use acc::circwitness::serial_circ_gen::*;
use acc::circwitness::modular_circ_gen::*;
use acc::groth16::dis_prover::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
//use acc::groth16::common::*;
use acc::groth16::verifier::*;
use acc::groth16::aggregate::*;
use acc::groth16::dis_prove_key::*;
use acc::groth16::new_dis_qap::*;
use acc::zkregex::prover::*;
use acc::zkregex::batch_prover::*;
//use acc::jsnark_driver::new_jd_tools::*;
use acc::poly::common::*;
use acc::proto::ripp_driver::*;
use acc::zkregex::aggregate::*;

extern crate once_cell;
use std::rc::Rc;
//use std::borrow::Borrow;

use self::ark_ec::{PairingEngine};
use self::ark_ff::{PrimeField,UniformRand,to_bytes};


//use acc::poly::disfft::*;
use ark_ff::{Zero};
use acc::poly::dis_key::*;
//use acc::poly::serial::*;
use acc::tools::*;
use std::marker::PhantomData;
use self::ark_ec::{AffineCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_poly::Polynomial;
//use self::ark_poly::{EvaluationDomain};

use self::ark_bn254::Bn254;
type Fr = ark_bn254::Fr;
type PE= Bn254;
use self::ark_bls12_381::Bls12_381;
//use acc::proto::ripp_driver::*;

type Fr381=ark_bls12_381::Fr;
type PE381=Bls12_381;

/// just to use some of the definitions if some code is commented out
fn phantom_func(){
	let _d1: PhantomData<Fr381>;
	let _d2: PhantomData<PE381>;
}

/// DON'T call this function. compiling purpose
fn fake_profile(){//just to include ALL, don't call it. call profile()!
	let size = 1024*1024*32;
	profile_dis_vec(size, &RUN_CONFIG);
	profile_serial_fft(size, &RUN_CONFIG);
	profile_serial_dizk_fft(size, &RUN_CONFIG);
	profile_dis_dizk_fft(size, &RUN_CONFIG);

	let root_size = 1024*1024;
	profile_serial_build_poly_from_roots(root_size, &RUN_CONFIG);
	profile_dist_build_poly_from_roots(root_size, &RUN_CONFIG);
	profile_dis_feea(root_size, &RUN_CONFIG);

	let poly_size = 1024*1024;
	profile_key_and_eval(poly_size, &RUN_CONFIG);

	//profile_small_mul(10, &RUN_CONFIG);
	let mut poly_size= 1024*1024;
	for _i in 0..1{
		//profile_serial_div(poly_size, &RUN_CONFIG);
		profile_hgcd(poly_size, &RUN_CONFIG);
		poly_size *= 2;
	}

	let size = 1024;
	profile_pairing::<PE>("BN254", size, &RUN_CONFIG);
	profile_pairing::<PE381>("BLS12-381", size, &RUN_CONFIG);

	let size = 1024*32;
	profile_r1cs_serialization(size);
	profile_matrix_to_qap(size);
	profile_compute_witness_h(size);
	profile_make_even(size);
	profile_dis_eval_matrix(size);
	profile_dis_compute_h(size);
	profile_dis_gen_r1cs(size);
	profile_dis_to_qap(size);
	let size = 1024*32;
	profile_all_protos(size, &RUN_CONFIG);
	//profile_groth16(size);
	profile_dis_groth16(size);
}

fn debug_aggregate_subset(){
	let n = 32;
	log(LOG1, &format!("==== debug aggregate_subset prfs size: {} ======", n));
	//let job_list = create_job_list("./batchscripts/results");
	//for x in job_list{
	//	log(LOG1, &format!("{}", x.to_string()));
	//}
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let key_size = if np<16 {32} else {np*16};
	let key = Rc::new(DisKey::<PE381>::gen_key1(key_size));
	let seed = 13214u128;
	let size = get_max_test_size_for_key(&key);
	let proto = ZkSubsetV3::<PE381>::new(key.clone());
	let mut claims:Vec<ZkSubsetV3Claim<PE381>> = vec![];
	let mut prfs:Vec<ZkSubsetV3Proof<PE381>> = vec![];
	let vec_crs = create_vec_crs_verifier::<PE381>(n);
	let g5s = extract_g5s(&vec_crs);
	let g10s = vec![vec![key.g.into_affine(); g5s[0].len()]; 10];
	let ac_dir = "../DATA/anti_virus_output/clamav_100"; 
	let gipa = GIPA::<PE381>::setup(n, &key, &g5s, &vec_crs, &g10s, ac_dir);
	for i in 0..n{
		let (_proto, _inp, cl, pr)= proto.rand_inst(
			size,seed + i as u128 ,false, key.clone()); //no err injected 
		let claim=cl.as_any().
			downcast_ref::<ZkSubsetV3Claim<PE381>>().unwrap(); 
		let proof=pr.as_any().
			downcast_ref::<ZkSubsetV3Proof<PE381>>().unwrap(); 
		let c2 = claim.clone();
		claims.push(c2);
		let p2 = proof.clone();
		prfs.push(p2);
	}
	let (c_claim, c_prf) = ZkSubsetV3::<PE381>::
		agg_prove(&claims, &prfs, &gipa, &key);

	let mut bclaim = c_claim.to_bytes();
	let c_claim2 = ZkSubsetV3AggClaim::<PE381>::from_bytes(&mut bclaim);
	let mut bprf = c_prf.to_bytes();
	log(LOG1, &format!("claim: {}bytes, prf: {}bytes",bclaim.len(),bprf.len()));
	let mut c_prf2 = ZkSubsetV3AggProof::<PE381>::from_bytes(&mut bprf, &gipa);	
	let bres = ZkSubsetV3::<PE381>::
		agg_verify(&c_claim2, &c_prf2, &gipa, &key);
	if me==0 {assert!(bres, "aggregate prf of ZkSubsetV3 failed");}
}

fn debug_aggregate_kzg(){
	let n = 32;
	log(LOG1, &format!("======= debug aggregate kzg size: {} =========", n));
	//let job_list = create_job_list("./batchscripts/results");
	//for x in job_list{
	//	log(LOG1, &format!("{}", x.to_string()));
	//}
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let key_size = if np<16 {32} else {np*16};
	let key = Rc::new(DisKey::<PE381>::gen_key1(key_size));
	let seed = 13214u128;
	let size = get_max_test_size_for_key(&key);
	let proto = ZkKZGV2::<PE381>::new(key.clone());
	let mut claims:Vec<ZkKZGV2Claim<PE381>> = vec![];
	let mut prfs:Vec<ZkKZGV2Proof<PE381>> = vec![];
	let vec_crs = create_vec_crs_verifier::<PE381>(n);
	let g5s = extract_g5s(&vec_crs);
	let g10s = vec![vec![key.g.into_affine(); g5s[0].len()]; 10];
	let ac_dir = "../DATA/anti_virus_output/clamav_100"; 
	let gipa = GIPA::<PE381>::setup(n, &key, &g5s, &vec_crs, &g10s, ac_dir);
	for i in 0..n{
		let mut g5 = vec![];
		for j in 0..5 {g5.push(g5s[j][i].clone());}
		let (_proto, _inp, cl, pr)= proto.rand_inst_adv(
			size,seed + i as u128 ,false, key.clone(), &g5); //no err injected 
		let claim=cl.as_any().
			downcast_ref::<ZkKZGV2Claim<PE381>>().unwrap(); 
		let proof=pr.as_any().
			downcast_ref::<ZkKZGV2Proof<PE381>>().unwrap(); 
		let c2 = claim.clone();
		claims.push(c2);
		let p2 = proof.clone();
		prfs.push(p2);
	}
	let (c_claim,c_prf) = ZkKZGV2::<PE381>::
		agg_prove(&claims, &prfs, &gipa, &key);

	let mut bclaim = c_claim.to_bytes();
	let c_claim2 = ZkKZGV2AggClaim::<PE381>::from_bytes(&mut bclaim);
	let mut bprf = c_prf.to_bytes();
	log(LOG1, &format!("claim: {}bytes, prf: {}bytes",bclaim.len(),bprf.len()));
	let mut c_prf2 = ZkKZGV2AggProof::<PE381>::from_bytes(&mut bprf, &gipa);	
	let bres = ZkKZGV2::<PE381>::
		agg_verify(&c_claim2, &c_prf2, &gipa, &key);
	if me==0 {assert!(bres, "aggregate prf of ZkKZGV2 failed");}
}

fn debug_aggregate_groth16(){
	let n_prfs = 32;
	log(LOG1, &format!("==== debug agg groth16 prfs size: {} =====", n_prfs));
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let key_size = if np<16 {32} else {np*16};
	let key = Rc::new(DisKey::<PE381>::gen_key1(key_size));
        let n = get_min_test_size().next_power_of_two()*64;
	let degree = n - 2; //degree+2 must be power of 2	
	let num_inputs = 2;
	let num_vars = n;
	let seed = 1122u128;
        let (qap, qw) = DisQAP::<Fr381>::
		rand_inst(seed, num_inputs, num_vars,degree, true);
	let num_segs = qap.num_segs;
	let b_sat = qap.is_satisfied(&qw);
	if me==0 {assert!(b_sat, "qap is NOT satisfied");}

	let prover = DisProver::<PE381>
			::new(num_segs, seed, qap.seg_size.clone());
	let diskey = DisKey::<PE381>::gen_key1(32); 	
	let (dkey, vkey) = dis_setup(234234234u128, &qap, &diskey);
	let p1 = prover.prove_stage1(&dkey, &qw, 2);
	let p2 = prover.prove_stage2(&dkey, &qw, 2);
	let bres = verify::<PE381>(&p1, &p2, &vkey);
	if me==0 {assert!(bres, "instance self-check failed");}

	let file_size = 2016; //dummy params
	let subset_id = 10; //dummy params 
	let (_, crs_v) = zk_setup(32, Rc::new(dkey), Rc::new(vkey), file_size, 
		subset_id, &qap);
	let mut v_prf1 = vec![];
	let mut v_prf2 = vec![];
	let mut vec_crs = vec![];
	let r_crs_v = Rc::new(crs_v);
	for _i in 0..n_prfs{
		v_prf1.push(p1.clone());
		v_prf2.push(p2.clone());
		vec_crs.push(r_crs_v.clone());
	}
	let g5s = extract_g5s(&vec_crs);
	let g10s = vec![vec![key.g.into_affine(); g5s[0].len()]; 10];
	let ac_dir = "../DATA/anti_virus_output/clamav_100"; 
	let gipa = GIPA::<PE381>::setup(n_prfs, &key, &g5s, &vec_crs, &g10s, ac_dir);
	let (c_claim, c_prf) = 
		groth16_agg_prove::<PE381>(&v_prf1, &v_prf2, &gipa, &vec_crs);

	let mut bclaim = c_claim.to_bytes();
	let c_claim2 = Groth16AggClaim::<PE381>::from_bytes(&mut bclaim);
	let mut bprf = c_prf.to_bytes();
	log(LOG1, &format!("Groth16 AGG claim: {}bytes, prf: {}bytes",bclaim.len(),bprf.len()));
	let mut c_prf2 = Groth16AggProof::<PE381>::from_bytes(&mut bprf, &gipa);	
	let bres = groth16_agg_verify::<PE381>(&c_claim2, &c_prf2, &gipa);
	if me==0 {assert!(bres, "aggregate prf of Groth16 failed");}
}


fn debug_vanish(){
	let seed = 123123u128;
	let mut rng = gen_rng_from_seed(seed);
	let r = Fr381::rand(&mut rng);
	log(LOG1, &format!("r is: {}", r));
	let myset:Vec<u64> = vec![729234, 234234234, 98234234234, 3723423423,23232323,4343434322222,123123123123,2339999];
	log(LOG1, &format!("vec is: {:?}", myset));
	let mut myset2 = vec![];
	for x in myset{
		myset2.push( Fr381::from(x) );
	}
	let p1 = DisPoly::<Fr381>::binacc_poly(&myset2);
	let dp = DisPoly::<Fr381>::from_serial(0, &p1 ,p1.degree()+1);
	let v = dp.eval(&r);
	log(LOG1, &format!("v is {}: ", v));
}

fn debug_ripp(){
	//let me = RUN_CONFIG.my_rank;
	log(LOG1, &format!("=== DEBUG RIPP DRIVER version 2==="));
	let n = 16usize;
	let np = RUN_CONFIG.n_proc;
	let key_size = if np<16 {32} else {np*16};
	let key = Rc::new(DisKey::<PE381>::gen_key1(key_size));
	let vec_crs = create_vec_crs_verifier::<PE381>(n);
	let g5s = extract_g5s(&vec_crs);
	let g10s = vec![vec![key.g.into_affine(); g5s[0].len()]; 10];
	let ac_dir = "../DATA/anti_virus_output/clamav_100"; 
	let gipa = GIPA::<PE381>::setup(n, &key, &g5s, &vec_crs, &g10s, ac_dir);
	let alpha1 = <PE381 as PairingEngine>::Fr::from(98123123u64);
	let beta = <PE381 as PairingEngine>::Fr::from(12312312u64);
	let alpha2 = <PE381 as PairingEngine>::Fr::from(23209234u64);
	let g1 = <PE381 as PairingEngine>::G1Affine::prime_subgroup_generator();
	let g2 = <PE381 as PairingEngine>::G2Affine::prime_subgroup_generator();
	let base = 35;
	let vg1:Vec<<PE381 as PairingEngine>::G1Projective> 
		= gen_powers::<PE381>(g1.into(), alpha1, beta, base, n)
			.into_iter().map(|v| v.into_projective()).collect();
	let vg2:Vec<<PE381 as PairingEngine>::G2Projective> 
		= gen_powers_g2::<PE381>(g2.into(), alpha2, beta, base, n)
			.into_iter().map(|v| v.into_projective()).collect();
	let r = <PE381 as PairingEngine>::Fr::from(982734u64);
	let (prf, z_ab) = gipa.tipp_prove(&vg1, &vg2, &r);
	let cm_a = gipa.cm1(&vg1);
	let cm_b = gipa.cm2(&vg2);
	let bres = gipa.tipp_verify(&cm_a, &cm_b, &r, &z_ab, &prf);
	assert!(bres, "gipa_tipp failed!");

	let vg3 = rand_arr_field_ele::<<PE381 as PairingEngine>::Fr>(n, 123123u128);
	let cm_c = gipa.cmz(&vg3);
	let (prf2, z_ac) = gipa.mipp_prove(&vg1, &vg3, &r);
	let bres2 = gipa.mipp_verify(&cm_a, &cm_c, &r, &z_ac, &prf2);
	assert!(bres2, "gipa_mipp failed v2!");

	//----- DEBUG serialization --------
	let me = RUN_CONFIG.my_rank;
	let mut arrb= vec![];
	MyMIPPProof::<PE381>::serialize(&prf2, &mut arrb).unwrap();
	let mut b1 = &arrb[..];
	let prf2_2 = MyMIPPProof::<PE381>::deserialize(&mut b1).unwrap();
	let bres2_2 = gipa.mipp_verify(&cm_a, &cm_c, &r, &z_ac, &prf2_2);
	let mut arrb2 = vec![];
	MyMIPPProof::<PE381>::serialize(&prf2_2, &mut arrb2).unwrap();
	assert!(arrb2==arrb, "arrb2!=arrb");
	//----- DEBUG END -----------------	

	if me==0 {assert!(bres2_2, "mipp serialization failed");}
	log(LOG1, &format!("BOTH PROOF PASSED"));
	
}

/// debug purpose
fn debug_dism_v1(){
	let me = RUN_CONFIG.my_rank;	
	let n = 16;
	//let vec= rand_arr_field_ele::<Fr381>(n, seed);
	let mut vec = vec![Fr381::zero(); n];
	for i in 0..vec.len(){ vec[i] = Fr381::from((1) as u64);}
	let key = DisKey::<PE381>::gen_key1(32);
	let seg_info = vec![(1, 5)];
	let g = key.g;
	let gs= vec![g.into_affine(); n];
	let mut base = GroupDisVec::<<Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine>::new_dis_vec(gs);
	//let mut base = GroupDisVec::<PE381::G1Affine>::new_dis_vec(gs);
	let mut exp = DisVec::<Fr381>::new_dis_vec_with_id(0, 0, vec.len(), vec);
	exp.to_partitions(&RUN_CONFIG.univ);
	base.to_partitions(&RUN_CONFIG.univ);

	if me==0{
		let mut sum = g.into_affine().mul(Fr381::zero()).into_affine();
		for i in 0..4{
			sum = sum + g.into_affine();
			println!("	i: {}, g: {}, sum: {}", i, g.into_affine(), sum);
		}
	}
	
	let res1 = dis_vmsm_g1_old::<PE381>(&base, &exp, &seg_info);
	let res2 = dis_vmsm_g1_new::<PE381>(&base, &exp, &seg_info);
	if me==0{
		assert!(res1==res2, "old!=new dis_vmsm_g1");
		println!("IT PASSES!");
	}
}

fn debug(){
	debug_ripp();
	//debug_vanish();
//	debug_aggregate_kzg();
//	debug_aggregate_subset();
//	debug_aggregate_groth16();
}

fn profile(){
/*
	let size = 1024*1024*32;
	profile_dis_vec(size, &RUN_CONFIG);
	profile_serial_fft(size, &RUN_CONFIG);
	profile_serial_dizk_fft(size, &RUN_CONFIG);
	profile_dis_dizk_fft(size, &RUN_CONFIG);

	let root_size = 1024*1024;
	profile_serial_build_poly_from_roots(root_size, &RUN_CONFIG);
	profile_dist_build_poly_from_roots(root_size, &RUN_CONFIG);

	let poly_size = 1024*1024;
	profile_key_and_eval(poly_size, &RUN_CONFIG);

	//profile_small_mul(10, &RUN_CONFIG);
	let mut poly_size= 1024*1024;
	for _i in 0..1{
		//profile_serial_div(poly_size, &RUN_CONFIG);
		profile_hgcd(poly_size, &RUN_CONFIG);
		poly_size *= 2;
	}

	let size = 1024;
	profile_pairing::<PE>("BN254", size, &RUN_CONFIG);
	profile_pairing::<PE381>("BLS12-381", size, &RUN_CONFIG);

	let size = 1024*32;
	profile_r1cs_serialization(size);
	profile_matrix_to_qap(size);
	profile_compute_witness_h(size);
	profile_make_even(size);
	profile_dis_eval_matrix(size);
	profile_dis_compute_h(size);
	let size = 1024*32;
	profile_all_protos(size, &RUN_CONFIG);
	profile_dis_groth16(size);
*/
	//let size = 1024*1024;
	//profile_poly_ops(size, &RUN_CONFIG);
	//collect_poly_data("fft", 24, 24, 2, 2, 100);
//	collect_poly_data("binacc", 21, 21, 1, 1, 100);
//	collect_poly_data("serial_binacc", 20, 20, 1, 1, 100);
//	collect_poly_data("mul", 16, 32, 1, 2, 100);
	//collect_poly_data("serial_div", 22, 22, 1, 3, 200);
	//collect_poly_data("div", 23, 23, 1, 1, 200);
	//collect_poly_data("gcd", 20, 26, 1, 2, 300);
	//collect_poly_data("gcd_new", 16, 16, 1, 2, 300);
	//collect_poly_data("sub_key", 20, 20, 1, 2, 250);
	//collect_poly_data("groth16prove", 20, 20, 1, 2, 250);
	//collect_poly_data("vmsm", 15, 15, 1, 2, 250);
	
	//8k for 1M FFT 256 nodes
 	//1k for 128k FFT 256 nodes
 	//64k for 8M FFT
	//collect_poly_data("net", 10, 32, 1, 3, 200); 


	collect_poly_data("groth16prove", 18, 18, 2, 2, 250);											
	//log(LOG1, &format!("START profiling ..."));
	//profile_dis_compute_h(size);
}

/**  ALL NODES needs to call. Source file should exist on MAIN node.
  Data written to ALL NODES. (except kzg files)
generate the kzg commitment given that the data (list of numbers)
is contained in the given fname (e.g., "st", note: do NOT include file suffix)
   Let a = {a_0, ..., a_n} be the number in the data file.
   let keys = {g^alpha^0, ..., g^alpha^n} be the KZG commitment keys
   gen_kzg generates the KZG commitment to the polynomial (biliear accumulator)
of set a: that is
	kzg = g^{p(alpha)} where polynomial p is defined as:
		p(x) = (x+a_0) (x+a_1) .... (x+a_n)
   The output of this function will be saved into destDir (if the
destDir does not exist, create it). Take "ST.dat"
as an example, it genreates:
	(1) st_poly.dat (co-efficients of polynomial p) [this is the polynomial
		for the list of numbers).
		-> when running in MPI ditributed mode the file is located
		on each node as
		st_poly_0.dat, st_poly_1.dat .... (distributed storage)
	(2) st_kzg.dat (the serialized form of kzg) -> *** ONLY *** stored
		on the main working node (rank 0)
It generate also the subset data, each subset has a similar structure (poly
nomial files and kzg, kzg_beta and proof.dat, where the proof shows
that it is a subset of the total kzg)
 NOTE: run ./scripts/publish.sh to run a local test
*/
fn gen_kzg<E:PairingEngine>(src_dir: &String, dest_dir: &String, fname: &String, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>)) 
	where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
	<<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{ 
	let b_perf = true;
	let b_mem = false;

	let mut t1 = Timer::new();
	if b_mem {dump_mem_usage("before gen_charpoy");}
	t1.start();	


	//1. contrust Distributed Polynomial from main node
	let me = RUN_CONFIG.my_rank;
	let mut num_st = 0;
	let src_file= format!("{}/{}.dat", &src_dir, fname);
	if me==0{	
		num_st = read_1st_line_as_u64(&src_file); 
	}
	let vec1 = broadcast_vecu64(0, &vec![num_st as u64]);
	num_st = vec1[0];

	log(LOG1, &format!("=========== Publisher Data Generation: ========= \n Source File: {} \n DFA State + Transition Size: {}", &src_file, num_st));
	new_dir_if_not_exists(dest_dir);
	let my_rank = RUN_CONFIG.my_rank;
	let id = 0u64;	
	let main_processor = 0u64;
	let mut dpoly:DisPoly<E::Fr> = DisPoly::dispoly_from_roots_in_file_from_mainnode(id, main_processor, &src_file, netarch);
	dpoly.dvec.set_real_len();
	let real_len = dpoly.dvec.real_len;
	dpoly.repartition(real_len);
	if b_perf {log_perf(LOG1, &format!("PERF_USE_GenCharPoly size: {}", dpoly.dvec.len), &mut t1);}

	//2. generate KZG commitment and write to file
	if b_mem {dump_mem_usage("before gen_key");}
	let np = RUN_CONFIG.n_proc;
	let key = DisKey::<E>::gen_key1(dpoly.dvec.len);
	let key_len = key.powers_g.len() * np;
	if b_perf {log_perf(LOG1, &format!("PREF_USE_GenKey Size: {}", key_len), &mut t1);}

	if b_mem {dump_mem_usage("before gen_kgz");}
	let kzg = key.gen_kzg(&mut dpoly);
	if b_perf {log_perf(LOG1, &format!("PERF_USE_GenKZG Size: {}", dpoly.dvec.len), &mut t1);}

	//let kzg_beta = key.gen_kzg_beta(&mut dpoly);
	//if b_mem {dump_mem_usage("before gen_kgz2");}
	//let kzg_beta = key.gen_kzg_beta(&mut dpoly);
	//if b_perf {log_perf(LOG1, &format!("PERF_USE_GenKZG_G2 Size: {}", dpoly.dvec.len), &mut t1);}

	if b_mem {dump_mem_usage("before writing files");}
	if my_rank==0{
		let v8 = to_vecu8(&kzg); 
		let kzg_filename = format!("{}/{}_kzg.dat", &dest_dir, &fname);  
		write_vecu8(&v8, &kzg_filename);
		//let v8 = to_vecu8(&kzg_beta); 
		//let kzg_filename = format!("{}/{}_kzg_beta.dat", &dest_dir, &fname);  
		//write_vecu8(&v8, &kzg_filename);
	}

	//3. write the polynomial to files (at each node)
	let poly_filename = format!("{}/{}_coefs.dat", &dest_dir, &fname);  
	dpoly.write_coefs_to_file(&poly_filename);
	log_perf(LOG1, &format!("PERF_USE_WriteKeys"), &mut t1);

	//4. generate the kzg and proof for each step
	if b_mem {dump_mem_usage("** BEFORE Generate Subset Proofs *");}
	for subset_id in RUN_CONFIG.subset_ids.clone(){
		gen_subset_proof::<E>(src_dir, dest_dir, 
			fname, subset_id, &mut dpoly, &key, &kzg[0], netarch);
		log_perf(LOG1, &format!("PERF_USE_GenSubset {}", subset_id), &mut t1);
	}
	if b_perf {dump_mem_usage("ESTIMATE OF PEAK MEM 2x: ");}
}

/// Generate the polynomial, kzg commitment and its proof for subset
/// of the given depth.
/// Will generate the following files:
/// (1) coefs.dat (distributed over nodes);  --> distributed to all nodes
/// (2) kzg.dat, kzg_beta.dat
/// (3) proof.dat  (over group G2)
/// ASSUMPTION: data file fname_subsetXXX.dat is available in src_dir
fn gen_subset_proof<E:PairingEngine>(src_dir: &String, dest_dir: &String, fname: &String, depth: usize, dpoly_all: &mut DisPoly<E::Fr>, key: &DisKey<E>, kzg_all: &E::G1Affine, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>))
	where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>, 
	<<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{ 
	log(LOG1, &format!("\n ==== Generate Subset Proof depth: {}====", depth));
	let b_perf = true;
	let b_mem = false;
	let my_rank = RUN_CONFIG.my_rank;
	let mut t1= Timer::new();
	t1.start();

	//1. read st data and set up directory
	let src_file= format!("{}/{}_subset_{}.dat", &src_dir, fname, depth);
	let mut dpoly:DisPoly<E::Fr> = DisPoly::dispoly_from_roots_in_file_from_mainnode(0, 0, &src_file, netarch);
	dpoly.to_partitions();
	dpoly.dvec.set_real_len();
	dpoly.repartition_to_real_len();
	let dpoly_len = dpoly.dvec.len;
	let subset_dir = format!("{}/subset_{}", dest_dir, depth);
	new_dir_if_not_exists(&subset_dir);
	if b_perf {log_perf(LOG1, &format!("-- construct poly SIZE: {}, real_len: {}", dpoly.dvec.len, dpoly.dvec.real_len), &mut t1);}
	if b_mem {dump_mem_usage("-- construct poly ");} 

	//2. generate kzg and kzg_beta
	let kzg = key.gen_kzg(&mut dpoly);
	if b_perf {log_perf(LOG1, &format!("-- GenKZG (G1)"), &mut t1);}
	if b_mem {dump_mem_usage("-- GenKZG (G1)");} 

	let kzg_beta= key.gen_kzg_beta(&mut dpoly);
	if b_perf {log_perf(LOG1, &format!("-- GenKZG (Beta)"), &mut t1);}
	if b_mem {dump_mem_usage("-- GenKZG (Beta)");} 

	if my_rank==0{
		let v8 = to_vecu8(&kzg); 
		let kzg_filename = format!("{}/{}_kzg.dat", &subset_dir, &fname);  
		write_vecu8(&v8, &kzg_filename);
		let v8 = to_vecu8(&kzg_beta); 
		let kzg_filename = format!("{}/{}_kzg_beta.dat", &subset_dir, &fname);  
		write_vecu8(&v8, &kzg_filename);
	}
	RUN_CONFIG.better_barrier("wait for files");
	let poly_filename = format!("{}/{}_coefs.dat", &subset_dir, &fname);  
	dpoly.write_coefs_to_file(&poly_filename);
	if b_perf {log_perf(LOG1,&format!("-- Write KZG and Poly Files"), &mut t1);}

	//4. generate the proof
	let (mut dq,dr)=DisPoly::<E::Fr>::divide_with_q_and_r(dpoly_all, &mut dpoly);
	if my_rank==0 {assert!(dr.is_zero(), "proof not exist. remainder!=0");}
	if b_perf {log_perf(LOG1,&format!("-- Divide: dpoly_all/dpoly, Degrees: {}, {}", dpoly_all.dvec.len, dpoly_len), &mut t1);}
	if b_mem {dump_mem_usage("-- Divide: dpoly_all/dpoly");} 

	dq.to_partitions();
	dq.dvec.set_real_len();
	let kzg_proof = key.gen_kzg(&mut dq);
	if b_perf {log_perf(LOG1,&format!("-- GenKzgProof for dq: Degrees: {}", dq.dvec.len), &mut t1);}
	let kzg_proof_beta = key.gen_kzg_beta(&mut dq);
	if b_perf {log_perf(LOG1,&format!("-- GenKzgProof Beta for dq: Degrees: {}", dq.dvec.len), &mut t1);}
	let kzg_proof_g2= key.gen_kzg_g2(&mut dq);
	if b_perf {log_perf(LOG1,&format!("-- GenKzgProof over G2 for dq: Degrees: {}", dq.dvec.len), &mut t1);}
	if b_mem {dump_mem_usage("-- GenKzgProof and Beta");} 
	if my_rank==0{
		let v8 = to_vecu8(&kzg_proof); 
		let kzg_filename = format!("{}/{}_proof.dat", &subset_dir, &fname);  
		write_vecu8(&v8, &kzg_filename);
		let v8 = to_vecu8(&kzg_proof_beta); 
		let kzg_filename = format!("{}/{}_proof_beta.dat",&subset_dir,&fname);  
		write_vecu8(&v8, &kzg_filename);
		let v8 = to_vecu8(&kzg_proof_g2); 
		let kzg_filename = format!("{}/{}_proof_g2.dat", &subset_dir, &fname);  
		write_vecu8(&v8, &kzg_filename);
	}
	if b_perf {log_perf(LOG1,&format!("-- Write kzg and kzg_beta"), &mut t1);}

	//6. verify
    let me_kzg = kzg[0];
    let prf = kzg_proof_g2[0];
    if my_rank==0{
        let lhs = E::pairing(me_kzg, prf);
        let rhs = E::pairing(*kzg_all, key.g_g2);
        assert!(lhs==rhs, "failed pairing check of subset proof");
    }
    log(LOG1, &format!("VERIFICATION passed!"));


	if b_perf {log_perf(LOG1,&format!("-- Verify SubseProof"), &mut t1);}
}
		

/** generate the non-zk version of the sigma proof.
	ac_dir: the one contains the PUBLISHED ac-dfa
	poly_dir: the dir containing the information of
	the random "r" and the set of states and transitions
	assume "st.dat" and "r.dat" in poly_dir
	OUTPUT: nonzk_sigma_prf.dat and nonzk_sig_prf.claim in
	poly_dir
 */
fn gen_nonzk_sigma_proof<E:PairingEngine>(ac_dir: &str, poly_dir: &str){
	//println!("DEBUG USE 100: gen_nonzk_sigma! acDir: {}, polyDir: {}", ac_dir, poly_dir);
	//1. read the number of elements
	let file_st = format!("{}/st.dat", ac_dir);
	let deg = read_1st_line_as_u64(&file_st);
	let n:usize = deg as usize +2; //as total vec needs 1 more
	let nodes_file = "/tmp/tmp_nodelist.txt";
	let netarch = &get_network_arch(&nodes_file.to_string());

	//2. build the key and protocol
	let key = DisKey::<PE>::gen_key1(n);
	let rc_key = Rc::new(key);
	let proto = NonzkSigma::<PE>::new(rc_key);

	//3. build the publisher's polynomial 
	let zero = E::Fr::zero();
	let mut dp_superset = DisPoly::<E::Fr>::single_from_vec(0, 0, &vec![zero]);
	let share_file = format!("{}/st_coefs.dat", ac_dir);
	dp_superset.read_coefs_from_file(&share_file, (deg+1) as usize);

	//4. build the prover's polinomial
	let st_file = format!("{}/st.dat", poly_dir);
	let mut dp_subset = DisPoly::<E::Fr>::dispoly_from_roots_in_file_from_mainnode(0, 0, &st_file, netarch);
	dp_superset.to_partitions();
	dp_subset.to_partitions();

	//5. read the randon nonce r
	let random_fname = format!("{}/r.dat", poly_dir);
	let vec_r = read_arr_fe_from::<E::Fr>(&random_fname); 
	assert!(vec_r.len()>0, "ERROR reading rand nonce at: {}", random_fname);
	let r = vec_r[0];

	//6. prove
	let mut inp:NonzkSigmaInput<E> = NonzkSigmaInput{
		p_superset: dp_superset,
		p_subset: dp_subset,
		r: r
	};
	let prf = proto.prove(&mut inp);
	let claim = proto.claim(&mut inp);
	//let bres = proto.verify(claim.borrow(), prf.borrow());
	//assert!(bres, "ERROR: NonzkSigma verify() fails!");

	//7. write proof 
	if RUN_CONFIG.my_rank==0{
		let prf_fname = format!("{}/nonzk_sigma_prf.dat", poly_dir);
		let bvec = prf.to_bytes();
		write_vecu8(&bvec, &prf_fname);		

		let claim_fname = format!("{}/nonzk_sigma_claim.dat", poly_dir);
		let bvec = claim.to_bytes();
		write_vecu8(&bvec, &claim_fname);		

		//let mut t1 = Timer::new();
		//t1.start();
		//let b2 = read_vecu8(&prf_fname);
		//let prf2 = NonzkSigmaProof::<E>::static_from_bytes(&b2);
		//let bres2 = proto.verify(claim.borrow(), &*prf2);
		//t1.stop();
		//assert!(bres2, "ERROR: reloading saved proof fails!");
		//println!("parse and verify time: {} ms", t1.time_us/1000);
		//PERFORMANCE: 6-7ms
		
		
	}
	RUN_CONFIG.better_barrier("gen_nonzk_sigma");
}

/** nodes_file: the MPI nodes file. The first one must be 127.0.0.1 */
fn prove_and_verify<PE:PairingEngine>(_ac_dir: &str, _poly_dir: &str, _prf_dir: &str, _subset_id: usize, _n: usize, _curve_type: &str, _nodes_file: &str, _max_final_state: usize) where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	panic!("prove_and_verify() DEPRECATED. Call batch_prove_verify!");
/*
	let me = RUN_CONFIG.my_rank;
	let crs = Rc::new(zk_setup::<PE>(n));
	let (prf, claim, dp) = zk_prove::<PE>(ac_dir, poly_dir, subset_id, &crs, curve_type, nodes_file, max_final_state);
	if me==0{
		prf.save_to(prf_dir);
	}
	let _bres = zk_verify(&claim, &prf, &crs, dp);
	if me==0{
		//RECOVER LATER!!!
		//assert!(bres, "VERIFICATION FAILED!");
		//RECOVER LATER!!! ABOVE
		println!("VERIFICATION passed v1.0!");
	}
*/
}

/** assuming proof and claim data in poly_dir */
fn verify_sigma_proof<E:PairingEngine>(poly_dir: &str){
	//a very small protocol is good
	let n = RUN_CONFIG.n_proc * 2;
	let key = DisKey::<PE>::gen_key1(n);
	let rc_key = Rc::new(key);
	let proto = NonzkSigma::<PE>::new(rc_key);
	if RUN_CONFIG.my_rank==0{//ONLY perform at processor 0
		let mut t1 = Timer::new();
		t1.start();
		let prf_fname = format!("{}/nonzk_sigma_prf.dat", poly_dir);
		let b2 = read_vecu8(&prf_fname);
		let prf2 = NonzkSigmaProof::<E>::static_from_bytes(&b2);
		let claim_fname = format!("{}/nonzk_sigma_claim.dat", poly_dir);
		let b2 = read_vecu8(&claim_fname);
		let claim2= NonzkSigmaClaim::<E>::static_from_bytes(&b2);
		let bres2 = proto.verify(&*claim2, &*prf2);
		assert!(bres2, "ERROR: verify failed!");	
		t1.stop();
		println!("very_sigma_proof PASSED! Note: recorded time contains key creation time, which is big.\nREAL verification time: {}ms", t1.time_us/1000);
	}
	RUN_CONFIG.better_barrier("gen_nonzk_sigma");
}

/// for experiments use
fn experiment(){
	let one = get_poly::<Fr381>(vec![Fr381::from(1u64)]);
	let p1 = rand_poly::<Fr381>(128, 1281231);
	let p2 = rand_poly::<Fr381>(128, 123428);
	let q = rand_poly::<Fr381>(256, 127778);
	let p = &p1 * &p2;
	if RUN_CONFIG.my_rank==0{
		println!("EXRERIMENT new gcd algorithm");
		println!("DEGREE INPUT: p1: {}, p2: {}, q: {}", p1.degree(), p2.degree(), q.degree());
		//print_poly("p1", &p1);
		//print_poly("p2", &p1);
		//print_poly("q", &q);
		let (q1, r1) = adapt_divide_with_q_and_r(&q, &p1); 
		let (q2, r2) = adapt_divide_with_q_and_r(&q, &p2); 
		let (_gcd1, s1, t1) = feea(&p1, &r1);
		let (_gcd2, s2, t2) = feea(&p2, &r2);
		assert!(&s1*&p1 + &t1*&r1 ==one, "s1*p1 + t2*r1!=one");
		assert!(&s2*&p2 + &t2*&r2 ==one, "s1*p2 + t2*r2!=one");
	
		let s1 = &s1 - &(&q1*&t1);
		let s2 = &s2 - &(&q2*&t2);
		assert!(&s1*&p1 + &t1*&q ==one, "s1*p1 + t1*q!=one");
		assert!(&s2*&p2 + &t2*&q ==one, "s1*p2 + t2*q!=one");
		let s = &s1 * &s2;
		let t = &t1 + &(&t2*&(&s1*&p1));
	
		let (u2, t_final) = adapt_divide_with_q_and_r(&t, &p);
		let s_final = &s + &(&u2*&q);
		assert!(&s*&p + &t*&q==one, "s*p + t*q!=one");
		assert!(&s_final*&p + &t_final*&q==one, "s_final*p + t_final*q!=one");
		println!("degree s: {}, t: {}, p: {}, q: {}, s1.degree: {}, s2.degree: {}, t1.degree: {}, t2.degree: {}", s.degree(), t.degree(), p.degree(), q.degree(), s1.degree(), s2.degree(), &t1.degree(), &t2.degree());
		println!("s_final: {}, t_final: {}", s_final.degree(), t_final.degree());
	}
	RUN_CONFIG.better_barrier("section 1");

	// ---- Now experiment with the distributed version
	let mut vec1 = vec![];
	let n  = 1024*4;
	for i in 0..n{ vec1.push(Fr381::from((i+2) as u64));}
	let mut vec2 = vec![];
	for i in 0..n{ vec2.push(Fr381::from((i+2*n) as u64));}
	let mut dv = DisVec::<Fr381>::from_serial(&vec1);
	let p2 = DisPoly::<Fr381>::binacc_poly(&vec2);
	let p = DisPoly::<Fr381>::binacc_poly(&vec1);
	
	let mut dp2 = DisPoly::from_serial(0, &p2, p2.degree()+1);
	let (_gcd, s, t) = DisPoly::<Fr381>::feea_new(&mut dv, &mut dp2);
	let ps = s.to_serial();
	let pt = t.to_serial();
	if RUN_CONFIG.my_rank==0{ 
		assert!(&ps*&p + &pt*&p2 ==one, "DisFeea failed!");
	}
	log(LOG1, &format!("Dis gcd experiment PASSED!"));
	
}

/// This function shows a case study example of binacc22 paper err
/// Given an aribrary element acc in G1 (assuming it's the
///   accumulator of some polynomial
/// Given p as the order of G1, compute w = acc^(p+1)/2
/// let q = g^2, one could verify that e(acc, g) = e(q, w)
fn verify_binacc22_err(){
	println!("---- verify error of binacc22 paper ");
	let d = 31261;
	let key = DisKey::<PE381>::gen_key1(32768);
	let mut dp = DisPoly::<Fr381>::gen_dp(d);
	let kzg = key.gen_kzg(&mut dp)[0];
	let p = Fr381::MODULUS; 
	let sp = format!("{}", p);
	println!("FR381 order IS {}", sp);
	let half_p = str_to_fe::<Fr381>(&format!("26217937587563095239723870254092982918845276250263818911301829349969290592257")); //(p+1)/2
	println!("half_p: {}", half_p);

	let two = Fr381::from(2u64);
	let q = key.g_g2.mul(two);
	let half_kzg = kzg.mul(half_p);
	let lhs= PE381::pairing(kzg, key.g_g2); 
	let rhs = PE381::pairing(half_kzg, q);
	println!("LHS: {}", lhs);
	println!("rhs: {}", rhs);
	assert!(lhs==rhs, "VERIFICATION of binacc22 paper error passed.");
}
fn main() {

	let mut timer = Timer::new();
	timer.start();
	//not working ... needs to resolve import (use the same)
	//rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

	//REMOVE LATER ----
	env::set_var("RUST_BACKTRACE", "1");
	//REMOVE LATER ---- ABOVE
	let args: Vec<String> = env::args().collect();
/*
	if args[1].contains("profile"){
		if RUN_CONFIG.my_rank==0{println!("SYSTEM WARMUP. Prep TCP conns...");}
		warm_up(); //establish TCP connections (3-7 seconds) BEFORE profiling
		if RUN_CONFIG.my_rank==0{println!("WARMUP completed.");} 
	}
*/
	if args[1]=="aggregate"{
		let n_prfs = 128; //to expand if necessary by replicating (for profile)
		let me = RUN_CONFIG.my_rank;
		//let curve_type = args[2].clone();
		let ac_dir = args[3].clone();
		//let params_file = args[4].clone(); 
		let results_dir = args[5].clone();
		//let dfa_sigs = args[6].clone();
		let np = str_to_u64(&args[7]) as usize;
		println!("------ SINGLE NODE aggregate ------------. NO MPI");
		let jobs = create_job_list(&results_dir, np);
		//check_claims::<PE381>(&jobs, true, true, true,&curve_type,&ac_dir,&params_file, &dfa_sigs, np, &results_dir);
		let mut fd = new_file_append(&format!("{}/agg_report.txt", 
			&results_dir));
		let (gipa, key, v_crs, job_list, vec_conn_inp) = agg_setup(&jobs, &results_dir, &mut fd, n_prfs, &ac_dir);
		let mut t3 = Timer::new();
		t3.start();
		let (agg_claim, agg_prf) = agg_prove::<PE381>(&job_list, &vec_conn_inp, 
			&results_dir, &gipa, &key, &mut fd, n_prfs);
		log_perf(LOG1, "AggProof Total", &mut t3);
		let mut bprf = agg_prf.to_bytes();
		log(LOG1, &format!("#### SERIALIZED PROOF SIZE: {} bytes", bprf.len()));
		let mut agg_prf2 = AggProof::<PE381>::from_bytes(&mut bprf, &gipa);
		let bres = agg_verify::<PE381>(&agg_claim, &agg_prf, &gipa, &key, 
			&v_crs, &mut fd);
		if me==0 {assert!(bres, "Aggregation failed!");}
		return;
	}else if args[1]=="single_profile"{
		println!("------ SINGLE THREAD profile ------------. NO MPI");
		println!("=== BN-254===");
/*
		collect_group_data::<PE>("g1_mul", 20, 20, 1, 2, 500);
		collect_group_data::<PE>("g1_mul_proj", 20, 20, 1, 2, 500);
		collect_group_data::<PE>("g2_mul", 20, 20, 1, 2, 500);
		collect_group_data::<PE>("g2_mul_proj", 20, 20, 1, 2, 500);
		collect_group_data::<PE>("pair", 10, 10, 1, 2, 500);
*/
//		collect_group_data::<PE>("msm_g1", 20, 20, 1, 2, 500);
//		collect_group_data::<PE>("msm_g2", 20, 20, 1, 2, 500);
		println!("=== Bls381===");
/*
		collect_group_data::<PE381>("g1_mul", 20, 20, 1, 2, 500);
		collect_group_data::<PE381>("g1_mul_proj", 20, 20, 1, 2, 500);
		collect_group_data::<PE381>("g2_mul", 20, 20, 1, 2, 500);
		collect_group_data::<PE381>("g2_mul_proj", 20, 20, 1, 2, 500);
		collect_group_data::<PE381>("pair", 10, 10, 1, 2, 500);
*/
		//collect_group_data::<PE381>("msm_g1", 10, 20, 1, 2, 500);
		collect_group_data::<PE381>("msm_g2", 10, 20, 1, 2, 500);
		//collect_group_data::<PE381>("fsm_g1", 20, 20, 1, 2, 500);
		//collect_group_data::<PE381>("fsm_g2", 20, 20, 1, 2, 500);
//		collect_group_data::<PE381>("serialize_field", 20, 20, 1, 2, 500);
//		collect_group_data::<PE381>("deserialize_field", 20, 20, 1, 2, 500);
//		collect_group_data::<PE381>("serialize_g1", 20, 20, 1, 2, 500);
//		collect_group_data::<PE381>("deserialize_g1", 20, 20, 1, 2, 500);
		return;	
	}

	let me = RUN_CONFIG.my_rank;
	if args[1]=="debug"{
		debug();
		//verify_binacc22_err();
	}else if args[1]=="profile"{
		profile();
	} else if args[1]=="gen_kzg"{
		let curve_type = &args[5];
		let nodes_file = &args[6];
		let netarch = get_network_arch(&nodes_file.to_string());
		if curve_type=="BN254"{
			gen_kzg::<PE>(&args[2], &args[3], &args[4], &netarch);
		}else if curve_type=="Bls381"{
			gen_kzg::<PE381>(&args[2], &args[3], &args[4], &netarch);
		}else{
			panic!("{} not supported!", curve_type);
		}
	}else if args[1]=="gen_circ_witness_serial"{ 
		//process poly proof mostly SEQUENTIALLY
		gen_circ_witness_serial::<Fr>(&args[2], &args[3]);	
	}else if args[1]=="gen_poly_for_modular_verifier"{
		let curve_type = &args[5];
		let nodes_file = args[6].clone();
		let netarch = get_network_arch(&nodes_file);
		let server_id = 0;
		if curve_type=="BN254"{
			gen_witness_for_modular_verifier::<Fr>(server_id, &args[2], &args[3], &args[4], &netarch, true);
		}else if curve_type=="Bls381"{
			gen_witness_for_modular_verifier::<Fr381>(server_id, &args[2], &args[3], &args[4], &netarch, true);
		}else{
			panic!("Unsupported Curve Type: {}", curve_type);
		}
		log_perf(LOG1, "Generate Polynomial Witness", &mut timer);
	}else if args[1]=="gen_nonzk_sigma_proof"{
		gen_nonzk_sigma_proof::<PE>(&args[2], &args[3]);	
	}else if args[1]=="verify_sigma_proof"{
		verify_sigma_proof::<PE>(&args[2]);
	}else if args[1]=="rust_prove"{//expecting 4 extra params
		let ac_dir = &args[2]; //where AC data is
		let poly_dir = &args[3]; //where ALL polyomial evidence data is
		let prf_dir = &args[4]; //where to save proof
		let curve_type=&args[5]; //either "BN254" or "BLS12-381"
		let subset_id = str_to_u64(&args[6]) as usize; //see paper. an ID of subset
		let nodes_file = &args[7];
		let max_final_states = str_to_u64(&args[8]) as usize;

		//DETERMINE the degree needed
		let mut n = 0;	
		if me==0{
	 		let n1 = read_1st_line_as_u64(&format!("{}/st_subset_{}.dat",ac_dir, subset_id)) as usize + 1;
        	let n2 = read_1st_line_as_u64(&format!("{}/states.dat",poly_dir)) as usize;
        	let n3 = read_1st_line_as_u64(&format!("{}/trans.dat",poly_dir)) as usize;
        	let np = RUN_CONFIG.n_proc;
        	let n4 = (n2+n3+2+np).next_power_of_two();
        	n = if n1>n4 {n1} else {n4};
		}
		let vecn = broadcast_vecu64(0, &vec![n as u64]);
		n = vecn[0] as usize;

		if curve_type=="BN254"{
			prove_and_verify::<PE>(ac_dir, poly_dir, prf_dir, subset_id, n, curve_type, nodes_file, max_final_states);
		}else if curve_type=="Bls381"{
			prove_and_verify::<PE381>(ac_dir, poly_dir, prf_dir, subset_id, n, curve_type, nodes_file, max_final_states);
		}else{
			panic!("Unsupported curve type: {}", curve_type);
		}
	}else if args[1]=="pingpong"{//expecting 1 parameter 
		ping_pong(256);
	}else if args[1]=="profile_poly"{//expecting 1 parameter 
		let size = args[2].parse::<usize>().unwrap();
		data_profile_poly(size);
	}else if args[1]=="profile_fft"{//expecting 1 parameter 
		let size = args[2].parse::<usize>().unwrap();
		data_profile_fft(size);
		data_profile_fft(size);
	}else if args[1]=="profile_poly_mul"{//expecting 1 parameter 
		let size = args[2].parse::<usize>().unwrap();
		data_profile_poly_mul(size);
	}else if args[1]=="collect_poly_data"{
		let sop = args[2].clone();
		let log_min_size = args[3].parse::<usize>().unwrap();
		let log_max_size = args[4].parse::<usize>().unwrap();
		let log_size_step= args[5].parse::<usize>().unwrap();
		let trials = args[6].parse::<usize>().unwrap();
		let timeout = args[7].parse::<usize>().unwrap();
		collect_poly_data(&sop, log_min_size, log_max_size, log_size_step, trials, timeout);
	}else if args[1]=="batch_prove"{
		let node_file = args[2].clone();	
		let job_file = args[3].clone();
		let work_dir = args[4].clone();
		let report_dir = args[5].clone();
		let curve_type = args[6].clone(); //only BN254 or BLS12-381
		let ac_dir = args[7].clone(); //where ac_dir is
		let param_file = args[8].clone(); //where ac_dir is
		let num_worker= args[9].parse::<usize>().unwrap();
		let sig_file = &args[10].clone();

		//if true, skip the batch_preprocess (gen states procedure)
		let s_skip = &args[11].clone();
		assert!(s_skip.starts_with("skip_batch_preprocess"),
			"arg[11] should be skip_batch_preprocess");

		//if true, skip the batch generating GCD procedure (use existing files)
		let s_skip_gcd = &args[12].clone();
		assert!(s_skip_gcd.starts_with("skip_batch_gcd"),
			"arg[12] should be skip_batch_gcd");
			
		let b_skip_preprocess = s_skip.find("true")>=Some(0);
		let b_skip_batch_gcd = s_skip_gcd.find("true")>=Some(0);
		if curve_type=="BN254"{
			batch_prove::<PE>(&node_file, &job_file, &work_dir, &report_dir, 
				&curve_type, &ac_dir, &param_file, num_worker, sig_file, 
				b_skip_preprocess, b_skip_batch_gcd);	
		}else if curve_type=="BLS12-381"{
			batch_prove::<PE381>(&node_file, &job_file, &work_dir, &report_dir, 
				&curve_type, &ac_dir, &param_file, num_worker, sig_file, 
				b_skip_preprocess, b_skip_batch_gcd);	
		}else{
			panic!("batch_prove can't handle curve: {}", curve_type);
		}
	}else if args[1]=="exp"{
		experiment();
	}else{
		phantom_func();
    	println!("ERROR: unrecognized option/args: {:?}", args);
	}
	RUN_CONFIG.better_barrier("main");
	log_perf(LOG1, "WaitForBarrier of Main", &mut timer);
	if RUN_CONFIG.my_rank==0{println!("ACC COMPLETED");}


}
