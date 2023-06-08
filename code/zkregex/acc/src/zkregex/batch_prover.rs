/** 
	Copyright Dr. CorrAuthor
	Author: Dr. CorrAuthor 
	Created: 12/20/2022
	Refined: 12/26/2022 -> Added GrothStage2 and other subset proofs 
	Revised: verifier on 2-stage Groth'16 part
*/

/* ****************************************************************
This file contains BATCH prover related functions.
It takes a batch job (so set up needs only once)
**************************************************************** */
extern crate ark_ec;
extern crate ark_ff;
extern crate ark_poly;
extern crate mpi;
extern crate ark_serialize;
extern crate ark_bls12_381;
extern crate ark_bn254;

use std::str;
use std::fs::File;
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use std::rc::Rc;
use poly::dis_poly::DisPoly;
use poly::serial::*;
use self::ark_ff::{UniformRand,Zero,Field};
use self::mpi::traits::*;
use poly::common::*;
use self::ark_poly::{Polynomial};

/*
*/
//use self::mpi::environment::*;

use tools::*;
use profiler::config::*;
//use jsnark_driver::new_jd_tools::*;
use circwitness::modular_circ_gen::*;
use jsnark_driver::new_r1cs_gen::*;
use zkregex::prover::*;
use groth16::new_dis_qap::*;
use groth16::verifier::*;
//use poly::dis_poly::*;
use poly::dis_key::*;
use r1cs::dis_r1cs::*;
use groth16::dis_prove_key::*;
use groth16::dis_prover::*;
use groth16::serial_prove_key::*;
use proto::zk_subset_v3::*;
use proto::zk_kzg_v2::*;
use proto::*;
//use poly::dis_vec::*;
//use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};



/*
use poly::dis_key::*;
//use poly::common::*;
//use poly::serial::*;
use proto::*;
use proto::zk_kzg::*;
use proto::zk_dlog::*;
*/

use self::ark_bn254::Bn254;
type Fr254 = ark_bn254::Fr;
type PE254= Bn254;
use self::ark_bls12_381::Bls12_381;
type Fr381=ark_bls12_381::Fr;
type PE381=Bls12_381;

/// return the working dir of circ
pub fn get_circ_dir()->String{
	let me = RUN_CONFIG.my_rank;
	let jsnark_dir = get_absolute_path("../jsnark/JsnarkCircuitBuilder/");
	let case_id = 11223344u64;
	let inp_dir= format!("{}/circuits/{}/{}", jsnark_dir, case_id, me);
	return inp_dir;
}

// handle the names conversion of curve types
pub fn get_curve_name(curve_type: &str) -> String{
	let curve_name = if curve_type=="BLS12-381" {"Bls381"} else {curve_type};
	return curve_name.to_string();
}
/** batch prove the job given in job_file. Extract the group_id
	and subset_id from the job file.
	job_file: e.g., job_10_20.txt (group 2^10 and subset_id: 20)
	work_dir: temporary folder for storing traces  (can be somewhere in /tmp
	report_base_dir: dir for reports: assume this dir exist.
		will create job_file.report in that folder
	param_file: the parameters for running the java main program
		NOTE: check scripts/prover.sh of java main
	num_worker: num of pre-processor worker (java threads),
	sig_file: the location of signature files
	b_skip_preprocess: whether to skip the preprocess (java) step
	b_skip_batch_gcd: whether to skip the batch preprocessing of GCD (generating		gcd polynomials - reason - gcd does not scale well).
*/
	
pub fn batch_prove<PE:PairingEngine>(node_file: &str, job_file: &str, 
	work_dir: &str, report_base_dir: &str, curve_type: &str, 
	ac_dir: &str, param_file: &str, num_worker: usize, sig_file: &str,
	b_skip_preprocess: bool, b_skip_batch_gcd: bool)
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. one time set up: compute the circuit -> QAP. and get Sigma key
	let b_perf = true;
	let b_mem = true;
	let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	timer.start();
	let netarch = get_network_arch(&node_file.to_string());
	let mut max_final_states = if me==0 {get_final_states(ac_dir) as u64} else {0u64};
	max_final_states = broadcast_vecu64(0, &vec![max_final_states])[0];
	let num_final_states = max_final_states as usize;
	if b_mem {dump_mem_usage("ENTERING batch_prove");}
	let (dis_r1cs, dis_qap, crs, crs_verifier, mut fd_log, subset_id, b1st_node, var_map, group_size, mut dp_subset) = onetime_setup::<PE>(
			&netarch, job_file, work_dir, report_base_dir, 
			curve_type, ac_dir, param_file, num_worker, 
			num_final_states, sig_file, b_skip_preprocess, b_skip_batch_gcd);
	if b_perf {flog_perf(LOG1, "PERF_USE_OnetimeSetup",&mut timer,&mut fd_log);}
	if b_mem {dump_mem_usage("AFTER onetime setup");}


	let inp_dir= &get_circ_dir();
	let curve_name = &get_curve_name(curve_type);
	let evaluator = CircEvaluator::<PE>::parse_from(inp_dir, curve_name);

	//2. handle each file
	let num_jobs = get_num_jobs(job_file);
	let jobs = get_jobs(job_file);
	let jobs_full = get_job_full(job_file);
	let mut fname;
	let oldtar_path = tos("/tmp/102.tar");
	let worktar_path = tos("/tmp/102.tar");
	for i in 0..num_jobs{
		//0. decide the server id
		let n_servers = netarch.1.len();
		let job_shares = num_jobs/n_servers;

		//0.5 find out the server ID
		let mut load = vec![job_shares; n_servers];
		let mut beg_idx = vec![0; n_servers];
		let mut end_idx = vec![0; n_servers];
		
		let n_left = num_jobs - job_shares * n_servers;
		for j in 0..n_left {load[j] += 1;}
		beg_idx[0] = 0;
		end_idx[0] = load[0];
		for j in 1..n_servers{
			beg_idx[j] = end_idx[j-1];
			end_idx[j] = end_idx[j-1] + load[j];
		}
		let i_max = 10000000000000000;
		let mut server_id = i_max;
		for j in 0..n_servers{
			if i>=beg_idx[j] && i<end_idx[j]{
				server_id = j; 
				break;
			}
		}	
		assert!(server_id<i_max, "server_id is not set!");

		//1. node 0 prepare the job folder
		fname = jobs[i].replace("/", "_");
		let job_full = jobs_full[i].clone();
		if me==netarch.1[server_id]{
			let mut timer2 = Timer::new();
			timer2.start();
			copy_dir(work_dir, &fname, SWORK_DIR);
			flog_perf(LOG1, &format!("COPY folder: {}->{}", fname, SWORK_DIR),
				&mut timer, &mut fd_log);
		}
		let poly_dir = &format!("{}/{}", work_dir, SWORK_DIR);

		//2. prove it and save the proof to report directory
		let job_fname = extract_fname(job_file);
		let job_fname = job_fname.replace(".txt","");
		let prf_dir = &format!("{}/{}/proof/{}", report_base_dir,
			job_fname, fname); 
		prove_file(server_id, &fname, ac_dir, poly_dir, group_size, subset_id, 
				&crs, &crs_verifier,
				curve_type, &netarch, num_final_states, &mut fd_log,
				prf_dir, &dis_r1cs, &dis_qap, 
				b1st_node, &var_map, group_size, &evaluator, &mut dp_subset,
				&job_full);

		//3. save proof and reset
		if me==netarch.1[server_id]{
			println!("REMOVE LATER 102: me: {}, server_id: {}, job_id: {}. MOVE FILE back : oldtar_path: {} <==  worktar_path: {}", me, server_id, i, oldtar_path, worktar_path);
		}
	} 
	log(LOG1, &tos(" ----- DONE WITH PROVING ALL FILES ----"));
	//REMOVE the temp directory
	if is_1st_node_of_server_by_arch(&netarch){
		remove_dir(work_dir);
	}
}

// --------------------------------------------------------------
// ------------------ UTILITY FUNCTIONS BELOW -----------------
// --------------------------------------------------------------

/** generate the zero knowledge proof for a GIVEN file.
	Save the PROOF and CLAIM in the given prf_dir
	Will perform self-check (verification) after each proof is generated.

	This function is to be called by each MPI mode.
	server_id: the SERVER (not node) which has the poly_dir
	job_name: the name of the job (only valid at main node)
	ac_dir: containing AC-DFA data
	poly_dir: containing polynomial evidence data set
	subset_id: the subset_id of the proof
	curve_type: either BN254 or BLS12-381
	subset_id: see paper (a subset of transition set of AC-DFA).
	nodes_file: the list of nodes MPI (the first one must be 
		127.0.0.1)
	prf_dir: where to save proof and claim
	b1st_node: whether this node is the first node of the server
	var_map: the global varialbe mapping for reading variable values
	file_size: the rounded file size for the group, e.g., 2^12 size group
		(it's calculated by function get_group_size, all files are rounded
		up to this size)
	dp_subset: the dispoly which represents the subset of states/trans
		at subset_id

	NOTE: only generates valid proof at NODE 0!

 */
pub fn prove_file<PE:PairingEngine>(server_id: usize, job_name: &str, ac_dir: &str, poly_dir: &str, group_size: usize, subset_id: usize, crs: &CRS<PE>, _crs_verifier: &CRS<PE>,_curve_type: &str, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), _max_final_states: usize, fd_log: &mut File, prf_dir: &str, dis_r1cs: &DisR1CS<PE::Fr>, dis_qap: &DisQAP<PE::Fr>, b1st_node: bool, var_map: &Vec<Vec<(usize,usize)>>, file_size: usize, evaluator: &CircEvaluator<PE>, dp_subset: &mut DisPoly<PE::Fr>, job_details: &str)
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let b_mem = false;
	let b_test = true;
	
	//0. setup
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let bar = "===================================";
	flog(LOG1, &format!("{}\nSTART_PROVE: {}\n{}", bar, job_name, bar), fd_log);
	let mut timer = Timer::new();
	let mut timer_all = Timer::new();
	timer.start();
	timer_all.start();
	let seed = 71231231237u128; //fixed rand constant, to imrpove later
	let mut rng = gen_rng_from_seed(seed);
	let num_vars = dis_r1cs.num_vars+1; //to include cconstant 1
	let prove_key = &crs.prover_key;


	//1. generate the var values
	let s_np = &format!("{}", np);
	let s_size= &format!("{}", file_size);
	let (mut vec_disvec, mut spolys, mut tpolys, mut chunk_inputs) = 
		gen_witness_for_modular_verifier_shortcut::<PE::Fr>
			(server_id, poly_dir, s_size, s_np, netarch, false); 
	if b_perf {flog_perf(LOG1, "ProveStep1: PERF_USE_GenWitness1", &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep1: MEM_USE_GenWitness1", fd_log);}

	//2. evaluate circuit and generate vars
	let mut timer3 = Timer::new();
	timer3.start();
	let vec_disvec_len = vec_disvec.len();
	let arr_wit = collect_witness(&vec_disvec, &spolys, &tpolys, file_size, np);
	let local_vars = evaluator.gen_local_vars(&arr_wit);
	let d_vars = DisR1CS::<PE::Fr>::vars_from_serial_each_node(&local_vars, var_map, num_vars, fd_log); 
	if b_perf {flog_perf(LOG1, &format!("ProveStep2: PERF_USE_EvalCirc1 Vars:{}, LocalVars: {}", d_vars.len, local_vars.len()), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep2: MEM_USE_EvalCirc1", fd_log);}

	//--------ENABLE FOR DEBUG ONLY ----------
	//log(LOG1, &format!("-------SLOW version for GenVAR-----"));
	//let d_vars = gen_var_vals::<PE>(server_id, poly_dir, curve_type, nodes_file, max_final_states, var_map, num_vars, fd_log);
	//if b_perf {flog_perf(LOG1, &format!("PERF_USE_GenCircVars total_vars: {}", d_vars.len), &mut timer, fd_log);}
	//if b_mem {flog_mem(LOG1, "MEM_USE_GenCircVars", fd_log);}
	//log(LOG1, &format!("-------SLOW version for GenVAR ABOVE-----"));

	let b_skip_h = true; //for saving proof cost
	let qw = if b_skip_h {dis_r1cs.to_qap_witness_no_h(d_vars)} else 
		{dis_r1cs.to_qap_witness(d_vars)};
	if b_perf {flog_perf(LOG1, &format!("ProveStep3: PERF_USE_WitnessToQAP. b_skip_h: {}", b_skip_h), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep3: MEM_USE_WitnessToQAP", fd_log);}
	if b_test && !b_skip_h{//SHOULD NOT BE called when using no_h
		let bres = dis_qap.is_satisfied(&qw);
		if me==0 {assert!(bres, "qap NOT SATISIFED by qw!");};
		if me==0 {println!("+++++ QAP SAT passed!");}
		if b_perf {flog_perf(LOG1, "ProveStep3.5: QAP Test Time", &mut timer, fd_log);}
	}

	//2. Generate Groth1.
	let num_segs = dis_qap.num_segs;
	let dprover = DisProver::<PE>::new(num_segs, seed, dis_qap.seg_size.clone());	
	let p1 = dprover.prove_stage1(&prove_key, &qw, 1);
	if b_perf {flog_perf(LOG1, &format!("ProveStep4: PERF_USE_Groth1. Constraints: {}", dis_r1cs.num_constraints), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep4: MEM_USE_Groth1", fd_log);}

	//3. Generate the commitment of  
	let r_q2 = PE::Fr::rand(&mut rng); //used for encoding C_st
	let mut dp_set_states = spolys[3].clone();
	let mut dp_set_trans = tpolys[3].clone();
	let mut dp_st = DisPoly::<PE::Fr>::mul(&mut dp_set_states, 
		&mut dp_set_trans); 
	dp_set_states.dvec.to_partitions(&RUN_CONFIG.univ);
	dp_set_trans.dvec.to_partitions(&RUN_CONFIG.univ);
	dp_st.dvec.to_partitions(&RUN_CONFIG.univ);
	let c_st = crs.sigma_key.gen_kzg(&mut dp_st)[0] 
		+ crs.sigma_key.h.mul(r_q2).into_affine();
	if b_perf {flog_perf(LOG1, "ProveStep5: PERF_USE_GenDpSetCommit", &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep5: MEM_USE_GenDpSetCommit", fd_log);}

	//3. generate hash - apply Fiat-Shamir
	let c1 = p1.arr_c[0];
	let vecu8 = to_vecu8(&vec![c_st, c1]);
	let r = hash::<PE::Fr>(&vecu8); 
	let r_inv = r.inverse().unwrap();
	//let vecu8 = to_vecu8(&vec![r]);
	let arr_r = rewrite_rand_nonce::<PE>(r, r_inv, poly_dir, b1st_node);
	let r = arr_r[0];
	let r_inv = arr_r[1]; 
	let z = arr_r[2];
	let r1 = arr_r[3];
	let r2 = arr_r[4];
	let key = arr_r[5];

	//let dirpath = &get_circ_dir(curve_type);
	//let mut chunk_inputs2 = create_chunked_inputs(poly_dir, file_size, np, r);
	let svec = &vec_disvec[0]; //for states.dat
	let tvec = &vec_disvec[4]; //for trans.dat
	update_chunked_inputs_on_p_acc(&mut chunk_inputs, &r, svec, tvec);
	update_chunk_inputs("S_", &mut spolys, 2*file_size+np+1, 
		&mut chunk_inputs, r);
	update_chunk_inputs("T_", &mut tpolys, 2*file_size+1, &mut chunk_inputs, r);
	let dv_chunk_inputs2 = chunked_poly_inputs_to_dvec(poly_dir, &chunk_inputs, z, r1, r2, key, r, r_inv, false); 
	vec_disvec[vec_disvec_len-1] = dv_chunk_inputs2;
	let arr_wit = collect_witness(&vec_disvec, &spolys, &tpolys,file_size, np);
	let local_vars = evaluator.gen_local_vars(&arr_wit);
	let d_vars2 = DisR1CS::<PE::Fr>::vars_from_serial_each_node(&local_vars, var_map, num_vars, fd_log); 
	if b_perf {flog_perf(LOG1, "ProveStep5: PERF_USE_EvalCirc2", &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep5: MEM_USE_EvalCirc2", fd_log);}


	//--------ENABLE FOR DEBUG ONLY ----------
	//log(LOG1, &format!("--- SLOW VERSION GenVar2 --------------------"));
	//let d_vars2 = gen_var_vals::<PE>(server_id, poly_dir, curve_type, nodes_file, max_final_states, var_map, num_vars, fd_log);
	//if b_perf {flog_perf(LOG1, "PERF_USE_SLOW_GenWitness2", &mut timer, fd_log);}
	//if b_mem {flog_mem(LOG1, "MEM_USE_GenWitness2", fd_log);}
	//log(LOG1, &format!("--- SLOW VERSION GenVar2 ABOVE --------------------"));

	let qw2 = dis_r1cs.to_qap_witness(d_vars2);
	if b_test{
		let bres = dis_qap.is_satisfied(&qw2);
		if me==0 {assert!(bres, "qap NOT SATISIFED by qw2!");};
	}
	if b_perf {flog_perf(LOG1, &format!("ProveStep6: PERF_USE_GenWitness2: num_cons: {}", dis_r1cs.num_constraints), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "MEM_USE_GenWitness2", fd_log);}


	//4. prove stage 2
	let p2 = dprover.prove_stage2(&prove_key, &qw2, 1);
	let (a,b,c3) = (p2.a, p2.b, p2.last_c);
	let hash = p2.io[1];
	if b_test{
		let bres2 = verify(&p1, &p2, &crs.verifier_key);
		if me==0 {
			assert!(bres2, "Self Test: 2-Stage Groth16 Proof Fail!");
			//println!("SelfTest Step 7: 2-Stage Groth16 Proof Passed!");
		}
	}
	if b_perf {flog_perf(LOG1, "ProveStep7: PERF_USE_Groth16Stage2", &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep7: MEM_USE_Groth16Stage2", fd_log);}


	//5. generate the 1st subset proof (subset_id \subset TOTAL)
	let r_q = PE::Fr::rand(&mut rng);
	let r_w = PE::Fr::rand(&mut rng);
	let key2 = crs.sigma_key.clone();
	let (prf_subset1, claim_subset1) = gen_subset1_proof::<PE>(ac_dir, 
		subset_id, &crs.sigma_key, r_q, r_w); 
	if b_perf {flog_perf(LOG1,"ProveStep8: PERF_USE_Build_Subset_Prf1",&mut timer,fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep8: MEM_USE_Build_Subset_Prf1", fd_log);}

	//6. generate the 2nd subset proof (trace set \subset subset_id)
	let dp_set_states = &mut spolys[3];
	let dp_set_trans = &mut tpolys[3];
	dp_set_states.repartition_to_real_len();
	dp_set_trans.repartition_to_real_len();
	dp_subset.repartition_to_real_len();

	let (prf_subset2, claim_subset2, mut dp_st, _r_q, _r_q2) = gen_subset2_proof::<PE>(dp_subset, dp_set_states, dp_set_trans, &crs.sigma_key, r_q, r_q2);
	let _dp_st2 = dp_st.clone();
	if me==0{
		assert!(claim_subset1.c_q==claim_subset2.c_p, 
			"subset1.subset==subset2.superset!");
	}
	if b_perf {flog_perf(LOG1, &format!("ProveStep9: PERF_USE_Build_Suset_Prf2 Degree: {}", dp_subset.dvec.len), &mut timer,fd_log);}
	if b_mem {flog_mem(LOG1, "ProveStep9: MEM_USE_Build_Subset_Prf2", fd_log);}



	//9. generate the blindeval proof
	let svec = &vec_disvec[0]; //for states.dat
	//let tvec = &vec_disvec[4]; //for trans.dat
	let last_idx = svec.len-1;
	let s_1 =  svec.get_for_each_node(0); 
	let s_n = svec.get_for_each_node(last_idx);
	let chunked_inputs = &vec_disvec[vec_disvec.len()-1]; 
	assert!(chunked_inputs.len==43*np, "chunked_inputs.len()!=43*np");
	let p_v = chunked_inputs.get_for_each_node(43*np-1);
	let z_g1 = prove_key.get_g1_key(1, 0, &dis_qap); //z's key
	let z_g2 = prove_key.get_g1_key(1, 1, &dis_qap); //r2's key
	let z_g3 = prove_key.get_g1_key(1, 2, &dis_qap); //r2's key
	let z_g4 = prove_key.get_g1_key(1, 3, &dis_qap); //r2's key
	let delta_k = prove_key.delta_g1[num_segs-1]; 
	let ri_2 = dprover.r_i[1]; //used as the part2 in prove_stage1 for seg #2
	let zk_kzg = ZkKZGV2::<PE>::new(key2);
	let c_q = claim_subset2.c_q;
	let c2 = p2.arr_c[0];
	let (prf_kzg, claim_kzg) = zk_kzg.prove_direct(&mut dp_st, r_q2, r, z_g1, z_g2, z_g3, z_g4, delta_k, s_1, s_n, r2, ri_2, c_q, p_v); 
	if b_test{
	  if me==0{
		assert!(zk_kzg.verify(&claim_kzg, &prf_kzg), "zk_kzg failed");
		assert!(claim_kzg.c_z == c2, "kzg.c_z != c2");
		assert!(claim_kzg.c_p == claim_subset2.c_q, "kzg.c_p!=subset2.c_q");
		//println!(" ## Step 9 zk-kzg passed");
	  }
	}
	if b_perf {flog_perf(LOG1,&format!("ProveStep10: PERF_USE_Build_ZkKZG Degree: {}", dp_st.dvec.len),&mut timer,fd_log);}
	if b_mem {flog_mem(LOG1, "MEM_USE_Build_ZkKZG", fd_log);}

	//9. assembly proof
	let aux = ZkregexAux::<PE>{
		aux_subset1: prf_subset1.aux.clone(),
		aux_subset2: prf_subset2.aux.clone(),
		aux_kzg: prf_kzg.aux.clone()
	};
	assert!(!&aux.is_dummy(), "ERROR: aux is dummy!");
	let prf = ZkregexProof::<PE>{
		a: a,
		b: b,
		c1: c1,
		c2: c2,
		c3: c3,
		c_subset: claim_subset2.c_p,
		c_st: claim_subset2.c_q, 
		subset1_prf: prf_subset1,
		subset2_prf: prf_subset2,
		kzg_prf: prf_kzg, 
		r: r,
		aux: aux
	};
	let claim = ZkregexClaim::<PE>{
		hash: hash, 
		kzg_all: claim_subset1.c_p,
	};
	if me==0{
		new_dir(prf_dir);
		assert!(exists(prf_dir), "prf_dir does not exist: {}!", prf_dir);
		prf.save_to(prf_dir);
		claim.save_to(prf_dir);
		write_file(&format!("{}/info.txt", prf_dir), tos(&job_details));
	}
	if b_perf {flog_perf(LOG1, "PERF_USE_WritePrf", &mut timer, fd_log);}
	RUN_CONFIG.better_barrier("waiting for prf writing complets");

	if b_test{
		//test reaload crs_verifier
		if me==0 {
			let fpath = format!("{}/../../../crs/crs_{}_{}.dat", prf_dir, group_size, subset_id);
			let crs_verifier = CRS::<PE>::load_from(&fpath);
			let prf = ZkregexProof::load_from(&prf_dir);
			let claim = ZkregexClaim::load_from(&prf_dir);
			let b_ok = zk_verify(&claim, &prf, &crs_verifier); 
			assert!(b_ok, "zk_verify FAILED!");
			println!(" #####!!!!! FINAL zk_verify passed! ####");
		}
	}
	//FINAL: data summary
	if b_perf {flog(LOG1, &format!("{}\nEND_PROVE: {}\n{}", bar, job_name, bar), fd_log);}
	if b_perf {flog_perf(LOG1, &format!("PERF_USE_Proof_File {} ", job_name), 
		&mut timer_all, fd_log);}

}

/// ALL nodes should call and will get the same number
fn get_num_jobs(job_file: &str) -> usize{
	let me = RUN_CONFIG.my_rank;
	let mut num_jobs = 0;
	if me==0{
		let jobs = get_jobs(job_file);
		num_jobs = jobs.len();
	}
	let vecn = broadcast_vecu64(0, &vec![num_jobs as u64]);
	num_jobs = vecn[0] as usize;
	return num_jobs;
}
/** one time set up. Return
	(1) t used for generating QAP from DisR1CS
	(2) DisQAP - distributed QAP instance
	(3) Rc<CRS> - the CRS for Sigma protocol proof and Prover/Verifier key for Groth, and also the verifier_crs (which is lighter)
	(4) subset_id
	(5) variable map
	(5) the group_size: like the clostest rounded up size to a power of 2
		depending on the group (like 2^15)
	(6) DisPoly of the subset of that given subset_id
	(7) the DisPoly for the subset.
*/
pub fn onetime_setup<PE:PairingEngine>(netarch: &(Vec<u64>, Vec<usize>, Vec<Vec<usize>>), job_file: &str, 
	work_dir: &str, report_base_dir: &str, curve_type: &str, 
	ac_dir: &str, param_file: &str, num_worker: usize, max_final_states: usize, sig_file: &str, b_skip_preprocess: bool, b_skip_batch_gcd: bool)
	-> (DisR1CS<PE::Fr>, DisQAP<PE::Fr>, Rc<CRS<PE>>, Rc<CRS<PE>>, File, usize, bool, Vec<Vec<(usize,usize)>>, usize, DisPoly::<PE::Fr>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. set up logging and work directories
	let b_perf = true;
	let b_mem = true;
	let mut timer = Timer::new();
	timer.start();

	let np = RUN_CONFIG.n_proc;
	let me = RUN_CONFIG.my_rank;
	let b1st_node = is_1st_node_of_server_by_arch(netarch);
	let mut file_log = set_up_folders(job_file,work_dir,report_base_dir, b1st_node, b_skip_preprocess);
	let fd_log=&mut file_log;
	let bar_line = "======================";
	let job_fname = extract_fname(job_file);
	let (group_id, subset_id) = get_job_details(job_fname);
	//let group_size = get_group_size(group_id, np);
	if b_perf {flog_perf(LOG1, &format!("{}  Job: {}  {}\n Group_ID: {}, Subset_ID: {}",bar_line,job_fname,bar_line, group_id, subset_id),&mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("ENTERING one-time setup"), fd_log);}

	//2. preprocess the jobs (by calling ../main/batch_proces)
	//generate the transitions array for each exectible and stores in workdir
	// NOTE that now the files are distributed among all servers
	if !b_skip_preprocess{
		preprocess(curve_type, ac_dir, job_file, work_dir, np, param_file, num_worker, fd_log, sig_file, netarch);
		if b_perf {flog_perf(LOG1, "PERF_USE_PreprocessTransitions", &mut timer, fd_log);}
		if b_mem {flog_mem(LOG1, &format!("AFTER PreprocessTransitions."), fd_log);}
	}else{
		if b_perf {flog(LOG1, &format!("Skip the preprocessing step"), fd_log);}		
	}

	//2.5 batch_gcd for all data directories: NOTE: this cost
	// should be COUNTED as prover cost (as it generates GCD)
	let group_size = get_group_size(group_id, np);
	if !b_skip_batch_gcd{
		batch_gcd::<PE>(&netarch, work_dir, group_size, fd_log);
		if b_perf {flog_perf(LOG1, "PERF_USE_Batch_GCD", &mut timer,fd_log);}
		if b_mem {dump_mem_usage("AFTER Batch_GCD");}
	}

	//3. Generate the circuit
	let (dis_r1cs, dis_qap, prove_key, verify_key, var_map) = gen_dis_qap::<PE>(fd_log, curve_type, job_file, work_dir, np, group_size, netarch, ac_dir, max_final_states);
	flog_perf(LOG1, "PERF_USE_GenQAP", &mut timer, fd_log);

	//4. Generate the key
	let mut key_size= 0;	
	if me==0{
		let n1 = read_1st_line_as_u64(&format!("{}/st_subset_{}.dat",ac_dir, subset_id)) as usize + 1;
		let n2 = 2*(group_size + np);
		key_size  = if n1>n2 {n1} else {n2};
	}
	let vecn = broadcast_vecu64(0, &vec![key_size as u64]);
	key_size = vecn[0] as usize;
	let (c1, c2) = zk_setup::<PE>(key_size, Rc::new(prove_key), Rc::new(verify_key), group_size, subset_id, &dis_qap);
	let crs = Rc::new(c1);
	let crs_verifier = Rc::new(c2);
	if me==0{ crs_verifier.save_to(&format!("{}/crs/", report_base_dir)); }
	flog_perf(LOG1, "PERF_USE_GenSigmaKey", &mut timer, fd_log);

	//5. generate the DisPoly for the given subset_id
	let supfile= format!("{}/subset_{}/st_coefs.dat", ac_dir, subset_id);
	let zero = PE::Fr::zero();
	let mut dp_subset = DisPoly::<PE::Fr>::single_from_vec(0,0,&vec![zero]);
	dp_subset.read_coefs_from_file_new(&supfile);
	flog_perf(LOG1, "PERF_USE_GenSubsetPoly", &mut timer, fd_log);

	return (dis_r1cs, dis_qap, crs, crs_verifier, file_log, subset_id, 
		b1st_node, var_map, group_size, dp_subset);
}

/// batch preprocessing GCD for states and transitions
/// This should be regarded part of the proving cost
pub fn batch_gcd<PE:PairingEngine>(netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), work_dir: &str, group_size: usize, fd_log: &mut File){
	let b_perf = true;
	let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	let mut timer2 = Timer::new();
	timer.start();
	timer2.start();

	let num_workers = decide_num_workers(group_size, &netarch);
	let mylist = decide_my_worklist(num_workers, work_dir, netarch);
	for file in &mylist{
		preprocess_gcd::<PE>(&file.as_str(), "S_", fd_log);
		preprocess_gcd::<PE>(&file.as_str(), "T_", fd_log);

		timer.clear_start();
		//let parent_path = get_absolute_path(&get_parent_dir(file));
		//let dirname = get_fname(file);
		if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 9. tar the dir: {}", file), &mut timer, fd_log);}
	}
	if b_perf {flog_perf(LOG1, &format!("PERF_BATCH_GCD: me: {}, #jobs: {}", me, mylist.len()), &mut timer2, fd_log);}	
}

/// preprocess the GCD's of the polynomials
/// save the polys (serialized SINGLE thread) into directory fpath.
/// This basically simualtes circ_modular_generate_witness
/// it generates and saves polynomial coefs for:
/// P, P_D, GCD, P_GCD, PD_GCD, S, T
/// produce the tar file of the entire dirpath in parent folder
pub fn preprocess_gcd<PE:PairingEngine>(dirpath: &str, prefix: &str, fd_log: &mut File){
	let b_perf = true;
	let b_mem = false;
	let b_test = false;

	let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	timer.start();
	let mut timer2 = Timer::new();
	timer2.start();

	let src_name = if prefix=="S_" {"states.dat"} else {"trans.dat"};
	if b_perf {flog(LOG1, &format!("preprocess_gcd: me: {}, {}/{} ...", 
		me, dirpath, src_name), fd_log);}
	if b_mem {flog_mem(LOG1, &format!("batch_gcd {}/{}: before start.", dirpath, src_name), fd_log);}

	//1. write the generated set to file
	let srcfile = &format!("{}/{}", dirpath, src_name);
	let fname_gen = &format!("generated_set_{}.dat", src_name);
	let srcfile2 = &format!("{}/{}", dirpath, fname_gen);
	let total = read_1st_line_as_u64(srcfile);
	let multi_set:Vec<u64> = read_arr_u64_from(srcfile, 1, total as usize);
	let set_support = get_set_u64(&multi_set);
	write_arr_with_size(&set_support, srcfile2); 
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 1: generate set for {}, set_size: {}", srcfile, set_support.len()), &mut timer, fd_log);}

	//2. generate P
	let mut v_p = vec![PE::Fr::zero(); multi_set.len()];
	for i in 0..multi_set.len() {v_p[i] = PE::Fr::from(multi_set[i]);}
	let p = DisPoly::<PE::Fr>::binacc_poly(&v_p); 
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 2: gen P for {}, poly_size: {}", srcfile, v_p.len()), &mut timer, fd_log);}

	//3. generate p_gcd (set support = p/gcd)
	let mut v_p_gcd = vec![PE::Fr::zero(); set_support.len()];
	for i in 0..v_p_gcd.len() {v_p_gcd[i] = PE::Fr::from(set_support[i]);}
	let p_gcd = DisPoly::<PE::Fr>::binacc_poly(&v_p_gcd); 
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 3: gen P_GCD for {}, poly_size: {}", srcfile, v_p_gcd.len()), &mut timer, fd_log);}

	//4. generate p_d (derivative of p);
	let pd = get_derivative(&p);
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 4: write P_D for {}, poly_size: {}", srcfile, pd.degree()), &mut timer, fd_log);}

	//5. generate GCD
	let (gcd, r0) = adapt_divide_with_q_and_r(&p, &p_gcd);
	if b_test {assert!(r0.is_zero(), "r0 is not zero!");}
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 5: gen GCD for {}, poly_size: {}", srcfile, gcd.degree()), &mut timer, fd_log);}

	//6. generate PD_GCD
	let (pd_gcd, r1) = adapt_divide_with_q_and_r(&pd, &gcd);
	if b_test {assert!(r1.is_zero(), "r0 is not zero!");}
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 6: gen PD_GCD for {}, poly_size: {}", srcfile, pd_gcd.degree()), &mut timer, fd_log);}
	
	//7. generate the bezout identity s and t s.t. s*p_gcd + t*pd_tcd = 1
	let (gcdres, s, t) = feea(&p_gcd, &pd_gcd);
	let pone = get_poly::<PE::Fr>(vec![PE::Fr::from(1u64)]);
	if b_test{
		assert!(gcdres==pone, "p_gcd and pd_gcd are not co-rpime!");
	}
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 7: gen Bizout identity for {}. a:{}, b:{}, s: {}, t: {}", srcfile, p_gcd.degree(), pd_gcd.degree(), s.degree(), t.degree()), &mut timer, fd_log);}

	//8. LAST, write all files
	let vdata = vec![
		(&p, "P"),
		(&p_gcd, "P_GCD"),
		(&pd, "PD"),
		(&gcd, "GCD"),
		(&pd_gcd, "PD_GCD"),
		(&s, "S"),
		(&t, "T"),
	];
	for entry in vdata{
		let poly = entry.0;
		let name = entry.1;
		let fname = format!("{}/{}serial_{}.dat", dirpath, prefix, name);
		let coefs = &poly.coeffs;
		write_arr_fe_to(coefs, &fname);
	}
	if b_perf {flog_perf(LOG1, &format!("-- -- process_gcd Step 8. write ALL files  for {}", srcfile), &mut timer, fd_log);}


	if b_perf {flog_perf(LOG1, &format!("-- PROCESS_GCD TOTAL for {}", srcfile), &mut timer2, fd_log);}
	if b_mem {flog_mem(LOG1, &format!("batch_gcd {}/{}: when complete.", dirpath, src_name), fd_log);}
}

/// based on the num of workers and my own ID
/// decide the local list of files to take 
fn decide_my_worklist(num_workers: usize, work_dir: &str, 
	netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>)) -> Vec<String>{
	//1. get my worker id in server
	let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let b_debug = false;

	let n_server = netarch.1.len();
	let nodes_per_server = np/n_server;
	let workers_per_server = num_workers/n_server;
	assert!(num_workers%np==0, "num_workers: {} % np: {} !=0",num_workers,np);
	assert!(nodes_per_server>=workers_per_server, "nodes_per_server: {} < workers_per_server: {}", nodes_per_server, workers_per_server);	
	let (server_id, my_id_in_server) = get_identity_in_server(netarch);
	let b_work = my_id_in_server<workers_per_server;
	if b_debug {
		println!("-- DebugMsg1 for decide_worklist: nodes_per_server: {}, worker_per_server: {}, me: {}, my_worker_id: {} of server: {}", nodes_per_server, workers_per_server, me, my_id_in_server, server_id);
	}

	//2. get the list
	if b_work{
		let listjobs = list_dir(work_dir);
		let total = listjobs.len();
		let mut unit_share = total/workers_per_server;
		unit_share = if total%workers_per_server>0 {unit_share+1} 
			else {unit_share};
		let mut my_start = unit_share * my_id_in_server;
		let mut my_end = if my_id_in_server==workers_per_server-1 {total} else {unit_share * (1 + my_id_in_server)};
		my_start = if my_start>total {total} else {my_start};	
		my_end = if my_end>total {total} else {my_end};
		let myshare = listjobs[my_start..my_end].to_vec();
		if b_debug{
			println!("-- DebugMsg2 for decide_worklist: me: {}, worker_id: {} of server: {}, shares: {} -> {} (not included), joblist size: {} of total: {}", me, my_id_in_server, server_id, my_start, my_end, myshare.len(), total);
			for x in &myshare{
				println!("me: {} process: {}", me, x);
			}
		}
		return myshare;
	}else{
		if b_debug{println!("me: {}, worker_id: {} of server: {} -> not work", me, my_id_in_server, server_id);}
		return vec![];
	}
}

/// decide the number of workers needed
/// ALL nodes will get the same decision (made by 1st node)
fn decide_num_workers(group_size: usize, netarch: &(Vec<u64>,Vec<usize>, Vec<Vec<usize>>) )->usize{
	//e.g., 1k group size -> 2k (max) transitions (usually only 10%)
	//each transition needs a group element (reserve 64 bytes at least)
	//multiplication may needs 10x more
	//set factor to 1024. 1k group size -> 2*1024 = 2M, 
	//e.g., 1M -> 2G RAM needed.

	let np = RUN_CONFIG.n_proc;
	let me = 0;
	let mut res = 0;
	let b_debug= true;

	if me==0{
		let mem_on_server = get_sys_mem();
		let num_trans = group_size * 2;
		let factor = 1024;
		let estimate_per_worker = num_trans * factor;
		let n_servers = netarch.1.len();
		
		let max_worker_per_server = mem_on_server/estimate_per_worker;
		let max_workers = max_worker_per_server * n_servers;
		res = if max_workers>np {np} else {max_workers};
		if b_debug{log(LOG1, &format!("DECIDE_Num_Workers: mem_on_server: {}, transitions: {}, factor: {}, estimate_per_worker: {}, max_workers_per_server: {}, max_workers: {}, res: {}", mem_on_server, num_trans, factor, estimate_per_worker, max_worker_per_server, max_workers, res));}
	}

	let arr = broadcast_small_arr(&vec![res], 0);
	let final_res = arr[0];
	return final_res;
} 

/// return the file size for all files in group (in nibbles)
pub fn get_group_size(group_id: usize, np: usize)->usize{
	// need to be consistent with read_and_padd() of RustProver in main
//	let cur_len = 1<<(group_id+1);
	let unit = 126;
	let cur_len = (1<<(group_id+1)) - np*unit;
	let cur_len_per_node = cur_len/np;
	let target_len_per_node = if cur_len_per_node%unit==0
		{cur_len_per_node} else {(cur_len_per_node/unit+1) * unit};
	let min_len = unit * np;
	let target_len = if target_len_per_node*np < min_len
		{min_len} else {target_len_per_node*np};
	return target_len; //ni nibbles
}


/// set up the working directory and result directory
/// return the log file file handler (for main node)
/// others get a file handler to "/tmp/rpt101.txt" which is never used
fn set_up_folders(job_file: &str, work_dir: &str, report_base_dir: &str,
	b1st_node: bool, b_skip_preprocess: bool) -> File{
	//1. only the main node establishes the report_base_dir
	let me = RUN_CONFIG.my_rank;
	let mut fd = new_file_append(&format!("/tmp/rpt101_{}.txt", me)); //fake fd
	if b1st_node{
		if me==0{
			assert!(exists(report_base_dir), "report_dir: {} not eixsts!", 
			report_base_dir);
			let crs_dir = format!("{}/crs", report_base_dir);
			if !exists(&crs_dir){
				new_dir(&crs_dir);
			}
		}
		if !b_skip_preprocess{//keep it if skipping preprocesss
			remove_dir(work_dir);
			new_dir(work_dir); 
		}
		if me==0{	
			let job_fname = extract_fname(job_file);
			let report_fname = &format!("{}/{}.report", report_base_dir, job_fname);
			fd = new_file_append(&report_fname);
		}
	}

	//2. ONLY 1st node of each server needs to create work_dir
	RUN_CONFIG.better_barrier("setup_folder");	
	return fd;
}

/// from file name extract the information of size_group and
/// subset_id
pub fn get_job_details(fname: &str) -> (usize, usize){
	let fsuffix = &fname[fname.len()-4..fname.len()];
	assert!(fsuffix==".txt", "suffix of fname: {}!=.txt", fname);
	let fname = &fname[0..fname.len()-4]; //chop off .txt
	let vecs = fname.split("_").collect::<Vec<&str>>();
	assert!(vecs[0]=="job", "vecs[0]!=job");
	let group_id:usize = vecs[1].parse().unwrap();
	let subset_id:usize = vecs[2].parse().unwrap();
	return (group_id, subset_id);
}

/// pre-process by calling java-main
/// idea: generate chunked transitions array for all executable
/// files and store everything in work_dir
/// NOW files are distributed among all servers
fn preprocess(curve_type: &str, ac_dir: &str, job_file: &str, work_dir: &str, np: usize, param_file: &str, num_worker: usize, fd_log: &mut File, sig_file: &str, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>)){
	//1. synchronize the set up information
	let b_perf = true;
	//let me = RUN_CONFIG.my_rank;
	let mut timer = Timer::new();
	broadcast_file_to_all_nodes(sig_file, netarch);
	broadcast_file_to_all_nodes(job_file, netarch);
	broadcast_file_to_all_nodes(param_file, netarch);
	if b_perf {flog_perf(LOG1, "-- preprocess Step1: broadcast config files", &mut timer, fd_log);}

	//2. read the params needed for running java main (node: the jar paths
	// are generated using gentar.py in scripts/ in java main folder
	//adjusted the MEMORY allocation (when workers <=4 we assume it's small 
	// allocate 2GB to each worker). When worker>4, we assume it's
	// full running environment: each worker has a full 20G DFA
	// allocate each worker: 16G 
	if !is_1st_node_of_server_by_arch(&netarch){
		//NON 1st node, wait and don't do anything
		RUN_CONFIG.better_barrier("WAIT FOR ALL");
		if b_perf {flog_perf(LOG1, "-- preprocess Step1: broadcast config files", &mut timer, fd_log);}
		return;
	}
	//NOW assume 1st node of each server
	let vs = read_arrlines(&tos(param_file));
	let mut line = vs[0].clone(); //assume only one line
	for li in vs{ if !li.starts_with("#") {line = li.clone();} }	
	let mut vec1 = split_str(&line);
	let n_servers = netarch.0.len();
	//full mode needs 16G, if node <=4 regard as small experiment
	//for 32-d server (16 nodes) allocate 4G
	let ram_per_worker = if num_worker<=4 {2} else {
		if num_worker<=16 {4} else {16}
	}; 
	let worker_per_server = num_worker/n_servers;
	let server_id = get_server_id(&netarch);
	let ram = get_sys_mem()/(1024*1024*1024); 
	if ram_per_worker * worker_per_server > ram{
		panic!("ram_per_worker: {} * worker_per_server: {} > sys ram: {}! Reduce number of Java workers", ram_per_worker, worker_per_server, ram);
	}

	//2. construct the 2nd params
	for id in 0..vec1.len(){
		if vec1[id].starts_with("-Xmx"){
			vec1[id] = format!("-Xmx{}g", (ram_per_worker*worker_per_server));
		}
	}
	let mut vec2 = vec![
		tos("batch_preprocess"),
		tos(curve_type), tos(job_file), tos(ac_dir), tos(work_dir),
		format!("{}",np),
		format!("{}",worker_per_server),
		format!("{}",server_id),
		format!("{}",n_servers),
		format!("{}",sig_file),
	];
	vec1.append(&mut vec2);

	//3. invoke the java
	let sres = run_in_dir("java", &vec1, &tos("../main"));
	if sres.contains("FATAL"){
		panic!("(JAVA) preprocessing fatal err: {}", &sres);	
	}
	if b_perf{flog(LOG1, &format!("---Java Main Preprpocessing Details---\n {}", &sres), fd_log);}
	RUN_CONFIG.better_barrier("WAIT FOR ALL");
	if b_perf {flog_perf(LOG1, "-- preprocess Step1: broadcast config files", &mut timer, fd_log);}
}

/// read from info.txt in ac_dir
fn get_final_states(ac_dir: &str)-> usize{
	let fname = &format!("{}/info.txt", ac_dir);
	let arr_lines = read_arrlines(fname);
	let line_finals = &arr_lines[1];
	let num = line_finals.parse::<u64>().unwrap();
	let num_usize = num as usize;
	return num_usize;
}

/// return a list of jobs
fn get_jobs(job_file: &str)->Vec<String>{
	let lines = read_arrlines(&tos(job_file));
	let mut vecres = vec![];
	for line in lines{
		let trimline = line.trim();
		if trimline.starts_with("#") {continue;}
		let job= &trimline.split(" ").collect::<Vec<&str>>()[0];
		vecres.push(tos(job));
	}
	return vecres;
}
fn get_job_full(job_file: &str)->Vec<String>{
	let lines = read_arrlines(&tos(job_file));
	let mut vecres = vec![];
	for line in lines{
		let trimline = line.trim();
		if trimline.starts_with("#") {continue;}
		vecres.push(tos(trimline));
	}
	return vecres;
}
/// Generate the distributed QAP
/// By calling jsnark_driver
/// work_dir: where to place data
/// file_size: the file size of each file in the group
/// netarch: network arch for synch files
/// num_final_states: number of final states in AC-DFA
/// return includes variable_map for all variables
/// ASSUMPTION: 1st job is located at node 0
fn gen_dis_qap<PE:PairingEngine>(fd_log: &mut File,
		curve_type: &str, job_file: &str, work_dir: &str, np: usize,
		file_size: usize, netarch: &(Vec<u64>,Vec<usize>,Vec<Vec<usize>>), 
		ac_dir: &str, num_final_states: usize) 
		-> (DisR1CS<PE::Fr>, DisQAP<PE::Fr>, DisProverKey<PE>, VerifierKey<PE>, Vec<Vec<(usize,usize)>>)
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let b_mem = true;
	if b_perf{flog(LOG1, &format!("gen_dis_qap: filesize: {}", file_size), fd_log);}

	//1. select the 1st file and extract it to WORK_DIR
	//assumption: polys and witness have ALREADY been generated (in serial)
	let seed = 71231231237u128; //fixed rand constant, to imrpove later
	let mut timer = Timer::new();
	timer.start();
	let me = RUN_CONFIG.my_rank;
	if me==0{
		let jobs = get_jobs(job_file);
		let file1 = jobs[0].replace("/", "_");
		copy_dir(work_dir, &file1, SWORK_DIR);
	}
	let server_id = 0; //as we always takes the 1st job
	let poly_dir = &format!("{}/{}", work_dir, SWORK_DIR); 
	let s_size = &format!("{}", file_size);
	let s_np = &format!("{}", np);
	let (mut _vec_disvec, mut _spolys, mut _tpolys, mut _chunk_inputs) = 
		gen_witness_for_modular_verifier_shortcut::<PE::Fr>
			(server_id, poly_dir, s_size, s_np, netarch, true); 
	if b_perf {flog_perf(LOG1, "-- GenQAP Step 1: LoadWitness", &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "-- GenQAP Step 1: LoadWitness", fd_log);}


	//3. supply the evidence and generate distributed R1CS
	let poly_dir = &format!("{}/{}", work_dir, SWORK_DIR);
	let (dis_r1cs, _dis_inst, var_map) = gen_dis_r1cs::<PE>(0, ac_dir, poly_dir, curve_type, netarch, num_final_states, fd_log);	
	if b_perf {flog_perf(LOG1, &format!("-- GenQAP Step 2: GenDisR1CS: size: {}, ", dis_r1cs.num_constraints), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "-- GenQAP Step 2: GenDisR1CS", fd_log);}


	let mut rng = gen_rng_from_seed(seed);
	let t = PE::Fr::rand(&mut rng);
	let dis_qap = dis_r1cs.to_qap(&t);
	if b_perf {flog_perf(LOG1, &format!("-- GenQAP Step 3: GenQAP: vars: {}", dis_qap.num_vars), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "-- GenQAP Step 3: GenQAP", fd_log);}



	//4. generate the prover and verifier key
	let np = RUN_CONFIG.n_proc;
	let diskey = DisKey::<PE>::gen_key1(32*np); 	 //just a small one
	let (dkey, vkey) =dis_setup::<PE>(seed, &dis_qap, &diskey); 
	if b_perf {flog_perf(LOG1, &format!("-- GenQAP Step 4: GenDisKey for SigmaProtos size: {}", dkey.query_a.len), &mut timer, fd_log);}
	if b_mem {flog_mem(LOG1, "-- GenQAP Step 4: GenDisKey for SigmaProtos", fd_log);}

	//4. reset
	let b1st_node = is_1st_node_of_server_by_arch(netarch);
	if b1st_node{
		remove_dir(&format!("{}/{}", work_dir, SWORK_DIR));
	}
	RUN_CONFIG.better_barrier("gen_dis_qap_completed");
	return (dis_r1cs, dis_qap, dkey, vkey, var_map);
}

/// used by Groth16 Stage 2. 
/// Rewrite r and r_inv into poly_dir
/// Need to be jointly called by all nodes
fn rewrite_rand_nonce<PE:PairingEngine>(r: PE::Fr, r_inv: PE::Fr, poly_dir: &str , b1st_node: bool)->Vec<PE::Fr>{
	//1. broadcast r and r_inv to all nodes
	let vdata = vec![r, r_inv];
	let mut vu8 = to_vecu8(&vdata);
	let world = RUN_CONFIG.univ.world();
	let root_proc = world.process_at_rank(0);
	root_proc.broadcast_into(&mut vu8);

	//2. receive from main node
	let v_r = from_vecu8(&vu8, PE::Fr::zero());
	let r = v_r[0];
	let r_inv = v_r[1];
	let fname = &format!("{}/r.dat", poly_dir); 

	//3. 1st node of each server re-write the new array into r.dat
	if b1st_node{
		let mut arr_r = read_arr_fe_from(fname);
		arr_r[0] = r;
		arr_r[1] = r_inv;
		arr_r[6] = r; //kind of waste 2 elements, improve later 
		arr_r[7] = r_inv; 
		write_arr_fe_to::<PE::Fr>(&arr_r, fname);
	}

	//4. ALL nodes read from the file
	RUN_CONFIG.better_barrier("wait for all storing r");
	let arr_r = read_arr_fe_from(fname);
	return arr_r;
}


/** build the first subset proof: the indicated subset_i is a subset of
the total subset of all transitions+states, negligible cost
as it uses shortcut prove.
r_q and r_w are used to blind c_q and c_w (shortcut_prove).
ONLY RETURN VALID proof at node 0!
*/
pub fn gen_subset1_proof<PE:PairingEngine>(ac_dir: &str, subset_id: usize, 
	key: &Rc<DisKey<PE>>, r_q: PE::Fr, r_w: PE::Fr) 
-> (ZkSubsetV3Proof<PE>, ZkSubsetV3Claim<PE>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//0. MOST of ops will be on node 0; other node just return dummy res
	let me = RUN_CONFIG.my_rank;
	let b_test = true;

	if me!=0{ 
		return (ZkSubsetV3Proof::<PE>::dummy(), ZkSubsetV3Claim::<PE>::dummy());
	}

	//2. retrieve already prepared result by publisher
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	let sdir = format!("{}/subset_{}", ac_dir, subset_id);
	let c_p = read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", ac_dir));

	let c_q = read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", sdir));
	let prf_q = read_ge::<PE::G1Affine>(&format!("{}/st_kzg_beta.dat", sdir));

	let c_w= read_ge::<PE::G1Affine>(&format!("{}/st_proof.dat", sdir));
	let prf_w= read_ge::<PE::G1Affine>(&format!("{}/st_proof_beta.dat", sdir));
	let c_w2= read_ge::<PE::G2Affine>(&format!("{}/st_proof_g2.dat", sdir));

	let r_p = PE::Fr::zero(); // as KZG of p(X) is directly used in our app
	let prf = zk.shortcut_prove(
		c_q, prf_q,
		c_w, prf_w, c_w2,
		r_q, r_w, r_p)
		.as_any().
		downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap().clone();

	let claim = zk.shortcut_claim(c_p, c_q, r_q).
		as_any().downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap().clone();
	let bres = zk.verify(&claim, &prf);
	if b_test{
		if RUN_CONFIG.my_rank==0 {assert!(bres, "1st subset proof failed");}
		//println!("## Step8 SelfCheck: 1st subset proof pass!");
	}
	return (prf, claim); 
}

/** generate the 2nd subset proof: acceptance path set +transition set 
belongs to subset claimed 
	dp: the superset
	dq = dp_states x dp_trans (is the subset)
	r_p and r_q are the blinding factor (opening) for the two commitments
	dp, dq.
	RETURN: prf, claim, dq_(states+trans), r_p, r_q 
*/
pub fn gen_subset2_proof<PE:PairingEngine>(dp: &mut DisPoly::<PE::Fr>, dp_states: &mut DisPoly::<PE::Fr>, dp_trans: &mut DisPoly::<PE::Fr>,key: &Rc<DisKey<PE>>,
	r_p: PE::Fr, r_q: PE::Fr) -> (ZkSubsetV3Proof<PE>, ZkSubsetV3Claim<PE>, DisPoly<PE::Fr>, PE::Fr, PE::Fr) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = false;
	let b_test = false;
	let me = RUN_CONFIG.my_rank;
	let mut t1 = Timer::new();
	t1.start();

	//1. load the subset polynomial
	let zk = ZkSubsetV3::<PE>::new(key.clone());
	dp_states.dvec.set_real_len();
	dp_trans.dvec.set_real_len();
	let mut dq = DisPoly::<PE::Fr>::mul(dp_states, dp_trans);
	dq.dvec.set_real_len();
	if !dq.dvec.b_in_cluster{
		dq.dvec.to_partitions(&RUN_CONFIG.univ);
	}
	if b_perf {log_perf(LOG1, &format!("---- GenSubsetPrf2 Step1: dq= dp_states x dp_trans. Size: {}", dq.dvec.len), &mut t1);}

	//let mut rng = gen_rng();
	let (box_prf, box_claim) = zk.prove_direct(dp, &mut dq, r_p, r_q);
	let prf = box_prf.
		as_any().downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap().clone();
	let claim = box_claim.
		as_any().downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap().clone();
	if b_perf {log_perf(LOG1, &format!("---- GenSubsetPrf2 Step2: GenProof. dp: {}, dq: {}", dp.dvec.len, dq.dvec.len), &mut t1);}
	
	if b_test{
		let bres = zk.verify(&claim, &prf);
		if me==0 {assert!(bres, "ZkSubsetPrf2 failed!");}
		log(LOG1, &format!("## ZkSubsetPrf2 PASSED!"));
	}

	return (prf, claim, dq, r_p, r_q);
}

/* Generate enhanced zkvpd proof:
	Claim: 
		Let C_q = g^{q(alpha) h^r_q} be its zk-vpd commitment.
		r the random challenge point
		Let C_z be a G1 element:
	Prove that C_z is the Pedersen commitment to q(r).

	Public input: r, g1, g2 (the (\beta u_i(x) + \alpha v_i(x) + w(x)/delta_2)
		for segment 2 in Groth 16). This segment has ONLY 2 wires.
		delta_k is one of the prover key of Groth16
	ScretInput:
		dq: DisPoly of q. Let z = dq(r)
	Prove that: C_2 = g1^z g2^r1 delta_k^r2 [note that r2 is FIXED 
		we do need r1 as random opening] 
*/
/*
pub fn gen_zkvpd_proof<PE:PairingEngine>(dp: DisPoly<PE::Fr>, key: &Rc<DisKey<PE>>, _claim_subset: &ZkSubsetV3Claim<PE>, _gamma: PE::Fr, _r1: PE::Fr, _r: PE::Fr, _z: PE::Fr, _r2: PE::Fr, _z_g: PE::G1Affine, _z_h: PE::G1Affine) -> (ZkKZGProof<PE>, ZkKZGClaim<PE>) 
where 
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	unimplemented!("buidl_blindeval_proof NOT DONE YET");
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
}
*/
