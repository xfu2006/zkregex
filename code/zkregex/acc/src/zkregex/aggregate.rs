/** 
	Copyright Dr. CorrAuthor
	Author: Dr. CorrAuthor 
	Created: 03/24/2023
*/

/* ****************************************************************
This file contains proof aggregator which generates aggregate proofs
**************************************************************** */

extern crate ark_ff;
extern crate ark_ec;
extern crate ark_serialize;

use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::{Field,Zero,One};

use tools::*;
use poly::common::*;
use poly::dis_key::*;
use profiler::config::*;
use zkregex::prover::*;
use proto::zk_subset_v3::*;
use proto::Protocol;
use proto::zk_conn::*;
use proto::ripp_driver::*;
use proto::zk_kzg_v2::*;
use groth16::serial_prover::*;
use groth16::aggregate::*;
use zkregex::batch_prover::{get_job_details, get_group_size};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use std::fs::File;
use std::rc::Rc;
use std::collections::HashMap;

/** A job characterizes the same kind of files to prove: group_size
	and sub_group_id whose set-up can be grouped together
*/
pub struct Job{
	/** the upper limit of file size */
	pub file_size: usize,
	/** the subset id to use */
	pub subset_id: usize,
	/** list of proof direcotires: absolute path */
	pub arr_dirs: Vec<String>,
	/** list of original file infor in job.txt like filepath 
		and state info */
	pub arr_info: Vec<String>
}

impl Job{
	pub fn to_string(&self) -> String{
		let mut s = format!("Job: file_size: {}, subset_id: {}. {} Jobs. Details:\n", self.file_size, self.subset_id, self.arr_dirs.len());
		for x in &self.arr_dirs{
			s.push_str( &format!("{}\n", x) );
		}
		return s;
	}

	pub fn name(&self) -> String{
		return format!("Job: file_size: {}, subset_id: {}, Files: {}",
			self.file_size, self.subset_id, self.arr_dirs.len());
	}

	/** return the dump file path in /tmp */
	pub fn get_dump_file_path(&self)->String{
		let res = format!("/tmp/job_{}_{}.txt",  self.file_size, self.subset_id);
		return res;
	}

	/** write all to dump file */
	pub fn write_to_dump(&self){
		let mut s = tos("");
		for finfo in &self.arr_info{
			s = s + &finfo + &tos("\n");
		}
		let fpath = self.get_dump_file_path();
		write_file(&fpath, s);
	}
}

/** consisting of claim, prf, and RC<CRS_Verifier> */
#[derive(Clone)]
pub struct ProcessJob<PE:PairingEngine>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub claim: ZkregexClaim<PE>,
	pub prf: ZkregexProof<PE>,
	pub file_size: usize,
	pub subset_id: usize,
	pub crs: Rc<CRS<PE>>,
	pub info: String,
}

	

impl <PE:PairingEngine> ProcessJob<PE>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// perform the check of the claim (1) kzg matches the one given
	/// and (2) if the hash in claim matches the one in the generated file
	pub fn check_claim(&self, kzg_all: &PE::G1Affine){
		//1. check kzg
		assert!(*kzg_all==self.claim.kzg_all, 
			"kzg_all does not match given! File: {} ", &self.info);
		//2. read the hash and check claim hash
		let vec1 = split_str(&self.info);
		let fpath = &vec1[0];
		let fname = extract_fname(&fpath);
		let par_dir = get_parent_dir(&fpath);
		let hash_file = format!("{}/{}.hash", par_dir, fname);
		let arr_h = read_arr_fe_from::<PE::Fr>(&hash_file);
		let hash = arr_h[0];
		assert!(hash==self.claim.hash, "hash not right for file: {}", fname);
	} 
}

/** Aggregated Claim */
pub struct AggClaim <PE:PairingEngine> 
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	vec_claims: Vec<ZkregexClaim<PE>>,
	vec_conn_claims: Vec<ZkConnClaim<PE>>,
}

/** Aggregated Proof. Could save some space by merge data items
across AggClaims with AggProofs 
(but do so for convenience of implementation).
All except last 3 items are log(n)
Last 3 items are linear
 */
pub struct AggProof<PE:PairingEngine>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	/// size of proof
	pub size: usize,

	/// Subset AggClaim 1 
	pub agg_claim_set1: ZkSubsetV3AggClaim<PE>,			
	/// Subset AggPrf 1
	pub agg_prf_set1: ZkSubsetV3AggProof<PE>,			

	/// Subset AggClaim 2 
	pub agg_claim_set2: ZkSubsetV3AggClaim<PE>,			
	/// Subset AggPrf 2
	pub agg_prf_set2: ZkSubsetV3AggProof<PE>,			

	/// KZG Agg Proof 
	pub agg_claim_kzg: ZkKZGV2AggClaim<PE>,			
	/// Subset AggPrf 2
	pub agg_prf_kzg: ZkKZGV2AggProof<PE>,			

	/// groth16 aggregated claim
	pub agg_claim_groth: Groth16AggClaim<PE>,			
	/// groth16 aggregated proof 
	pub agg_prf_groth: Groth16AggProof<PE>,			

	/// the aggregated proof for connecting file segments
	pub agg_prf_conn: ZkConnAggProof<PE>,

	/// vector of r's (linear component)
	pub v_r: Vec<PE::Fr>, 
	/// vector of c_st (linear component) 
	pub v_c_st: Vec<PE::G1Affine>,
	/// vector of c1 (linear component)
	pub v_c1: Vec<PE::G1Affine>
}



/// read the directory structure (typically batchscripts/results)
/// generate the structure of folder
/// CAN ONLY be run on node 0 ,otherwise return empty list
/// NOTE: np needs to be passed from caller as we cannot use
/// the real MPI np here (it's 1)
pub fn create_job_list(dirpath: &str, np: usize) -> Vec<Job>{
	let me = RUN_CONFIG.my_rank;
	if me!=0 {return vec![];}
	//1. retrieve all child folders with prefix "job"
	let mut vres = vec![];
	let list_sub_dirs = list_dir(dirpath);
	for dir in list_sub_dirs{
		if !is_dir(&dir) {continue;}
		let fname = get_fname(&dir); 
		if !fname.starts_with("job") {continue};
		let (group_id, subset_id) = get_job_details(&format!("{}.txt",fname));	
		let group_size = get_group_size(group_id, np);
		let arr_files = list_dir(&format!("{}/proof",dir));
		let mut arr_dirs = vec![];
		for x in arr_files{
			let full_path =   get_absolute_path(&x);
			arr_dirs.push(full_path);
		}
		let mut arr_info = vec![];
		for prfdir in &arr_dirs{
			let info_file = format!("{}/info.txt", prfdir);
			let lines = read_lines(&info_file);
			let sinfo = &lines[0];	
			arr_info.push(tos(sinfo));
		}

		let job = Job{file_size: group_size, subset_id: subset_id, 
			arr_dirs: arr_dirs, arr_info: arr_info};
		vres.push(job);
	}

	return vres;
} 

/** from job list to ProcessJob List. expand to 2^n */
pub fn to_process_list<PE:PairingEngine>(jobs: &Vec<Job>, prf_dir: &str) 
-> Vec<ProcessJob<PE>>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_test = false;
	let b_perf = false;

	//1. build the job
	let mut vres:Vec<ProcessJob<PE>> = vec![];
	let mut total = 0;
	for job in jobs{
		//1. retrieve the verifier crs
		let crspath= format!("{}/crs/crs_{}_{}.dat", prf_dir, job.file_size,
			job.subset_id);
		let crs_verifier = CRS::<PE>::load_from(&crspath);
		let crs = Rc::new(crs_verifier);
		let mut idx = 0;
		for dir in &job.arr_dirs{
			let prf = ZkregexProof::<PE>::load_from(&dir);
			let claim= ZkregexClaim::<PE>::load_from(&dir);
			if b_test{
				let crs= CRS::<PE>::load_from(&crspath);
				let mut t3 = Timer::new();
				let bres = zk_verify(&claim, &prf, &crs);
				if b_perf{ log_perf(LOG1, "zk_verify", &mut t3); }
				assert!(bres, "FAILED loaded proof!");
				println!("PASSED verification for pair: {}", vres.len());					}
			let info = job.arr_info[idx].clone();
			let proc_job = ProcessJob::<PE>{
				subset_id: job.subset_id,
				file_size: job.file_size,
				prf: prf,
				claim: claim,
				crs: crs.clone(),
				info: info,
			};
			vres.push(proc_job);
			idx += 1;
		}
		total += job.arr_dirs.len();
	}

	assert!(total==vres.len(),"vres.len(): {} != total: {}", vres.len(), total);
	//2. expand
	let new_total = closest_pow2(total);
	assert!(new_total>=total, "newtotal: {} < total: {}", new_total, total);
	let num_more = new_total - total;
	let last_rec = vres[vres.len()-1].clone();
	log(LOG1, &format!("to_proc_list: actual: {} -> new_total: {}", 
		total, new_total));
	for _i in 0..num_more{ vres.push(last_rec.clone()); } 
	return vres;	
}

/// expand the list by replicating last entry
pub fn expand_job_list<PE:PairingEngine>(
vecjob: &mut Vec<ProcessJob<PE>>, target_n: usize) 
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	if target_n < vecjob.len() {return;}
	let last_entry = vecjob[vecjob.len()-1].clone();	
	let num_more = target_n - vecjob.len();
	for _i in 0..num_more{
		vecjob.push(last_entry.clone());
	}
}


/// expand the list by replicating last entry
pub fn expand_conninp_list<PE:PairingEngine>(
vecjob: &mut Vec<ZkConnInput<PE>>, target_n: usize) 
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	if target_n < vecjob.len() {return;}
	let last_entry = vecjob[vecjob.len()-1].clone();	
	let num_more = target_n - vecjob.len();
println!("REMOVE LATER 202: num_more: {}", num_more);
	for _i in 0..num_more{
		vecjob.push(last_entry.clone());
	}
}

/** set up based on the jobs because it needs CRS, target_n
is for profiling purpose. If total size<target_n extend key size
to cloest_pow2(target_n) */
pub fn agg_setup<PE:PairingEngine>(jobs: &Vec<Job>, prf_dir: &str, fd: &mut File, target_n: usize, ac_dir:&str)
->(GIPA::<PE>, Rc<DisKey<PE>>, Vec<Rc<CRS<PE>>>, Vec<ProcessJob<PE>>, Vec<ZkConnInput<PE>>)
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;

	//let me = RUN_CONFIG.my_rank;
	let np = RUN_CONFIG.n_proc;
	let mut t1 = Timer::new();
	t1.start();

	let key_size = if np<16 {32} else {np*16};
	let key = Rc::new(DisKey::<PE>::gen_key1(key_size));
	let mut job_list = to_process_list::<PE>(jobs, prf_dir); 
	let mut conn_list = vec_procjobs_to_vec_conninput(&job_list); 
	let target_n = closest_pow2(target_n);
	let n2= closest_pow2(job_list.len());
	let target_n = if target_n>n2 {target_n} else {n2};
	expand_job_list(&mut job_list, target_n);
	expand_conninp_list(&mut conn_list, target_n);
	let g10s = extract_conn_gs(&conn_list);
	let n = job_list.len();
	let mut v_crs = vec![];	
	for i in 0..n{
		//1.1 global level vec
		let crs = &job_list[i].crs;
		v_crs.push(crs.clone());
	}
	let g5s = extract_g5s(&v_crs);
	let gipa = GIPA::<PE>::setup(n, &key, &g5s, &v_crs, &g10s, ac_dir);
	if b_perf {flog_perf(LOG1, &format!("AggSetup size: {}", n), &mut t1, fd);}
	return (gipa, key, v_crs, job_list, conn_list);
}

/** aggregate proofs. Last param: target_n expands jobs by replicating
last entry to the desired target_n size, for profiling purpose. */
pub fn agg_prove<PE:PairingEngine>(job_list: &Vec<ProcessJob<PE>>, 
	arr_conn_inp: &Vec<ZkConnInput<PE>>,
	_prf_dir: &str, gipa: &GIPA::<PE>, key: &Rc<DisKey<PE>>,
	fd: &mut File, _target_n: usize)
->(AggClaim<PE>,AggProof<PE>)
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let b_test = false;
	let mut t1 = Timer::new();
	t1.start();

	//1. collect claims prfs and crs
	let n = job_list.len();
	assert!(n.is_power_of_two(), "job_list len not power of 2");

	let mut v_claims = vec![];
	let mut v_crs = vec![];

	let mut v_claims_set1 = vec![];
	let mut v_prfs_set1 = vec![];

	let mut v_claims_set2 = vec![];
	let mut v_prfs_set2 = vec![];

	let mut v_claims_kzg = vec![];
	let mut v_prfs_kzg = vec![];

	let mut v_groth_prf1 = vec![];
	let mut v_groth_prf2 = vec![];

	let mut v_r = vec![];
	let mut v_c_st = vec![];
	let mut v_c1 = vec![];

	for i in 0..n{
		//1.1 global level vec
		let job = &job_list[i];
		let zkprf = &job_list[i].prf;
		let zkclaim = &job_list[i].claim;
		let crs = &job_list[i].crs;
		if b_test{
			let bres = zk_verify(&zkclaim, &zkprf, &crs);
			assert!(bres, "zk_verify failed for {}", i); 
		}
		v_claims.push(job.claim.clone());
		v_crs.push(job_list[i].crs.clone());

		//1.2 for subset_prf1: subset_i \in all_trans_states
		let claim = ZkSubsetV3Claim::<PE>{
			c_p: zkclaim.kzg_all,
			c_q: zkprf.c_subset,  
		};
		v_claims_set1.push(claim);
		v_prfs_set1.push(zkprf.subset1_prf.clone());

		//1.3 for subset_prf2: st from accept path \in subset_i
		let claim2 = ZkSubsetV3Claim::<PE>{
			c_p: zkprf.c_subset.clone(),
			c_q: zkprf.c_st.clone(),  
		};
		v_claims_set2.push(claim2);
		v_prfs_set2.push(zkprf.subset2_prf.clone());

		//1.4 for kzg proof: 
		let claim_kzg= ZkKZGV2Claim::<PE>{
			c_p: zkprf.c_st.clone(),
			c_z: zkprf.c2.clone(), 
			r: zkprf.r,
			g1: crs.g1.clone(),
			g2: crs.g2.clone(),
			g3: crs.g3.clone(),
			g4: crs.g4.clone(),
			g5: crs.g5.clone(),
		};
		let prf_kzg = zkprf.kzg_prf.clone();
		v_claims_kzg.push(claim_kzg);
		v_prfs_kzg.push(prf_kzg);

		//1.5 build groth16 note prf2.io has the "claim"
		let r= zkprf.r;
		let inv_r = r.inverse().unwrap();
		let myhash = zkclaim.hash.clone();
		let io =  vec! [PE::Fr::from(1u32), myhash, r, inv_r];
		let part1 = ProofPart1::<PE>{
			arr_c: vec![ zkprf.c1 ],
			io: io.clone(),
		};
		let part2 = ProofPart2::<PE>{
			a: zkprf.a.clone(),
			b: zkprf.b.clone(),
			arr_c: vec![zkprf.c2.clone()],
			last_c: zkprf.c3,
			io: io.clone(),
		};
		v_groth_prf1.push(part1);
		v_groth_prf2.push(part2);
		
		//1.6 linear component
		v_r.push(zkprf.r.clone());
		v_c_st.push(zkprf.c_st.clone());
		v_c1.push(zkprf.c1.clone());
	}
	//let g5s = extract_g5s(&v_crs);
	//let gipa = GIPA::<PE>::setup(n, &key, &g5s, &v_crs);
	if b_perf {flog_perf(LOG1, &format!("AggProve Step 1: Build Vec of Claims and Proofs: {} Proofs", job_list.len()), &mut t1,fd);}

	//2. do batch proof subset proof 1
	let (agg_claim_set1, agg_prf_set1) = ZkSubsetV3::<PE>::
		agg_prove(&v_claims_set1, &v_prfs_set1, &gipa, &key);
	if b_perf {flog_perf(LOG1, &format!("AggProve Step 2: Aggregate SubsetPrf1"), &mut t1,fd);}


	//3. do batch proof subset proof 2
	let (agg_claim_set2, agg_prf_set2) = ZkSubsetV3::<PE>::
		agg_prove(&v_claims_set2, &v_prfs_set2, &gipa, &key);
	if b_perf {flog_perf(LOG1, &format!("AggProve Step 3: Aggregate SubsetPrf2"), &mut t1,fd);}

	//4. do kzg proof
	let (agg_claim_kzg, agg_prf_kzg) = ZkKZGV2::<PE>::
		agg_prove(&v_claims_kzg, &v_prfs_kzg, &gipa, &key);
	if b_perf {flog_perf(LOG1, &format!("AggProve Step 4: Aggregate KZGProof"), &mut t1,fd);}

	//5. do groth16 batch proof
	let (agg_claim_groth, agg_prf_groth) = 
		groth16_agg_prove::<PE>(&v_groth_prf1, &v_groth_prf2, &gipa, &v_crs);
	if b_perf {flog_perf(LOG1, &format!("AggProve Step 5: Aggregate Groth16"), &mut t1,fd);}

	//6. do the batch proof of ZkConnProof
	let (arr_claims_conn, agg_prf_conn) = ZkConn::<PE>::
		batch_prove(&arr_conn_inp, gipa, key);


	//6. assemble data
	let size = v_claims.len();
	let a_claim = AggClaim::<PE>{
		vec_claims: v_claims,
		vec_conn_claims: arr_claims_conn,
	};

	let a_prf = AggProof::<PE>{
		size: size,
		agg_claim_set1: agg_claim_set1,
		agg_prf_set1: agg_prf_set1,
		agg_claim_set2: agg_claim_set2,
		agg_prf_set2: agg_prf_set2,
		agg_claim_kzg: agg_claim_kzg,
		agg_prf_kzg: agg_prf_kzg,
		agg_claim_groth: agg_claim_groth,
		agg_prf_groth: agg_prf_groth,
		agg_prf_conn: agg_prf_conn,

		v_r: v_r, v_c_st: v_c_st, v_c1: v_c1
	};
	return (a_claim, a_prf);
}

pub fn agg_verify<PE:PairingEngine>(claim: &AggClaim<PE>, prf: &AggProof<PE>, 
	gipa: &GIPA::<PE>, key: &Rc<DisKey<PE>>, v_crs: &Vec<Rc<CRS<PE>>>, 
	fd: &mut File)->bool
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let b_perf2 = true;
	let mut t1 = Timer::new();
	let mut t2 = Timer::new();
	let me = RUN_CONFIG.my_rank;
	t1.start();

	//1. verify groth
	let b_groth = groth16_agg_verify(&prf.agg_claim_groth, 
		&prf.agg_prf_groth, &gipa);
	if me==0 && !b_groth{
		log(LOG1, &tos("WARN: failed groth16 aggprf"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step1: Groth16"), 
		&mut t1, fd);}

	//2. verify r is the hash of c_st and c1
	for i in 0..prf.v_r.len(){
		let r = prf.v_r[i];
		let c_st = prf.v_c_st[i];
		let c1 = prf.v_c1[i];
		let exp_r = hash::<PE::Fr>(&to_vecu8(&vec![c_st, c1]));
		if me==0 && exp_r!=r{ log(LOG1, &format!(
				"WARN: failed linear check r = hash(c_st, c1) for prf {}", i));
			return false;
		}
	} 
	if b_perf {flog_perf(LOG1, &format!(
		"AggVerify: Step2: LinearCheck: for all: r=hash(c_st,c1)"), 
		&mut t1, fd);}

	//3. verify subset1 proof
	let b_set1= ZkSubsetV3::<PE>::agg_verify(&prf.agg_claim_set1, 
		&prf.agg_prf_set1, gipa, key);
	if me==0 && !b_set1{
		log(LOG1, &tos("WARN: failed subset1 aggprf"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step3: subset1 proof"), 
		&mut t1, fd);}

	//4. verify subset2 proof
	let b_set2= ZkSubsetV3::<PE>::agg_verify(&prf.agg_claim_set2, 
		&prf.agg_prf_set2, gipa, key);
	if me==0 && !b_set2{
		log(LOG1, &tos("WARN: failed subset2 aggprf"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step4: subset2 proof"), 
		&mut t1, fd);}

	//5. verify zk_kzg proof
	let b_kzg= ZkKZGV2::<PE>::agg_verify(&prf.agg_claim_kzg, 
		&prf.agg_prf_kzg, gipa, key);
	if me==0 && !b_kzg{
		log(LOG1, &tos("WARN: failed kzg aggprf"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step5: kzg proof"), 
		&mut t1, fd);}

	//6. check relation between claim and subset1
	//let mut v_cp = vec![];
	//for i in 0..claim.vec_claims.len(){
	//	v_cp.push(claim.vec_claims[i].kzg_all.clone());
	//}
	//let exp_c_cp = gipa.cm1(&vec_affine_to_proj::<PE>(&v_cp));
	let exp_c_cp = gipa.c_kzg_all.clone();
	if me==0 && exp_c_cp != prf.agg_claim_set1.c_cp{
		log(LOG1, &tos("WARN: check claim.kzg_all=agg_claim_set.c_cp"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step6: compute cm1(kzg_all) and check agg_claim_set1.c_cp"), &mut t1, fd);}

	//7. check relation between subset1 and subset2
	if me==0 && prf.agg_claim_set1.c_cq !=prf.agg_claim_set2.c_cp{
		log(LOG1, &tos("WARN: check agg_subset1_claim.c_cq == subset2.c_cp"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step7: check subset1.c_cq = subset2.c_cp"), &mut t1, fd);}

	//8. check relation between subset2 and kzg
	if me==0 && prf.agg_claim_set2.c_cq != prf.agg_claim_kzg.c_cp{
		log(LOG1, &tos("WARN: fails set2.c_cq = kzg.c_cp"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step8: check set2.c_cq = kzg.c_cp"), &mut t1, fd);}

	//9. check relation between r, kzg, and groth
	let mut v_neg_r = vec![];
	let zero = PE::Fr::zero();
	for i in 0..prf.v_r.len(){
		v_neg_r.push(zero - prf.v_r[i]);
	}
	let exp_c_neg_r = gipa.cmz(&v_neg_r);
	if me==0 && exp_c_neg_r != prf.agg_claim_kzg.c_neg_r{
		log(LOG1, &tos("WARN: fails c_neg_r"));
		return false;
	}

	let exp_c1 = gipa.cm1(&vec_affine_to_proj::<PE>(&prf.v_c1));
	if me==0 && exp_c1!= prf.agg_prf_groth.v_cg1[3]{
		log(LOG1, &tos("WARN: fails c_c1"));
		return false;
	}

	let exp_c_st = gipa.cm1(&vec_affine_to_proj::<PE>(&prf.v_c_st));
	if me==0 && exp_c_st!= prf.agg_claim_kzg.c_cp{
		log(LOG1, &tos("WARN: fails c_st"));
		return false;
	}
	
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step9: check vec r, c1, c_st match their commitments in claims"), &mut t1, fd);}

	//10. check hash is included in groth
	let mut vec_io = vec![];
	for i in 0..claim.vec_claims.len(){
		let hash = claim.vec_claims[i].hash;
		let r = prf.v_r[i];
		let inv_r = r.inverse().unwrap();
		let io = [PE::Fr::one(), hash, r, inv_r];
		let vkey = &v_crs[i].verifier_key;
		let gamma_abc = vkey.gamma_abc_g1.clone();
		let mut abc_io = gamma_abc[0].mul(io[0]);
		for i in 1..gamma_abc.len(){
			abc_io = abc_io + gamma_abc[i].mul(io[i]);
		}
		vec_io.push(abc_io.into_affine());
	}
	let c_io2 = gipa.cm1(&vec_affine_to_proj::<PE>(&vec_io));
	if me==0 && c_io2 != prf.agg_claim_groth.c_io{
		log(LOG1, &tos("WARN: fails c_io2"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step10: check all hash contained in Groth16 claims."), &mut t1, fd);}

	//11. check the zk_conn_agg proof
	let b_conn = ZkConn::<PE>::agg_verify(&claim.vec_conn_claims, 
		&prf.agg_prf_conn, gipa, key);
	if me==0 && !b_conn{
		log(LOG1, &tos("WARN: fails connector proofs"));
		return false;
	}
	if b_perf {flog_perf(LOG1, &format!("AggVerify: Step11: check connector prf."), &mut t1, fd);}

	

	if b_perf2 {flog_perf(LOG1, &format!("PERF_USE_AggVerify size: {}", &prf.size), &mut t2, fd);}
	return true;
}

/// check if ALL claims are well formed.
/// mainly recompute the encrypted hash of all files
/// encrypted files will be written into the same folder of elfs/
/// will double the size of files
/// encrypte files will be suffixed with .encrypted
/// hash file will be suffixed with .hash
/// NOTE: somehow it fails to work with _xPart (chunked files)
/// TODO: fix later but not affecting proof correctness 
pub fn check_claims<PE:PairingEngine>(jobs: &Vec<Job>, b_regen_padd: bool,
	b_encrypt: bool, b_hash: bool, curve_type: &str, ac_dir: &str, 
	param_file: &str, dfa_sigs: &str, np: usize, prf_dir: &str)
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let b_perf = true;
	let mut t1 = Timer::new();
	t1.start();

	if b_regen_padd{ gen_java(jobs, curve_type, ac_dir, param_file, dfa_sigs, np, "batch_pad");}	
	if b_encrypt{ gen_java(jobs, curve_type, ac_dir, param_file, dfa_sigs, np, "encrypt");}	
	if b_hash{ gen_java(jobs, curve_type, ac_dir, param_file, dfa_sigs, np, "hash");}	
	if b_perf {log_perf(LOG1, &tos("CheckClaims Step1: enc/hash all files"), &mut t1);}

	let proc_jobs = to_process_list::<PE>(jobs, prf_dir);
	if b_perf {log_perf(LOG1, &tos("CheckClaims Step2: gen_proc_list"), &mut t1);}

	let kzg_all= read_ge::<PE::G1Affine>(&format!("{}/st_kzg.dat", ac_dir));
	for proc_job in proc_jobs{
		proc_job.check_claim(&kzg_all);	
	}
	if b_perf {log_perf(LOG1, &tos("CheckClaims Step3: check_each_job"), &mut t1);}
}


/// generate a vector of java parameters to run main program
/// allocate resource at the best
/// full mode needs 16G, if node <=4 regard as small experiment
/// return the vec of strings and number of workers
pub fn gen_java_params(b_multh: bool, params_file: &str) -> 
	(Vec<String>, usize) {
	let b_debug = false;
	let vs = read_arrlines(&tos(params_file));
	let mut line = vs[0].clone(); //assume only one line
	for li in vs{ if !li.starts_with("#") {line = li.clone();} }	
	let mut vec1 = split_str(&line);
	let sys_ram = get_sys_mem();
	let small_sys = sys_ram < 16*1024*1024*1024;
	let gb = 1024*1024*1024;
	let ram_per_worker = if small_sys {2} else {16}; 
	let num_workers = if b_multh {sys_ram*3/(4*ram_per_worker*gb)} else {1};
	let mut ram_alloc = tos("");
	for id in 0..vec1.len(){
		if vec1[id].starts_with("-Xmx"){
			if b_multh{
				vec1[id] = format!("-Xmx{}g", (ram_per_worker*num_workers));
			}
			ram_alloc = vec1[id].clone();	
		}
	}
	if b_debug {log(LOG1, &format!("Java RAM Plan: sys_ram: {}, small_sys: {}, num_workers: {}, b_multhread: {}, allocated: {}", sys_ram, small_sys, num_workers, b_multh, ram_alloc));}
	
	return (vec1, num_workers);
}

/// generated the padded version for all jobs, mainly by invoking java/jsnark
/// NOTE: we are actually running in single mode
/// curve_type: BLS12-381 or BN254, ac_dir: where are the ACDFA outputs
/// param_file: the java parameters to run main App
/// dfa-sigs: dfa-signature file
/// np: number of parallel processes (info need for padding)
/// op could be "batch_pad", "encrypt", "hash"
pub fn gen_java(jobs: &Vec<Job>, curve_type: &str, 
		ac_dir: &str, param_file: &str, dfa_sigs: &str, np: usize,
		op: &str){
	let b_perf = true;
	let mut t1 = Timer::new();
	let (vec, num_workers)  = gen_java_params(true, param_file);

	let skey = "12345678";
	for job in jobs{
		job.write_to_dump();
		let mut vec1 = vec.clone();
		let mut vec2 = vec![
			tos("multh_op"),
			job.get_dump_file_path(),
			format!("{}", num_workers),
			tos(ac_dir),
			tos(curve_type),
			tos(dfa_sigs),
			format!("{}", np),
			tos(op),
			tos(skey),
		];
		vec1.append(&mut vec2);
		let sres = run_in_dir("java", &vec1, &tos("../main"));
		//log(LOG1, &format!("RESULT: {}", sres));
		if sres.contains("FATAL"){
			panic!("(JAVA) preprocessing fatal err: {}", &sres);	
		}
		
		if b_perf {log_perf(LOG1, &format!(" -- {} files for {}", 
			op, job.name()), &mut t1);}
	}	
}

impl <E:PairingEngine> AggProof<E>
where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	pub fn to_bytes(&self)->Vec<u8>{
		let mut b_all: Vec<u8> = vec![];
		usize::serialize(&self.size, &mut b_all).unwrap();
		let mut b1 = self.agg_claim_set1.to_bytes();
		let mut b2 = self.agg_prf_set1.to_bytes();
		b_all.append(&mut b1);
		b_all.append(&mut b2);

		let mut b1 = self.agg_claim_set2.to_bytes();
		let mut b2 = self.agg_prf_set2.to_bytes();
		b_all.append(&mut b1);
		b_all.append(&mut b2);

		let mut b1 = self.agg_claim_kzg.to_bytes();
		let mut b2 = self.agg_prf_kzg.to_bytes();
		b_all.append(&mut b1);
		b_all.append(&mut b2);

		let mut b1 = self.agg_claim_groth.to_bytes();
		let mut b2 = self.agg_prf_groth.to_bytes();
		b_all.append(&mut b1);
		b_all.append(&mut b2);

		let mut b1 = self.agg_prf_conn.to_bytes();
		b_all.append(&mut b1);

		assert!(self.size==self.v_r.len(), "size != v_r.len");
		for i in 0..self.size{
			self.v_r[i].serialize(&mut b_all).unwrap();
			self.v_c_st[i].serialize(&mut b_all).unwrap();
			self.v_c1[i].serialize(&mut b_all).unwrap();
		}

		return b_all;
	}
	pub fn from_bytes(v_inp: &Vec<u8>, gipa: &GIPA<E>)->Self{
		let mut v = &v_inp[..];
		let size= usize::deserialize(&mut v).unwrap();		
		let mut pos = 0;
		let mut b1 = &v[pos..];
	
		let agg_claim_set1 = ZkSubsetV3AggClaim::<E>::
			from_bytes(&b1.to_vec());
		pos += agg_claim_set1.to_bytes().len();
		b1 = &v[pos..];
		let agg_prf_set1 = ZkSubsetV3AggProof::<E>::
			from_bytes(&b1.to_vec(), gipa);
		pos += agg_prf_set1.to_bytes().len();
		b1 = &v[pos..];

		let agg_claim_set2 = ZkSubsetV3AggClaim::<E>::
			from_bytes(&b1.to_vec());
		pos += agg_claim_set2.to_bytes().len();
		b1 = &v[pos..];
		let agg_prf_set2 = ZkSubsetV3AggProof::<E>::
			from_bytes(&b1.to_vec(), gipa);
		pos += agg_prf_set2.to_bytes().len();
		b1 = &v[pos..];

		let agg_claim_kzg= ZkKZGV2AggClaim::<E>::
			from_bytes(&b1.to_vec());
		pos += agg_claim_kzg.to_bytes().len();
		b1 = &v[pos..];
		let agg_prf_kzg= ZkKZGV2AggProof::<E>::
			from_bytes(&b1.to_vec(), gipa);
		pos += agg_prf_kzg.to_bytes().len();
		b1 = &v[pos..];

		let agg_claim_groth= Groth16AggClaim::<E>::from_bytes(&b1.to_vec());
		pos += agg_claim_groth.to_bytes().len();
		b1 = &v[pos..];
		let agg_prf_groth= Groth16AggProof::<E>::
			from_bytes(&b1.to_vec(), gipa);
		pos += agg_prf_groth.to_bytes().len();
		b1 = &v[pos..];

		let agg_prf_conn = ZkConnAggProof::<E>::from_bytes(&b1.to_vec(), gipa);
		pos += agg_prf_conn.to_bytes().len();
		b1 = &v[pos..];

		let mut v_r = vec![];
		let mut v_c_st = vec![];
		let mut v_c1 = vec![];
		for _i in 0..size{
			let r = E::Fr::deserialize(&mut b1).unwrap();
			v_r.push(r);
			let c_st = E::G1Affine::deserialize(&mut b1).unwrap();
			v_c_st.push(c_st);
			let c1 = E::G1Affine::deserialize(&mut b1).unwrap();
			v_c1.push(c1);
		}

		let res = Self{
			size: size,
			agg_claim_set1: agg_claim_set1,
			agg_prf_set1: agg_prf_set1,
			agg_claim_set2: agg_claim_set2,
			agg_prf_set2: agg_prf_set2,
			agg_claim_kzg: agg_claim_kzg,
			agg_prf_kzg: agg_prf_kzg,
			agg_claim_groth: agg_claim_groth,
			agg_prf_groth: agg_prf_groth,
			agg_prf_conn: agg_prf_conn,
			v_r: v_r,
			v_c_st: v_c_st,
			v_c1: v_c1
		};
		return res;
	}
}

pub fn vec_procjobs_to_vec_conninput<PE:PairingEngine>(v: &Vec<ProcessJob<PE>>)
-> Vec<ZkConnInput<PE>>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	//1. collect parts and name
	let b_test = true;
	let me = RUN_CONFIG.my_rank;
	let mut store = HashMap::<String,Vec<(ProcessJob<PE>, usize)>>::new(); 
	for i in 0..v.len(){
		let (name, has_part, part_id) = get_parts_info(&v[i].info);
		if has_part{
			let mut vec:Vec<(ProcessJob<PE>,usize)> = vec![];
			if store.contains_key(&name){
				vec = store.get(&name).unwrap().to_vec();
			}
			vec.push( (v[i].clone(), part_id) );
			store.insert(name, vec);
		}
	}

	//2. construct the vec of inputs for ZkConn
	let mut res: Vec<ZkConnInput<PE>> = vec![];
	for (_fname, vec) in store{
		let n = vec.len();
		for i in 0..n-1{//n-1 pairs
			//1. find 1st and 2nd job 
			let mut job1 = &vec[0].0;
			let mut job2 = &vec[0].0;
			for j in 0..vec.len(){ if vec[j].1==i{ job1 = &vec[j].0; } }
			for j in 0..vec.len(){ if vec[j].1==i+1{ job2 = &vec[j].0; } }

			//2. build the zkConnInput
			let aux1 = &job1.prf.aux.aux_kzg;
			assert!(!aux1.is_dummy(), "aux1 is dummy");
			let crs1 = &job1.crs;
			let (y1, s11, sn1, r41, r51) = (aux1.y.clone(), aux1.s1.clone(), aux1.sn.clone(), aux1.r4.clone(), aux1.r5.clone());
			let (g11, g21, g31, g41, g51) = (crs1.g1.clone(), crs1.g2.clone(), crs1.g3.clone(), crs1.g4.clone(), crs1.g5.clone());

			let aux2 = &job2.prf.aux.aux_kzg;
			assert!(!aux2.is_dummy(), "aux2 is dummy");
			let crs2 = &job2.crs;
			let (y2, s12, sn2, r42, r52) = (aux2.y.clone(), aux2.s1.clone(), aux2.sn.clone(), aux2.r4.clone(), aux2.r5.clone());
			let (g12, g22, g32, g42, g52) = (crs2.g1.clone(), crs2.g2.clone(), crs2.g3.clone(), crs2.g4.clone(), crs2.g5.clone());
			let mut inp = ZkConnInput::<PE>{
				y1:y1, s11: s11, sn1: sn1, r41: r41, r51: r51, 
				y2:y2, s12: s12, sn2: sn2, r42: r42, r52: r52, 
				g11: g41, g21: g11, g31: g21, g41: g31, g51: g51,
				g12: g42, g22: g12, g32: g22, g42: g32, g52: g52,
			};
			if b_test{
				//1. check zk_conn proof
				let mut inp2 = inp.clone();
				let mut size = n;
				let np = RUN_CONFIG.n_proc; //some would crash if size < np
				size = if size>2*np+16 {size} else {2*np+16};
				let key = Rc::new(DisKey::<PE>::gen_key1(size));
				let zk =  ZkConn::<PE>::new(key.clone());
				let cl= zk.claim(&mut inp2);
				let p1= zk.prove(&mut inp);
				let claim=cl.as_any().
					downcast_ref::<ZkConnClaim<PE>>().unwrap(); 
				let proof=p1.as_any().
					downcast_ref::<ZkConnProof<PE>>().unwrap(); 
				let bres = zk.verify(claim, proof);
				if me==0 {assert!(bres, "failed zkconn proof");}
	
				//2. check matching of c1 and c2
				if me==0{
					assert!(claim.c_1==job1.prf.c2, "c1 does not match job1");
					assert!(claim.c_2==job2.prf.c2, "c2 does not match job2");
				}
			}
			res.push(inp);
		}//for each pair
	} //for (fname, vec)
	return res;
}

/// extract from the information of file name, whether
/// it has parts and the current part ID
pub fn get_parts_info(info: &String) -> (String, bool, usize){
	let arr = info.split(" ").collect::<Vec<&str>>();
	let fname = arr[0];
	let arr2 = fname.split("_partx71_").collect::<Vec<&str>>();
	if arr2.len()==2{
		let part_id = arr2[1].parse::<usize>().unwrap();
		return (tos(arr2[0]), true, part_id);
	}else if arr2.len()==1{
		return (tos(arr2[0]), false, 0);
	}else{
		panic!("ERROR processing: {}", info);
	}
}

/// extractor the bases
/// return a 2d array of 10 elements, each is an array of G1 elements
pub fn extract_conn_gs<PE:PairingEngine>(vinp: &Vec<ZkConnInput<PE>>) -> Vec<Vec<PE::G1Affine>>
where
 <<PE as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G1Affine, Scalar=<<PE  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<PE as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=PE::G2Affine, Scalar=<<PE  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let mut v2d = vec![vec![]; 10];
	for i in 0..vinp.len(){
		let rec = &vinp[i];
		let vec = vec![ 
			rec.g11.clone(), rec.g21.clone(), rec.g31.clone(), 
			rec.g41.clone(), rec.g51.clone(), 
			rec.g12.clone(), rec.g22.clone(), rec.g32.clone(), 
			rec.g42.clone(), rec.g52.clone()];
		for j in 0..10{ v2d[j].push(vec[j]); }
	}
	return v2d;
}


