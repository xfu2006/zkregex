/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 06/28/2022
	Completed: 07/05/2022
	Mostly generating the circuit witness pack for a circuit.
	See main/src/main/java/cs/Employer/acc_driver/AccDriver for details.

	We only use the DisPoly distributed for processing building
the bin-acc polynomial \prod (x-a_i) from a multi-set \{a_i\}.
All other operations are handled by serial version of polynomial
operations.
*/

//use super::super::poly::common::*;
//use super::super::poly::dis_vec::*;
extern crate ark_ff;
extern crate ark_ec;
extern crate ark_poly;
extern crate ark_std;
extern crate mpi;
use super::super::poly::dis_poly::*;
use super::super::poly::serial::*;
use self::ark_ff::{PrimeField,Zero};
//use crate::tools::*;
use self::ark_poly::{DenseUVPolynomial,univariate::DensePolynomial};
use crate::profiler::config::*;
use crate::tools::*;
//use self::mpi::traits::*;
//use mpi::environment::*;
//use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
//use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};

/** generate the circuit pack. Expecting dirpath has the following
two files: states.dat and trans.dat, s_size is the total size
for EACH BigInteger array files (note: it's the DEGREE+1!). 
Pad zero if necessary.
Check main/src/main/java/cs/Employer/acc_driver/AccDriver for details
of each file to be generated.
  All witness polynoamisl will have size: s_size (pad zero on left if needed)
*/ 
pub fn gen_circ_witness_serial<F:PrimeField>(dirpath: &str, s_size: &str){
	println!("gen_circ_witness_serial: {}", dirpath);
	let size:usize = s_size.parse::<usize>().unwrap();

	//1. build the states evidence
	let s_set=gen_circ_witness_for_multiset::<F>(
		dirpath, "states.dat", "S_", size);

	//2. build the trans evidence
	let t_set=gen_circ_witness_for_multiset::<F>(
		dirpath, "trans.dat", "T_", size);


	//3. build the evidence for the they are disjoint
	let mainproc = 0u64;
	if RUN_CONFIG.my_rank==mainproc as usize{
		let (st_gcd, s,t) = feea(&s_set, &t_set);
		let pone = get_poly::<F>(vec![F::from(1u64)]);
		assert!(st_gcd==pone, "s and t not co-prime");
		write_poly_to_file(&s, &format!("{}/witness/S_ST", dirpath), size);
		write_poly_to_file(&t, &format!("{}/witness/T_ST", dirpath), size);
	}
	RUN_CONFIG.better_barrier("gen_circ_serial");
	

}

/** fpath refers to either the state file or trans file (states.dat or
trans.dat). prefix is one of the two optios: S_ or T_,
thus resulting in file names such as S_P etc.
For details of naming convention check main/java/..../acc_driver/AccDriver.java
The function returns P_GCD (the polynomial STANDARD SET, i.e., set-support,
for encoding the bilinear acc)
*/
pub fn gen_circ_witness_for_multiset<F:PrimeField>(dirpath: &str, fname: &str, prefix: &str, size: usize)->DensePolynomial<F>{
	//0. read data and generate the set data
	let mainproc = 0u64;
	let srcfile = &format!("{}/{}", dirpath, fname);
	let fname_gen = &format!("generated_set_{}.dat", fname);
	let nodes_file = "/tmp/tmp_nodelist.txt";
	let netarch = get_network_arch(&nodes_file.to_string());
	let srcfile2 = &format!("{}/{}", dirpath, fname_gen);
	if RUN_CONFIG.my_rank==mainproc as usize{
		let total = read_1st_line_as_u64(srcfile);
		let multi_set:Vec<u64> = read_arr_u64_from(srcfile, 1, total as usize);
		let set_support = get_set_u64(&multi_set);
		write_arr_with_size(&set_support, srcfile2); 
	}
	RUN_CONFIG.better_barrier("gen_circ_multi_set1");
	let mut dp_set = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, 0, &format!("{}/{}", dirpath, fname_gen), &netarch);
	
	//1. build the DisPoly from the roots
	let mut dp = DisPoly::<F>::dispoly_from_roots_in_file_from_mainnode(0, mainproc, &format!("{}/{}", dirpath, fname), &netarch);	
	let pzero = DensePolynomial::<F>::from_coefficients_vec(vec![F::zero()]);
	if RUN_CONFIG.my_rank!=mainproc as usize{ 
		RUN_CONFIG.better_barrier("gen_circ_multi_set2");
		return pzero;
	} 
	//--------------------------------------------------------
	//1.5 THE FOLLOWING ARE PERFORMED BY RANK 0 ONLY!
	//--------------------------------------------------------
	let c1 = dp.coefs();
	let p = DensePolynomial::<F>::from_coefficients_vec(c1);
	write_poly_to_file(&p, &format!("{}/witness/{}P", dirpath, prefix), size);
	
	//3. construct derive, but don't write it as the circuit can generate
	//itself
	let p_d = get_derivative(&p);

	//4. generate the gcd
	let c2 = dp_set.coefs();
	let p_set_support = DensePolynomial::<F>::from_coefficients_vec(c2);

	let (gcd, r0) = new_divide_with_q_and_r(&p, &p_set_support);
	assert!(r0.is_zero(), "r0 is not zero");
	//let (gcd, _s, _t) = feea(&p, &p_d); SOMEHOW feea has but does not
	//work for cases that two inputs are NOT co-prime
	write_poly_to_file(&gcd, &format!("{}/witness/{}GCD", dirpath, prefix), size);

	//5. calculate the p/gcd and pd/gcd
	let p_gcd = p_set_support.clone();
	write_poly_to_file(&p_gcd, &format!("{}/witness/{}P_GCD", dirpath, prefix), size);
	let (pd_gcd, r_2) = new_divide_with_q_and_r(&p_d, &gcd);
	assert!(r_2.is_zero(), "r2 is not zero!");
	write_poly_to_file(&pd_gcd, &format!("{}/witness/{}PD_GCD", dirpath, prefix), size);

	//6. generate the bizou efficients s and t s.t. s*p_gcd + t*pd_gcd = 1
	let (gcdprime, s, t) = feea(&p_gcd, &pd_gcd);
	let pone = get_poly::<F>(vec![F::from(1u64)]);
	assert!(gcdprime==pone, "p_gcd and pd_gcd not co-prime");
	write_poly_to_file(&s, &format!("{}/witness/{}S", dirpath, prefix), size);
	write_poly_to_file(&t, &format!("{}/witness/{}T", dirpath, prefix), size);

	RUN_CONFIG.better_barrier("gen_circ_multi_set3");
	return p_set_support;
}

