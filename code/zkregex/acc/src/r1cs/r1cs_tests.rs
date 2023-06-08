/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/25/2022
*/

//use crate::profiler::config::*;


#[cfg(test)]
mod tests{
	extern crate ark_bn254;
	extern crate ark_ff;
	extern crate ark_poly;

	use crate::profiler::config::*;
	use r1cs::serial_r1cs::*;
	use self::ark_ff::{Zero,UniformRand,FftField,Field};
	use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
	use r1cs::dis_r1cs::*;
	use tools::*;
	use poly::dis_vec::*;
	use poly::common::*;
	//use groth16::serial_qap::*;

	use self::ark_bn254::Bn254;
	type Fr = ark_bn254::Fr;
	type PE= Bn254;

	/// return the minimum size required for the cluster size
	pub fn get_min_test_size()->usize{
		let np = RUN_CONFIG.n_proc as usize;
		return np*np;
	}

	/// generate a random vector of field elements
	pub fn rand_vec_fe(n: usize)->Vec<Fr>{
		let mut vec = vec![Fr::zero(); n];
		let mut rng = gen_rng();
		for i in 0..n{
			vec[i] = Fr::rand(&mut rng);
		}
		return vec;
	}
/*
	#[test]
	fn test_r1cs_rand_inst(){
		let n = get_min_test_size();
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, n, n, false);
		assert!(r1cs.is_satisfied(&vars)==false, "serial_r1cs failed on false test");
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, n, n, true);
		assert!(r1cs.is_satisfied(&vars)==true, "serial_r1cs failed on true test");
	}


	#[test]
	fn test_r1cs_to_from_bytes(){
		let mut rng = gen_rng();
		let mut matrix = vec![];
		let n = 100;
		for _i in 0..n{
			let row = rand_row::<Fr>(3, n, &mut rng);
			matrix.push(row);
		}
		let barr = LinearTerm::<Fr>::matrix_to_bytes(&matrix);
		let matrix2 = LinearTerm::<Fr>::matrix_from_bytes(&barr);
		assert!(matrix==matrix2, "matrix to/from bytes failed");
	}

	#[test]
	fn test_r1cs_serialization(){
		let n = get_min_test_size();
		let (r1cs,_vars) = R1CS::<Fr>::rand_inst(1122u128, n, n, false);
		let dr1cs = DisR1CS::<Fr>::from_serial(&r1cs);
		let r1cs2 = dr1cs.to_serial();
		if RUN_CONFIG.my_rank==0{
			if r1cs!=r1cs2{
				r1cs.dump("r1cs1");
				r1cs2.dump("r1cs2");
			}
			assert!(r1cs==r1cs2, "r1cs to DisR1cs test failed");
		}
	}

	#[test]
	fn test_sparse_ifft(){
		let n = 172;
		let mut rng = gen_rng();
		let vec = rand_row(n, n, &mut rng);
		let vec_coef = slow_sparse_ifft(&vec, n);
		let n2 = vec_coef.len() as u64;
		let omega = Fr::get_root_of_unity(n2).unwrap();
		let p = DensePolynomial::<Fr>::from_coefficients_vec(vec_coef);
		for i in 0..vec.len(){
			let exp = vec[i].index as u64;
			let omega_i = omega.pow(&[exp]);
			let v2 = p.evaluate(&omega_i);
			assert!(v2==vec[i].value, "sparse ifft test fails on i: {}, v1: {}, v2: {}", i, vec[i].value, v2);
		}
	}	

	#[test]
	fn test_matrix_to_qap_poly_eval(){
		let n = 256;
		let mut rng = gen_rng(); 
		let matrix = rand_matrix(n, n, 3, &mut rng);
		let t = Fr::rand(&mut rng);
		let v1 = slow_matrix_to_qap_poly_eval(&matrix, n, n, t);
		let v2 = matrix_to_qap_poly_eval(&matrix, n, n, t);
		assert!(v1==v2, "fail test_matrix_to_qap_poly_eval");
	}
	#[test]
	fn test_dis_matrix_to_qap_poly_eval(){
		let np = RUN_CONFIG.n_proc as usize;
		let my_rank = RUN_CONFIG.my_rank as usize;
		let n = 16 * np;
		let unit_size = (n+1)/np;
		let mut rng = gen_rng_from_seed(3117u128);  //GOT TO USE SAME among nodes!!!

		let matrix = rand_matrix(n, n, 3, &mut rng);
		let t = Fr::rand(&mut rng);
		let v1 = if my_rank==0 {matrix_to_qap_poly_eval(&matrix, n, n, t)} else {vec![]};
		RUN_CONFIG.better_barrier("test_dis_matrix_to_qap");
		let start_idx = unit_size * my_rank;
		let end_idx = if my_rank<np-1 {unit_size*(my_rank+1)} else {n};
		let my_share = matrix[start_idx..end_idx].to_vec();
		let dis_v2 = dis_matrix_to_qap_poly_eval(&my_share, n, n, start_idx, t);
		let v2 = dis_v2.collect_from_partitions(&RUN_CONFIG.univ);
		if RUN_CONFIG.my_rank==0{ 
			assert!(v1==v2, "fail dis_test_matrix_to_qap_poly_eval");
		}
	}

	#[test]
	fn test_compute_witness_h(){
		if RUN_CONFIG.my_rank!=0{
			RUN_CONFIG.better_barrier("test_slow_compute_witness_h");
			return;
		}
		let mut rng = gen_rng();
		let size = get_min_test_size();
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, size, size, true);
		let n = closest_pow2(r1cs.a.len());
		let poly_z = vanish_poly::<Fr>(n); 	
		let t = Fr::rand(&mut rng);
		let va = matrix_to_qap_poly_eval::<Fr>(&r1cs.a, size, size, t);
		let vb = matrix_to_qap_poly_eval::<Fr>(&r1cs.b, size, size, t);
		let vc = matrix_to_qap_poly_eval::<Fr>(&r1cs.c, size, size, t);
		let vec_h = slow_compute_witness_h(&r1cs.a, &r1cs.b, &r1cs.c, &vars);
		let vec_h_clone = vec_h.clone();
		let vec_h2 = compute_witness_h(&r1cs.a, &r1cs.b, &r1cs.c, &vars);
		for i in 0..vec_h2.len(){
			if vec_h_clone[i]!=vec_h2[i]{
				assert!(false, "different at i: {}, vec_h: {}, vec_h2: {}",
					i, vec_h_clone[i], vec_h2[i]);
			}
		}
		assert!(vec_h_clone==vec_h2, "FASTER ifft based witness_h() failed");

		let poly_h = DensePolynomial::<Fr>::from_coefficients_vec(vec_h);
		let mut sum_a = Fr::zero();
		let mut sum_b = Fr::zero();
		let mut sum_c = Fr::zero();
		for i in 0..size+1{
			sum_a += va[i] * vars[i];
			sum_b += vb[i] * vars[i];
			sum_c += vc[i] * vars[i];
		}
		let val_z = poly_z.evaluate(&t);
		let val_h = poly_h.evaluate(&t);
		RUN_CONFIG.better_barrier("test_slow_compute_witness_h");
		assert!(sum_a * sum_b == sum_c + val_z * val_h, "fails test slow_compute_witness_h");
	}

	#[test]
	fn test_dis_r1cs_rand_inst_make_even(){
		let n = closest_pow2(get_min_test_size()*17);
		let new_n = n*2;
		let seed = 731123101u128;
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(seed, n, n, false);
		let (mut dis_r1cs, dis_vars) = DisR1CS::<Fr>::rand_inst(seed, n, n, false);
		dis_r1cs.make_even(new_n);	
		let _r1cs2 = dis_r1cs.to_serial();
		//AS they need to be capped
		let r1cs2_a = r1cs.a[0..n].to_vec();
		let r1cs2_b = r1cs.b[0..n].to_vec();
		let r1cs2_c = r1cs.c[0..n].to_vec();
		let vars2 = dis_vars.collect_from_partitions(&RUN_CONFIG.univ);
		if RUN_CONFIG.my_rank==0{
			assert!(r1cs.a==r1cs2_a, "failed dis_r1cs random check r1cs.a==r1cs2_a capped");
			assert!(r1cs.b==r1cs2_b, "failed dis_r1cs random check r1cs.b==r1cs2_b capped");
			assert!(r1cs.c==r1cs2_c, "failed dis_r1cs random check r1cs.c==r1cs2_c capped");
			//assert!(vars==vars2, "failed dis_r1cs random check vars==vars2");
		}
	}

	#[test]
	fn test_dis_matrix_eval(){
		let n = get_min_test_size()*2;
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, n, n, false);
		let dr1cs = DisR1CS::<Fr>::from_serial(&r1cs);
		let mut dvars = DisVec::new_dis_vec(vars.clone());
		dvars.to_partitions(&RUN_CONFIG.univ);
		let vec1 = eval_matrix(&r1cs.a, &vars);
		let dvec2 = dis_eval_matrix(&dr1cs.a_share, 
				dr1cs.num_vars, dr1cs.num_constraints, &dvars);
		let vec2 = dvec2.collect_from_partitions(&RUN_CONFIG.univ);
		if RUN_CONFIG.my_rank==0{
			assert!(vec1==vec2, "DisR1CS dis_eval_matrix fails");
		}
	}

	#[test]
	fn test_dis_compute_witness_h(){
		let n = closest_pow2(get_min_test_size());
		let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, n, n, true);
		let dr1cs = DisR1CS::from_serial(&r1cs);
		let mut dvars = DisVec::new_dis_vec_with_id(0, 0, vars.len(), vars.clone());
		dvars.to_partitions(&RUN_CONFIG.univ);
	
		let vec_h = compute_witness_h(&r1cs.a, &r1cs.b, &r1cs.c, &vars);
		let dvec_h = dis_compute_witness_h(n, n, &dr1cs.a_share, &dr1cs.b_share, &dr1cs.c_share, &dvars);
		let vec_h2 = dvec_h.collect_from_partitions(&RUN_CONFIG.univ);
		if RUN_CONFIG.my_rank==0{
			assert!(vec_h==vec_h2, "failed dis_compute_h()");
		}

	}

	#[test]
	fn test_serial_to_qap(){
		if RUN_CONFIG.my_rank!=0{
			RUN_CONFIG.better_barrier("test_serial_to_qap");
			return;
		}
		let mut rng = gen_rng();
		let t = Fr::rand(&mut rng);
		let size = closest_pow2(get_min_test_size());
		let binp = vec![false];
		for exp_val in binp{
			let (r1cs,vars) = R1CS::<Fr>::rand_inst(1122u128, size, size, exp_val);
			let qap = r1cs.to_qap(&t);	
			let qap_wit = r1cs.to_qap_witness(vars);
			let bres = qap.is_satisfied(&qap_wit);
			assert!(exp_val==bres, "serial_to_qap fails for case: {}", exp_val);
		}
		RUN_CONFIG.better_barrier("test_serial_to_qap");
	}
	#[test]
	fn test_dis_r1cs_rand_inst(){
		let n = get_min_test_size()*64;
		let (r1cs,vars) = DisR1CS::<Fr>::rand_inst(1122u128, n, n, false);
		let bres = r1cs.is_satisfied(&vars);
		if RUN_CONFIG.my_rank==0{
			assert!(bres==false, "dist_r1cs failed on false test");
		}

		let (r1cs,vars) = DisR1CS::<Fr>::rand_inst(1122u128, n, n, true);
		let bres = r1cs.is_satisfied(&vars);
		if RUN_CONFIG.my_rank==0{
			assert!(bres==true, "dist_r1cs failed on true test");
		}
	}
*/
	#[test]
	fn test_dis_to_qap(){
		let mut rng = gen_rng_from_seed(1235673u128);
		let t = Fr::rand(&mut rng);
		let size = closest_pow2(get_min_test_size());
		let binp = vec![false, true];
		for exp_val in binp{
			let (r1cs,vars) = DisR1CS::<Fr>::rand_inst(1122u128, size, size, exp_val);
			let qap = r1cs.to_qap(&t);	
			let qap_wit = r1cs.to_qap_witness(vars);
			let bres = qap.is_satisfied(&qap_wit);
			if RUN_CONFIG.my_rank==0{
				assert!(exp_val==bres,"dis_to_qap fails for case: {}", exp_val);
				println!("DEBUG USE 999: dis_to_qap passed for case: {}", exp_val);
			}
		}
		RUN_CONFIG.better_barrier("test_dis_to_qap");
	}
}
