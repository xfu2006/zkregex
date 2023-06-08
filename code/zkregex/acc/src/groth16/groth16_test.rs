/**
	Copyright Dr. CorrAuthor

	Author: Author4
	All Rights Reserved.
	Created: 08/05/2022
*/

//use crate::profiler::config::*;


#[cfg(test)]
mod tests{
    extern crate ark_bn254;
    use crate::profiler::config::*;
    use groth16::serial_qap::*;
    use groth16::new_dis_qap::*;
    use groth16::serial_prover::*;
    use groth16::serial_prove_key::*;
    use groth16::verifier::*;
    use poly::dis_poly::*;
    use poly::dis_key::*;
    use groth16::dis_prover::*;
    use groth16::dis_prove_key::*;
    //use r1cs::serial_r1cs::*;
    //use r1cs::dis_r1cs::*;
    //use tools::*;

    use self::ark_bn254::Bn254;
    type Fr = ark_bn254::Fr;
    type PE= Bn254;

    /// return the minimum size required for the cluster size
    pub fn get_min_test_size()->usize{
        let np = RUN_CONFIG.n_proc as usize;
        return np*2;
    }
/* RECOVER LATER
    #[test]
    fn test_serial_qap_rand_test(){
        let n = get_min_test_size().next_power_of_two()*4;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qapwitness) = QAP::<Fr>::rand_inst(seed, num_inputs, num_vars,degree, false);
        assert_eq!(qap.is_satisfied(&qapwitness), false, "serial_qap failed on FALSE test.");
        let (qap, qapwitness) = QAP::<Fr>::rand_inst(seed,num_inputs, num_vars, degree, true);
        assert_eq!(qap.is_satisfied(&qapwitness), true, "serial_qap failed on TRUE test.");
    }

    #[test]
    fn test_dis_qap_rand_test(){
        let n = get_min_test_size().next_power_of_two()*4;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qapwitness) = DisQAP::<Fr>::rand_inst(seed, num_inputs, num_vars,degree, false);
        assert_eq!(qap.is_satisfied(&qapwitness), false, "serial_qap failed on FALSE test.");
        let (qap, qapwitness) = DisQAP::<Fr>::rand_inst(seed,num_inputs, num_vars, degree, true);
        assert_eq!(qap.is_satisfied(&qapwitness), true, "serial_qap failed on TRUE test.");
    }
	#[test]
	fn test_serial_prover(){
        let n = get_min_test_size().next_power_of_two()*4;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qw) = QAP::<Fr>::rand_inst(seed, num_inputs, num_vars,degree, true);
		let num_segs = qap.num_segs;
		let prover = SerialProver::<PE>::new(num_segs, seed);
		let diskey = DisKey::<PE>::gen_key1(32); 	
		let (skey, vkey) = serial_setup(234234234u128, &qap, &diskey);
		let p1 = prover.prove_stage1(&skey, &qw);
		let p2 = prover.prove_stage2(&skey, &qw);
		let bres = verify::<PE>(&p1, &p2, &vkey);
		if RUN_CONFIG.my_rank==0{
			assert!(bres==true, "verification failed");
			println!("serial verification passed!");
		};
	}
	#[test]
	fn test_fast_rand(){
        let n = get_min_test_size().next_power_of_two()*4;
		let me = RUN_CONFIG.my_rank;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qw) = DisQAP::<Fr>::rand_inst_fast(seed, num_inputs, num_vars,degree, true);
		let bok = qap.is_satisfied_slow(&qw);
		if me==0{ assert!(bok, "qap_fast_rand true case failed!"); }

        let (qap, qw) = DisQAP::<Fr>::rand_inst_fast(seed, num_inputs, num_vars,degree, false);
		let bok = qap.is_satisfied_slow(&qw);
		if me==0{ assert!(!bok, "qap_fast_rand false case failed!"); }
	}

*/
	#[test]
	fn test_fast_is_sat(){
        let n = get_min_test_size().next_power_of_two()*4;
		let me = RUN_CONFIG.my_rank;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qw) = DisQAP::<Fr>::rand_inst_slow(seed, num_inputs, num_vars,degree, true);
		let bok = qap.is_satisfied_fast(&qw);
		if me==0{ assert!(bok, "qap_fast_is_sat() true case failed!"); }

        let (qap, qw) = DisQAP::<Fr>::rand_inst_slow(seed, num_inputs, num_vars,degree, false);
		let bok = qap.is_satisfied_fast(&qw);
		if me==0{ assert!(!bok, "qap_fast_is_sat() false case failed!"); }
	}

	#[test]
	fn test_dis_prover(){
        let n = get_min_test_size().next_power_of_two()*4;
		let degree = n - 2; //degree+2 must be power of 2	
		let num_inputs = 2;
		let num_vars = n;
		let seed = 1122u128;
        let (qap, qw) = DisQAP::<Fr>::rand_inst(seed, num_inputs, num_vars,degree, true);

		let num_segs = qap.num_segs;
		let prover = DisProver::<PE>::new(num_segs, seed, qap.seg_size.clone());
		let diskey = DisKey::<PE>::gen_key1(32); 	
		let (dkey, vkey) = dis_setup(234234234u128, &qap, &diskey);


		let p1 = prover.prove_stage1(&dkey, &qw, 2);
		let p2 = prover.prove_stage2(&dkey, &qw, 2);
		let bres = verify::<PE>(&p1, &p2, &vkey);
		if RUN_CONFIG.my_rank==0{
			assert!(bres==true, "verification failed");
			println!("DisProver verification passed!");
		};
	}


}
