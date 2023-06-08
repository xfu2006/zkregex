/**
	Copyright Dr. CorrAuthor

	Author: Author4
	All Rights Reserved.
	Created: 07/29/2022
	Updated: 08/03/2022
*/

/// Serial (standard) version of QAP, which is stored
/// in one computer node
///
/// Ref: Groth'16: J. Groth, "On the Size of Pairing-Based Non-Interactive
/// Arguments", EUROCRYPT16. https://eprint.iacr.org/2016/260.pdf
/// Ref2: DIZK: H. Wu et al, "DIZK: Distributed Zero Knowledge Proof system",
/// https://www.usenix.org/conference/usenixsecurity18/presentation/wu
/// NOTE: our variable naming convention simulates the source code of DIZK
/// The serial QAP is used for functional testing of distributed QAP.

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use self::ark_ff::{FftField};
//use r1cs::serial_r1cs::ark_std::rand::rngs::StdRng;
use tools::*;
use profiler::config::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// QAPWitness struct
#[derive(Clone)]
pub struct QAPWitness<F:FftField>{
	/// Corresponds to a_i in Groth'16
    pub coefs_abc: Vec<F>,

	/// Corresponds to h(X) in Groth'16
    pub coefs_h: Vec<F>,

	/// number of public I/O variables
    pub num_inputs: usize,

	/// total number of variables. Thus, num_witness = num_vars - num_inputs
	/// variables as listed as concats of [i/o vars] + [witness]
	/// in [witness] it is structured as [seg_0, seg_1, ...., seg_k]
	/// with the seg_k as uncommitted and all others as committed
    pub num_vars: usize,

	/// Corresponds to n-2 in Groth'16 (number of constraints). 
	/// See pp. 14. of Groth'16
	/// It is the degree of h(x). The degree of t(x) is degree+2.
	/// Thus coefs_h.len() should be degree+1
	/// DUE to the need of root of unity. degree+2 should be a power of 2!
    pub degree: usize,
}

/// Implementations of QAPWitness
impl <F:FftField> QAPWitness<F>{
	/// constructor
	pub fn new(
        num_inputs: usize,
        num_vars: usize,
        degree: usize,
        coefs_abc: Vec<F>,
        coefs_h: Vec<F>,) -> QAPWitness<F>{
		return QAPWitness{
		    num_inputs,
		    num_vars,
		    degree: degree,
		    coefs_abc,
		    coefs_h,
		};
	}
}

#[derive(PartialEq,Clone,Debug)]
pub struct NaiveMSM<F:FftField>{
    pub dummy: F,
}

impl <F:FftField> NaiveMSM<F>{
	/// compute \sum_i scalars[i] * bases[i]
	pub fn variable_base_msm(
        scalars: &Vec<F>,
        bases: &Vec<F>,) -> F {

        assert_eq!(scalars.len(), bases.len(), "Vector lengths don't match in variable_base_msm");
        assert!(scalars.len() > 0, "Vector length is zero in variable_base_msm");
		let mut result = F::zero();
		for i in 0..scalars.len() {
		    result += scalars[i] * bases[i];
		}
		return result;
	}
}

/// Serial version of QAP system
#[derive(Clone)]
pub struct QAP<F:FftField>{
	/// Corresponds to ui(X), evaluated at point t in Groth'16
    pub at: Vec<F>,

	/// Corresonds to vi(t) in Groth'16
    pub bt: Vec<F>,

	/// Corresponds to wi(t) in Groth'16
    pub ct: Vec<F>,

	/// Correpsonds to {t^0, t^1, ..., t^n-2} in Groth'16
	/// where self.degree = n-2
    pub ht: Vec<F>,

	/// Corresponds to t(X) at t in Groth'16
	/// i.e. t(X) = \prod_i (x-omega^i) where omega is the root of unity
    pub zt: F,

	/// random point t
    pub t: F,

	/// number of public I/O inputs
    pub num_inputs: usize,

	/// number of variables
    pub num_vars: usize,

	/// degree of h(X) in Groth'16
    pub degree: usize,

	// *** the following are our paper specific additional data structures ***
	/// number of segments of witness inputs. The last one is non-committed, all previous are committed, see the paper about committed witness.
	pub num_segs: usize,

	/// size of segments (sum of them should be num_witness = num_vars - num_io)
	pub seg_size: Vec<usize>,
}

/// Implementations of QAP
impl <F:FftField> QAP<F>{

	/// constructor
	pub fn new(
        at: Vec<F>,
        bt: Vec<F>,
        ct: Vec<F>,
        ht: Vec<F>,
        zt: F,
        t: F,

        num_inputs: usize,
        num_vars: usize,
        degree: usize,

        num_segs: usize,
        seg_size: Vec<usize>,) -> QAP<F>{
		return QAP{
		    at: at,
		    bt: bt,
		    ct: ct,
		    ht: ht,
		    zt: zt,
		    t: t,
		    num_inputs: num_inputs,
		    num_vars: num_vars,
		    degree: degree,
		    num_segs: num_segs,
		    seg_size: seg_size,
		};
	}

	/// Create a random instance of QAP and QAPWitness
	/// bsat: whether the created instance is satisfiable or not.
	pub fn rand_inst(seed: u128, num_inputs: usize, num_vars: usize, degree: usize, bsat: bool) -> (QAP<F>, QAPWitness<F>){
		assert!(num_inputs>0, "num_inputs must be greater than 0!");
        let mut rng = gen_rng_from_seed(seed);
        let t = F::rand(&mut rng);
		let zero = F::zero();

    	let mut at = vec![zero; num_vars]; 
        let mut bt = vec![zero; num_vars];
        let mut ct = vec![zero; num_vars]; 
        let mut coeff_abc = vec![zero; num_vars];
    	for i in 0..num_vars{
            at[i] = F::rand(&mut rng);
            bt[i] = F::rand(&mut rng);
            ct[i] = F::rand(&mut rng);
            coeff_abc[i] = F::rand(&mut rng);
        }

		// t(x)'s degree is degree+2
		// h(x)'s degree is degree. 
        let mut ht = vec![F::one(); degree+1];
        let mut power_of_t = F::one();
        for i in 0..(degree+1){
            ht[i] = power_of_t;
            power_of_t = power_of_t * t;
        }
        let mut coeff_h = vec![F::zero(); degree+1];
        for i in 0..(degree+1){
            coeff_h[i] = F::rand(&mut rng);
        }
        let last_ind = coeff_h.len()-1;
        coeff_h[last_ind] = F::zero();

		// taking advantage of root of unity's property	
		let n = degree+2; //as t(X)'s degree is degree+2
        let zt: F = t.pow(&[n as u64]) - F::one();

        let ans_a = NaiveMSM::variable_base_msm(&at, &coeff_abc);
        let ans_b = NaiveMSM::variable_base_msm(&bt, &coeff_abc);
        let ans_c = NaiveMSM::variable_base_msm(&ct, &coeff_abc);
        let ans_h = NaiveMSM::variable_base_msm(&ht, &coeff_h);

        if bsat {
            let diff_val = ans_a * ans_b - ans_c - ans_h * zt;
            let last_h = ht[ht.len()-1];
            let last_val = diff_val / (last_h * zt);
            coeff_h[last_ind] = last_val;
        }

        let qap_inst = QAP{
            at: at,
            bt: bt,
            ct: ct,
            ht: ht,
            zt: zt,
            t: t,
            num_inputs: num_inputs,
            num_vars: num_vars,
            degree: degree,
            num_segs: 2,
            seg_size: vec![num_vars-num_inputs-2, 2]
        };

        let qap_witness_inst = QAPWitness{
            coefs_abc: coeff_abc,
            coefs_h: coeff_h,
            num_inputs: num_inputs,
            num_vars: num_vars,
            degree: degree,
        };

        return (qap_inst, qap_witness_inst);
    }

	/// return True if QAP instance is satisfied by the witness
	/// result is CORRECT only at node 0
    pub fn is_satisfied(&self, witness: &QAPWitness<F>)->bool{
		if RUN_CONFIG.my_rank!=0{
			RUN_CONFIG.better_barrier("serial_qap sat");
			return true;
		}	
		let n = self.degree + 2;
		assert!(n.is_power_of_two(), "self.degree+2 should be a power of 2");
        assert!(witness.num_inputs == self.num_inputs, "invalid num_inputs");
        assert!(witness.num_vars== self.num_vars, "invalid num_vars");
        assert!(witness.degree == self.degree, "invalid degree");
        assert!(self.num_vars == witness.coefs_abc.len(), "invalid abc.len");
        assert!(self.degree+1 == witness.coefs_h.len(), "invalid h.len()");
        assert!(self.at.len() == self.num_vars, "invalid at.len()");
		assert!(self.bt.len() == self.num_vars, "invalid bt.len()");
		assert!(self.ct.len() == self.num_vars, "invalid ct.len()");
        assert!(self.ht.len() == self.degree + 1, "invalid ht.len()");

        let mut power_of_t = F::one();
        for power_of_h in self.ht.clone() {
           assert!(power_of_h == power_of_t, "ht incorrect!");
           power_of_t = power_of_t * self.t;
        }

		//double check z(t) using slower computing
		let n = self.degree + 2;
		let omega = F::get_root_of_unity(n as u64).unwrap();
		let mut omega_i = F::one(); //omega^0
		let mut zt_slow = F::one(); //computed as \prod_i (x-omega^i)
		for _i in 0..n{
			zt_slow *= self.t - omega_i;
			omega_i *= omega;
		}
		assert!(self.zt==zt_slow, "zt is not right!");

		//check if equality holds
        let ans_a = NaiveMSM::variable_base_msm(& self.at, & witness.coefs_abc);
        let ans_b = NaiveMSM::variable_base_msm(& self.bt, & witness.coefs_abc);
        let ans_c = NaiveMSM::variable_base_msm(& self.ct, & witness.coefs_abc);
        let ans_h = NaiveMSM::variable_base_msm(& self.ht, & witness.coefs_h);
		RUN_CONFIG.better_barrier("serial_qap sat");
        return ans_a * ans_b - ans_c == ans_h * self.zt;
    }

	/// Create a DEBUG INSTANCE 
	/// bsat: whether the created instance is satisfiable or not.
	pub fn debug_inst() -> (QAP<F>, QAPWitness<F>){
		let num_inputs = 2;
		let num_vars = 6;
		let degree = 6;
        let t = F::from(2u64);

    	let at = vec![F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    	let bt = vec![F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    	let ct = vec![F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64)];
		// i/o + witness
    	let coeff_abc = vec![F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64), F::from(0u64)];

		// t(x)'s degree is degree+2
		// h(x)'s degree is degree. 
		// taking advantage of root of unity's property	
		let n = degree+2; //as t(X)'s degree is degree+2
        let zt: F = t.pow(&[n as u64]) - F::one();
        let mut ht = vec![F::one(); degree+1];
        let mut power_of_t = F::one();
        for i in 0..(degree+1){
            ht[i] = power_of_t;
            power_of_t = power_of_t * t;
        }
        let mut coeff_h = vec![F::from(1u64), F::from(1u64), F::from(1u64), F::from(1u64), F::from(1u64), F::from(1u64), F::from(1u64)];
		assert!(coeff_h.len()==degree+1, "coeff_h.len!=degree+1");
        let last_ind = coeff_h.len()-1;
        coeff_h[last_ind] = F::zero();

        let ans_a = NaiveMSM::variable_base_msm(&at, &coeff_abc);
        let ans_b = NaiveMSM::variable_base_msm(&bt, &coeff_abc);
        let ans_c = NaiveMSM::variable_base_msm(&ct, &coeff_abc);
        let ans_h = NaiveMSM::variable_base_msm(&ht, &coeff_h);

		let diff_val = ans_a * ans_b - ans_c - ans_h * zt;
		let last_h = ht[ht.len()-1];
println!("*** DEBUG USE 105: *** diff_val: {}, last_h: {}, zt: {}", diff_val, last_h, zt);
		let last_val = diff_val / (last_h * zt);
		coeff_h[last_ind] = last_val;
println!("*** DEBUG USE 106: *** lats_val: {}", last_val);

        let qap_inst = QAP{
            at: at,
            bt: bt,
            ct: ct,
            ht: ht,
            zt: zt,
            t: t,
            num_inputs: num_inputs,
            num_vars: num_vars,
            degree: degree,
            num_segs: 2,
            seg_size: vec![num_vars-num_inputs-2, 2]
        };

        let qap_witness_inst = QAPWitness{
            coefs_abc: coeff_abc,
            coefs_h: coeff_h,
            num_inputs: num_inputs,
            num_vars: num_vars,
            degree: degree,
        };

        return (qap_inst, qap_witness_inst);
    }

}
