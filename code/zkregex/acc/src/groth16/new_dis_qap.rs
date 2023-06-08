/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor, Author4
	All Rights Reserved.
	Created 10/14/2022
	Completed 10/15/2022
	Revised 03/06/2023 (add new rand_inst and is_satisfied)

	This file contains data structure and various implementations
for distributed QAP (quadratic arithmetic program)	
*/

/// Distributed of QAP
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

use self::ark_ff::{PrimeField};
//use r1cs::serial_r1cs::ark_std::rand::rngs::StdRng;
use tools::*;
use poly::dis_vec::*;
use poly::common::*;
use groth16::serial_qap::*;
use profiler::config::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// QAPWitness struct
#[derive(Clone)]
pub struct DisQAPWitness<F:PrimeField>{
	/// Corresponds to a_i in Groth'16
    pub coefs_abc: DisVec<F>,

	/// Corresponds to h(X) in Groth'16
    pub coefs_h: DisVec<F>,

	/// number of public I/O variables
	/// NOTE: unlike dis_r1cs, it includes column 1 (so should be dis_r1cs.num_io+1)
    pub num_inputs: usize,

	/// total number of variables. Thus, num_witness = num_vars - num_inputs
	/// variables as listed as concats of [i/o vars] + [witness]
	/// in [witness] it is structured as [seg_0, seg_1, ...., seg_k]
	/// with the seg_k as uncommitted and all others as committed
	/// NOTE: unlike dis_r1cs, it includes column 1
	/// so should be dis_r1cs.num_vars+1
    pub num_vars: usize,

	/// Corresponds to n-2 in Groth'16 (number of constraints). 
	/// See pp. 14. of Groth'16
	/// It is the degree of h(x). The degree of t(x) is degree+2.
	/// Thus coefs_h.len() should be degree+1
	/// DUE to the need of root of unity. degree+2 should be a power of 2!
    pub degree: usize,
}

/// Implementations of QAPWitness
impl <F:PrimeField> DisQAPWitness<F>{
	/// constructor
	pub fn new(
        num_inputs: usize,
        num_vars: usize,
        degree: usize,
        coefs_abc: DisVec<F>,
        coefs_h: DisVec<F>,) -> DisQAPWitness<F>{
		assert!(coefs_abc.b_in_cluster, "partition coefs_abc first!");
		assert!(coefs_h.b_in_cluster, "partition coefs_hfirst!");
		let ret = DisQAPWitness{
		    num_inputs,
		    num_vars,
		    degree: degree,
		    coefs_abc,
		    coefs_h,
		};
		//ret.coefs_abc.to_partitions(&RUN_CONFIG.univ);
		//ret.coefs_h.to_partitions(&RUN_CONFIG.univ);
		return ret;
	}
}

/// Distributed version of QAP system
#[derive(Clone)]
pub struct DisQAP<F:PrimeField>{
	/// Corresponds to ui(X), evaluated at point t in Groth'16
    pub at: DisVec<F>,

	/// Corresonds to vi(t) in Groth'16
    pub bt: DisVec<F>,

	/// Corresponds to wi(t) in Groth'16
    pub ct: DisVec<F>,

	/// Correpsonds to {t^0, t^1, ..., t^n-2} in Groth'16
	/// where self.degree = n-2
    pub ht: DisVec<F>,

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

/// Implementations of DisQAP
impl <F:PrimeField> DisQAP<F>{

	/// constructor
	pub fn new(
        at: DisVec<F>,
        bt: DisVec<F>,
        ct: DisVec<F>,
        ht: DisVec<F>,
        zt: F,
        t: F,

        num_inputs: usize,
        num_vars: usize,
        degree: usize,

        num_segs: usize,
        seg_size: Vec<usize>,) -> DisQAP<F>{
		assert!(at.b_in_cluster, "partition at first!");
		assert!(bt.b_in_cluster, "partition bt first!");
		assert!(ct.b_in_cluster, "partition ct first!");
		assert!(ht.b_in_cluster, "partition ht first!");
		let res  = DisQAP{
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
		//res.at.to_partitions(&RUN_CONFIG.univ);
		//res.bt.to_partitions(&RUN_CONFIG.univ);
		//res.ct.to_partitions(&RUN_CONFIG.univ);
		//res.ht.to_partitions(&RUN_CONFIG.univ);
		return res;
	}

	/** return DisQAP and DisQAPWitness from serial version */
	pub fn from_serial(qap: &QAP<F>, qw: &QAPWitness<F>) -> 
		(DisQAP<F>, DisQAPWitness<F>){
		//1. build the DisQAP instance
		let mut dat = DisVec::<F>::from_serial(&qap.at);
		let mut dbt = DisVec::<F>::from_serial(&qap.bt);
		let mut dct = DisVec::<F>::from_serial(&qap.ct);
		let mut dht = DisVec::<F>::from_serial(&qap.ht);
		dat.to_partitions(&RUN_CONFIG.univ);
		dbt.to_partitions(&RUN_CONFIG.univ);
		dct.to_partitions(&RUN_CONFIG.univ);
		dht.to_partitions(&RUN_CONFIG.univ);
		let dqap = DisQAP::<F>::new(
			dat, dbt, dct, dht, qap.zt, qap.t, qap.num_inputs, qap.num_vars,
			qap.degree, qap.num_segs, qap.seg_size.clone() 
		);

		//2. build the DisQAP Witness
		let mut dcoefs_abc = DisVec::<F>::from_serial(&qw.coefs_abc);
		let mut dcoefs_h = DisVec::<F>::from_serial(&qw.coefs_h);
		dcoefs_abc.to_partitions(&RUN_CONFIG.univ);
		dcoefs_h.to_partitions(&RUN_CONFIG.univ);
		let dqw = DisQAPWitness::<F>::new(
			qw.num_inputs, qw.num_vars, qw.degree,
			dcoefs_abc, dcoefs_h, 
		);
		return (dqap, dqw);
	}

	/** return serial version */
	pub fn to_serial(dqap: &DisQAP<F>, dqw: &DisQAPWitness<F>) -> 
		(QAP<F>, QAPWitness<F>){
		//1. build the QAP instance
		let at = dqap.at.to_serial();
		let bt = dqap.bt.to_serial();
		let ct = dqap.ct.to_serial();
		let ht = dqap.ht.to_serial();
		let qap = QAP::<F>::new(
			at, bt, ct, ht, dqap.zt, dqap.t, dqap.num_inputs, dqap.num_vars,
			dqap.degree, dqap.num_segs, dqap.seg_size.clone() 
		);

		//2. build the QAP Witness
		let coefs_abc = dqw.coefs_abc.to_serial();
		let coefs_h = dqw.coefs_h.to_serial();
		let qw = QAPWitness::<F>::new(
			dqw.num_inputs, dqw.num_vars, dqw.degree,
			coefs_abc, coefs_h, 
		);
		return (qap, qw);
	}

	/// Create a random instance of QAP and QAPWitness
	/// bsat: whether the created instance is satisfiable or not.
	pub fn rand_inst_slow(seed: u128, num_inputs: usize, num_vars: usize, degree: usize, bsat: bool) -> (DisQAP<F>, DisQAPWitness<F>){
        let (qap, qw) = QAP::<F>::rand_inst(seed, num_inputs, num_vars, degree, bsat);
		let (dqap, dqw) = Self::from_serial(&qap, &qw);
		return (dqap, dqw);
    }

	pub fn rand_inst_fast(seed:u128, num_inputs: usize, num_vars: usize, degree: usize, bsat: bool) -> (DisQAP<F>, DisQAPWitness<F>){
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
	
		//1. first create all vectors random	
        let mut rng = gen_rng_from_seed(seed + 7123120123u128);
        let t = F::rand(&mut rng);
		let at = DisVec::<F>::rand_inst(seed + 3901, num_vars);
		let bt = DisVec::<F>::rand_inst(seed + 2301, num_vars);
		let ct = DisVec::<F>::rand_inst(seed + 3211, num_vars);
		let coefs_abc = DisVec::<F>::rand_inst(seed + 1701, num_vars);
		let mut coefs_h = DisVec::<F>::rand_inst_worker(seed + 2901, degree+1,true);
		let ht = DisVec::<F>::power_ts(degree, t);
		let zt = t.pow(&[(degree+2) as u64]) - F::one();

		//2. evaluates the diff right now
		let ans_a = at.dot_prod(&coefs_abc);
		let ans_b = bt.dot_prod(&coefs_abc);
		let ans_c = ct.dot_prod(&coefs_abc);
		let ans_h = ht.dot_prod(&coefs_h);
        if bsat {
            let diff_val = ans_a * ans_b - ans_c - ans_h * zt;
			//synchronize diff_val to all (node 0 collects)
			let arr_diff =  broadcast_small_arr(&vec![diff_val], 0);
			let diff_val = arr_diff[0];
		
			//synchronize the last h from the last one node
			let arr_lasth = broadcast_small_arr(&vec![ht.partition[ht.partition.len()-1]], np-1);	
            let last_h = arr_lasth[0];
            let last_val = diff_val / (last_h * zt);

			//synchronize the last_val from node 0 to last node
            let last_coef_h = last_val;
			let arr_last_coefh = broadcast_small_arr(&vec![last_coef_h], 0);
			let correct_last_val = arr_last_coefh[0];
			if me==np-1{
				let partlen = coefs_h.partition.len();
            	coefs_h.partition[partlen-1] = correct_last_val;
			}
        }

		//4. Build Instances
		let wit_size = num_vars - num_inputs; 
		let d_qap = DisQAP{
			at: at,
			bt: bt,
			ct: ct,
			ht: ht,
			zt: zt,
			t: t,
			num_inputs: num_inputs,
			num_vars: num_vars,
			degree: degree,
            num_segs: 3,
            seg_size: vec![8, wit_size/4, wit_size-8 - wit_size/4]
		};

		let d_wit = DisQAPWitness{
			coefs_abc: coefs_abc,
			coefs_h: coefs_h,
			num_inputs: num_inputs,
			num_vars: num_vars,
			degree: degree,
		}; 
		return (d_qap, d_wit);
	}

	pub fn rand_inst(seed:u128, num_inputs: usize, num_vars: usize, degree: usize, bsat: bool) -> (DisQAP<F>, DisQAPWitness<F>){
		return Self::rand_inst_fast(seed, num_inputs, num_vars, degree, bsat);
	}

	/// return True if QAP instance is satisfied by the witness
	/// NOTE: SLOW! used for testing only!
    pub fn is_satisfied_slow(&self, witness: &DisQAPWitness<F>)->bool{
		let (qap, qw) = Self::to_serial(self, witness);
		return qap.is_satisfied(&qw);
    }

	/// ONLY return the correct result at node 0
    pub fn is_satisfied_fast(&self, witness: &DisQAPWitness<F>)->bool{
		let ans_a = self.at.dot_prod(&witness.coefs_abc);
		let ans_b = self.bt.dot_prod(&witness.coefs_abc);
		let ans_c = self.ct.dot_prod(&witness.coefs_abc);
		let ans_h = self.ht.dot_prod(&witness.coefs_h);
		let diff_val = ans_a * ans_b - ans_c - ans_h * self.zt;
		let bres = diff_val.is_zero();
		return bres;	
    }

    pub fn is_satisfied(&self, witness: &DisQAPWitness<F>)->bool{
		return self.is_satisfied_fast(witness);
    }

}
