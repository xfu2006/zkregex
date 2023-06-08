/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/25/2022
	Refined: 07/29/2022: Added to QAP utilities 
	Refined: 08/22/2022: Added to QAP function
*/

/// Serial (standard) version of R1CS, which is stored
/// in one computer node

extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use self::ark_ff::{FftField,FromBytes,Zero};
use self::ark_std::{rand::Rng};
use r1cs::serial_r1cs::ark_std::rand::rngs::StdRng;
use self::ark_poly::{Polynomial, DenseUVPolynomial,univariate::DensePolynomial};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize,SerializationError,Read,Write};
use tools::*;
//use poly::disfft::*;
use poly::serial::*;
use poly::common::*;
use groth16::serial_qap::*;
//use profiler::config::*;


/*
use self::ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ff::UniformRand;

use std::any::Any;
use std::rc::Rc;

use proto::*;
use poly::dis_poly::*;
//use poly::dis_key::*;
use poly::serial::*;
*/

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;


/// Tuple <var_id, val>
/// var_id starts from 1. var_id: 0 is reserved for constant 1.
#[derive(Clone,PartialEq,Debug,Copy)]
pub struct LinearTerm<F:FftField>{
	pub index: usize,
	pub value: F
}

impl<F:FftField>  CanonicalSerialize for LinearTerm<F>{
	#[inline]
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
		let u64idx = self.index as u64;
		u64idx.serialize(&mut writer).unwrap();
		self.value.serialize(&mut writer).unwrap();
		Ok(())
	}

	#[inline]
	fn serialized_size(&self) -> usize {
		return self.value.serialized_size() + 8; //usize is 64-bit
	}
}

impl <F:FftField> CanonicalDeserialize for LinearTerm<F>{
	#[inline]
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
		let idx= u64::read(&mut reader).unwrap();
		let val= F::read(&mut reader).unwrap();
		let res = LinearTerm::new(idx as usize, val);
		Ok(res)
	}
}



impl <F:FftField> LinearTerm<F>{
	/// constructor
	pub fn new(idx: usize, val: F)->LinearTerm<F>{
		return LinearTerm{index: idx, value: val};
	}

	/// return the serialization size
	pub fn serialized_size(&self) -> usize{
		return self.index.to_le_bytes().len() + self.value.serialized_size();
	}

	/// serialize itself to vec at idx
	pub fn serialize_to(&self, vec: &mut Vec<u8>, idx: usize){
		let v8 = self.index.to_le_bytes();
		for i in 0..8{
			vec[idx + i] = v8[i];
		}
		let mut b2 = vec![];
		let new_idx = idx + 8;
		F::serialize(&self.value, &mut b2).unwrap();
		for i in 0..b2.len(){
			vec[new_idx + i] = b2[i];
		}
	}

	/// deserialize from
	pub fn deserialize_from(vec: &Vec<u8>, idx: usize)->LinearTerm<F>{
		let mut v8 = [0u8; 8];
		for i in 0..8{
			v8[i] = vec[idx+i];
		}
		let index = u64::from_le_bytes(v8);
		let val = F::zero();
		let b2 = &vec[idx+8..idx+8+val.serialized_size()]; 
		let value = F::deserialize(b2).unwrap();
		let term = LinearTerm::<F>{ index: index as usize, value: value };
		return term;
	}


	/// convert a matrix of linear terms to bytes
	pub fn matrix_to_bytes(vec: &Vec<Vec<LinearTerm<F>>>)->Vec<u8>{
		//--------------- structure: -----------------
		//1. total_units, total rows, row0_size, ..., row_n_sizeunits (as u64)
		//2. linear arrangement of all terms
		//--------------------------------------------

		//1. figure out the size
		let unit_size = LinearTerm::<F>::new(0, F::zero()).serialized_size();
		let u64_size = 8usize;
		let mut total_units =  0;
		for i in 0..vec.len(){ total_units += vec[i].len(); }
		let total_size = u64_size * (2 + vec.len()) + total_units*unit_size;
		let mut res:Vec<u8> = vec![0; total_size];

		//2. store the index
		write_u64_to(total_units as u64, &mut res, 0);
		write_u64_to(vec.len() as u64, &mut res, 8);
		let mut idx = 16;
		for i in 0..vec.len(){
			write_u64_to(vec[i].len() as u64, &mut res, idx);
			idx+=8;
		}
		

		//3. store the data
		for i in 0..vec.len(){
			let row = &vec[i];
			for item in row{
				item.serialize_to(&mut res, idx);
				idx += unit_size;
			}
		}
		assert!(idx==total_size, "matrix_to_bytes ERROR: did not write all data, idx: {}, total_size: {}", idx, total_size); 
		return res;
	}

	/// read a matrix from bytes
	pub fn matrix_from_bytes(vec: &Vec<u8>)->Vec<Vec<LinearTerm<F>>>{
		//--------------- structure: -----------------
		//1. total_units, total rows, row0_size, ..., row_n_sizeunits (as u64)
		//2. linear arrangement of all terms
		//--------------------------------------------

		//1. figure out the size
		let term = LinearTerm::<F>::new(0,F::zero());
		let unit_size = term.serialized_size();
		let total_units= read_u64_from(&vec, 0) as usize;

		//2. read the index
		let rows = read_u64_from(&vec, 8) as usize;
		let mut res:Vec<Vec<LinearTerm<F>>> = vec![vec![]; rows];
		let total_size = total_units * unit_size + 8 * (2 + rows);
		let mut vlen = vec![0usize; rows];
		let mut idx = 16;
		for i in 0..rows{
			let size = read_u64_from(&vec, idx) as usize;
			vlen[i] = size;
			res[i] = vec![term.clone(); size as usize];
			idx+=8;	
		}

		//3. read the data
		for i in 0..rows{
			let row = &mut res[i];
			for j in 0..vlen[i]{
				row[j] = LinearTerm::<F>::deserialize_from(&vec, idx);
				idx += unit_size;
			}
		}
		assert!(idx==total_size,
			"matrix_from_bytes ERROR: did not read all data"); 
		return res;
	}
}

/// Serial version of R1CS system
#[derive(PartialEq,Clone,Debug)]
pub struct R1CS<F:FftField>{
	/// matrix A. size should be num_constraints. Corresponds to <u> in Groth'16
	pub a: Vec<Vec<LinearTerm<F>>>,
	/// matrix B. corresponds to <v> in Groth'16
	pub b: Vec<Vec<LinearTerm<F>>>,
	/// matrix C. corresponds to <w> in Groth'16
	pub c: Vec<Vec<LinearTerm<F>>>,
	/// number of variables (NOT including constant 1 as var_0)
	pub num_vars: usize,

	/// number of constraints
	/// NOTE: Based on pp. 14. of Groth'16 (it is the n in Groth'16 paper)
	/// Its relation to degree in QAP (see groth16/serial_qap) is shown below:
	/// num_constraints (n) = QAP.degree+2
	/// In another word, in QAP: the "degree" attribute IS THE DEGREE of h(x),
	/// the degree of u_i(x), v_i(x) and w_i(x) in Groth'16 is
	/// n-1, and the degree of h(x) is n-2 and the degree of t(x) in
	/// Groth'16 is n. Thus, relation to serial_qap.rs:
	///     num_constraints = QAP.degree  + 2
	/// For applying FFT in calculating t(x) [vanishing poly], it is
	/// required that the num_constraints should be a power of 2!
	pub num_constraints: usize,
	/// number of public i/o vars. num_witness is num_vars - num_io
	pub num_io: usize,

	// *** the following are our paper specific additional data structures ***
	/// number of segments of witness inputs. The last one is non-committed, all previous are committed, see the paper about committed witness.
	pub num_segs: usize,
	/// size of segments (sum of them should be num_witness = num_vars - num_io)
	pub seg_size: Vec<usize>,
}

/// Implementations of R1CS
impl <F:FftField> R1CS<F>{
	pub fn dump(&self, prefix: &str){
		println!("\n ====== R1CS Dump: {} =======\n", prefix);
		println!("num_vasr: {}, num_constraints: {}, num_io: {}, num_segs: {}",
			self.num_vars, self.num_constraints, self.num_io, self.num_segs);
		print!("seg_size: ");
		for i in 0..self.seg_size.len(){ print!(" {} ", self.seg_size[i]);}
		println!("\n --- Matrix A -----");
		for i in 0..self.a.len(){
			print!("\nrow: {}: ", i);
			for j in 0..self.a[i].len(){
				print!(" ({},{}) ", self.a[i][j].index, self.a[i][j].value);
			}
		}
		println!(" --- Matrix B -----");
		for i in 0..self.b.len(){
			print!("\nrow: {}: ", i);
			for j in 0..self.b[i].len(){
				print!(" ({},{}) ", self.b[i][j].index, self.b[i][j].value);
			}
		}
		println!(" --- Matrix C -----");
		for i in 0..self.c.len(){
			print!("\nrow: {}: ", i);
			for j in 0..self.c[i].len(){
				print!(" ({},{}) ", self.c[i][j].index, self.c[i][j].value);
			}
		}
	}
	/// constructor
	pub fn new(
		a: Vec<Vec<LinearTerm<F>>>,
		b: Vec<Vec<LinearTerm<F>>>,
		c: Vec<Vec<LinearTerm<F>>>,
		num_vars: usize,
		num_constraints: usize,
		num_io: usize,
		num_segs: usize,
		seg_size: Vec<usize>) -> R1CS<F>{
		if !num_constraints.is_power_of_two(){
			panic!("num_constraints should be be POWER OF 2");
		}
		return R1CS{
			a: a,
			b: b,
			c: c,
			num_vars: num_vars,
			num_constraints: num_constraints,
			num_io: num_io,
			num_segs: num_segs,
			seg_size: seg_size,
		};
	}

	/// generate a random instancd
	/// bsat: whether the R1CS is satisified or not
	/// returns the R1CS instance and the variable assignment
	/// num_io set to a fixed number: 2, num_segment set to 1 (standard)
	/// The 0'th element of variable assignment needs to be 1.
	/// NOTE!!!: the ACTUAL generated system has num_constraints: the cloest
	/// power of 2 (see doc of R1CS declaration)
	pub fn rand_inst(seed: u128, num_vars: usize, num_constraints_inp: usize, bsat: bool) -> (R1CS<F>, Vec<F>){
		//1. create random variable assignment
		let num_constraints = closest_pow2(num_constraints_inp);
		let mut rng = gen_rng_from_seed(seed);
		let mut vars = vec![F::zero(); num_vars+1];
		vars[0] = F::from(1u64);
		for i in 0..num_vars{
			vars[i+1] = F::rand(&mut rng);
		}

		let mut a:Vec<Vec<LinearTerm<F>>> = vec![];
		let mut b:Vec<Vec<LinearTerm<F>>> = vec![];
		let mut c:Vec<Vec<LinearTerm<F>>> = vec![];
		//2. for each constraint
		for _i in 0..num_constraints{
			//2.1 create random A, B, C
			let row_a = rand_row::<F>(3, num_vars, &mut rng);
			let row_b = rand_row::<F>(3, num_vars, &mut rng);
			let mut row_c = rand_row::<F>(3, num_vars-1, &mut rng);

			//2.2. evaluate sumA, sumB, sumC
			let sum_a = Self::eval(&row_a, &vars);
			let sum_b = Self::eval(&row_b, &vars);
			let sum_c = Self::eval(&row_c, &vars);

			//2.3 calculate the last value of  
			let diff_val = sum_a * sum_b - sum_c;
			let last_val = vars[num_vars];
			let c_coef = diff_val / last_val;			
			let c_term = LinearTerm::<F>{index: num_vars, value: c_coef};
			if bsat{//make it satisfied
				row_c.push(c_term);
			}

			//2.4 add to matrix A, B, C
			a.push(row_a);
			b.push(row_b);
			c.push(row_c);
		}
		let r1cs = R1CS::<F>::new( a, b, c, num_vars, num_constraints,
				2, 1, vec![(num_vars-2)] );
		return (r1cs, vars);
	}

	/// evaluate a matrix row using variable assignment
	/// Sum^n_{i=0} vars[row[i].var] * row[i].value
	pub fn eval(row: &Vec<LinearTerm<F>>, vars: &Vec<F>)->F{
		let mut sum = F::zero();
		for term in row{
			let var_idx = term.index;
			let coef = term.value;
			let var_val = vars[var_idx];
			sum += var_val * coef;
		} 
		return sum;
	}

	/// evaluate a matrix row using variable assignment
	/// Sum^n_{i=0} vars[row[i].var] * row[i].value
	/// index are adjusted
	pub fn eval_adjusted(row: &Vec<LinearTerm<F>>, vars: &Vec<F>, seg: (usize, usize))->F{
		let mut sum = F::zero();
		let (mstart, _mend) = seg;
		for term in row{
			let var_idx = term.index;
			let coef = term.value;
			let var_val = vars[var_idx-mstart];
			sum += var_val * coef;
		} 
		return sum;
	}


	/// return true if the instance is valid
	pub fn is_satisfied(&self, vars: &Vec<F>)->bool{
		if vars.len()!=self.num_vars+1{panic!("vars.len(): {}!=self.num_vars+1: {}", vars.len(), self.num_vars+1);}
		for i in 0..self.num_constraints{
			// compute sum_j vars[a[i][j].var] * a[i][j].value
			let sum_a = R1CS::<F>::eval(&self.a[i], &vars);
			let sum_b = R1CS::<F>::eval(&self.b[i], &vars);
			let sum_c = R1CS::<F>::eval(&self.c[i], &vars);
			if sum_c != sum_a*sum_b{
				return false;
			}
		}
		return true;
	}

	/// generating the corresponding QAP
	pub fn to_qap(&self, t_inp: &F) -> QAP<F>{
		let t = t_inp.clone();
		let nvars = self.num_vars;
		let ncons = self.num_constraints;
		let a_t = matrix_to_qap_poly_eval(&self.a, nvars, ncons, t_inp.clone());
		let b_t = matrix_to_qap_poly_eval(&self.b, nvars, ncons, t_inp.clone());
		let c_t = matrix_to_qap_poly_eval(&self.c, nvars, ncons, t_inp.clone());
		let n = self.num_constraints; //must be pow of 2 (see struct of R1CS)
		assert!(n.is_power_of_two(), "n: {} is not power of 2!", n);
		let degree = n - 2; //see doc in struct R1CS
		//see groth'16 (degree of ht: n-2. But coefs needs 1 more element)
		let mut ht  = vec![F::one(); n-1]; 
		let mut power_of_t = F::one();
		for i in 0..ht.len() {
			ht[i] = power_of_t;
            power_of_t = power_of_t * t;
		}
		let zt: F = t.pow(&[n as u64]) - F::one();	

		let qap = QAP::new(
			a_t,
			b_t,
			c_t,
			ht,
			zt, 
			t,
			self.num_io+1, //including constant 1
			self.num_vars+1, //including constant 1 (column 0)
			degree,
			self.num_segs,
			self.seg_size.clone()
		);
		return qap;
	}

	/// generating the corresponding QAP
	pub fn to_qap_witness(&self, vars: Vec<F>) -> QAPWitness<F>{
		let coefs_h = compute_witness_h(&self.a, &self.b, &self.c, &vars);
		let qap_wit= QAPWitness::new(
			self.num_io+1, //num_inputs
			self.num_vars + 1, //num_vars
			self.num_constraints-2, //degree = n -2 (see groth'16)
			vars, //coefs_abc
			coefs_h
		);
		return qap_wit;	
	}
}

// --------------------------------------------------------
//	Utility Functions
// --------------------------------------------------------
/// generate a random row of linear terms
/// num: number of entries, num_vars: number of variables
/// might generate fewer entries than num depending on random gen
pub fn rand_row<F:FftField>(num: usize, num_vars: usize, rng: &mut StdRng)
	-> Vec<LinearTerm<F>>{
	return rand_row_worker(num, num_vars, rng, (0usize, 1usize), false);
}
	
/// generate a random row of linear terms
/// num: number of entries, num_vars: number of variables
/// might generate fewer entries than num depending on random gen
/// if b_in_seg is set, generate var_idx within the bound given in seg_bound
pub fn rand_row_worker<F:FftField>(num: usize, num_vars: usize, rng: &mut StdRng, seg_bound: (usize, usize), b_in_seg: bool) 
	-> Vec<LinearTerm<F>>{
	let mut vec = vec![];
	let (mstart, mend) = seg_bound;
	let mut cur_base = if b_in_seg {mstart} else {0usize};
	let seg_len = mend-mstart;
	for _i in 0..num{
		let mut offset = rng.gen::<usize>();
		offset = if b_in_seg {offset%seg_len} else {offset%num_vars};
		let var_id = cur_base + offset + 1;
		let coef = F::rand(rng);
		if var_id>num_vars {break;}
		if b_in_seg && var_id>=mend {break;}  
		cur_base = var_id;
		let item = LinearTerm::<F>{
			index : var_id,	
			value: coef
		};	
		vec.push(item);
	}
	return vec;
}

/// generate a random matrix of ncons constraints, nvars and num_entries
/// per row.
pub fn rand_matrix<F:FftField>(nvars: usize, ncons: usize, num_entries: usize, rng: &mut StdRng) -> Vec<Vec<LinearTerm<F>>>{
	if num_entries>=nvars {panic!("num_entries has to be less than nvars!");}
	let mut res = vec![vec![]; ncons];
	for i in 0..ncons{
		res[i] = rand_row(num_entries, nvars, rng);
	}
	return res;
}


/// write u64 as 8 bytes and store from vec[idx]
pub fn write_u64_to(val: u64, vec: &mut Vec<u8>, idx: usize){
	let v8 = val.to_le_bytes();
	for i in 0..8{
		vec[idx+i] = v8[i];
	}
}

/// read u64 from the index (8 bytes)
pub fn read_u64_from(vec: &Vec<u8>, idx: usize)->u64{
	let mut arr = [0u8; 8];
	arr.copy_from_slice(&vec[idx .. idx+8]);	
	let val = u64::from_le_bytes(arr);
	return val;
}


/// The var_id of LinearTerm should be treated as "ConstraintID" instead
/// of varialbe ID. Given the sparse vector, populates the full vector
/// of size n. 
pub fn sparse_vec_y_to_full_y<F:FftField>(v: &Vec<LinearTerm<F>>, 
	n: usize) -> Vec<F>{
	let mut res = vec![F::zero(); n];
	for item in v{
		res[item.index] = item.value;
	}
	return res;
}


/// treat the vector of linear term as the sparse valuation
/// NOTE: the var_id is treated as the constraint ID.
/// n: is treated as the number of constraints.
/// Run the ifft on expanded full vector and then run IFFT on it.
/// Resulting vector will be cloest power of 2 on it.
pub fn slow_sparse_ifft<F:FftField>(v: &Vec<LinearTerm<F>>, n: usize) 
	-> Vec<F>{
	let vec_y = sparse_vec_y_to_full_y(&v, n);
	let coefs = ifft(&vec_y);
	return coefs;	
}
/// for testing purpose. Establish for each column of the matrix
/// using IFFT and for each variable polynomial evaluate it ussing
/// given point t (ASSUMPTION: t is NOT any of the power of
/// the root of unity). Return the vector of poly evals.
/// matrix is sparse.
/// nvars: number of variables; ncons number of constraints 
/// NOTE: ncons must be >= v.len() as matrix is sparse
/// RETURN: size is actually nvars+1 (including const 1 column)
///
/// Performance: 2k: 1.5 sec (can't scale)
pub fn slow_matrix_to_qap_poly_eval<F:FftField>(
	v: &Vec<Vec<LinearTerm<F>>>, 
	nvars: usize, ncons: usize, t: F) -> Vec<F>{
	//1. convert the matrix to an array of sparse vectors
	let mut vec_cols = vec![vec![]; nvars+1];
	for row_id in 0..v.len(){
		let row = &v[row_id];
		for item in row{
			let col_id = item.index;
			let new_item = LinearTerm::<F>::new(row_id, item.value);
			vec_cols[col_id].push(new_item);
		}
	}
	//2. for each variable, generate the IFFT poly and eval it
	let mut res = vec![F::zero(); nvars+1];
	for col_id in 0..nvars+1{
		let col = &vec_cols[col_id];
		let coefs = slow_sparse_ifft(col, ncons); 
		let poly = DensePolynomial::<F>::from_coefficients_vec(coefs);
		res[col_id] = poly.evaluate(&t);
	}
	//3. return the result
	return res;
}

/// KEY function for converting from r1cs to QAP.
/// faster version assuming matrix is sparse. Use Lagrange coefs approach.
/// v: matrix. nvars: number of variables (NOT including constant column 1). ncons: number of constraints.
/// Lagrange Coefs definition: where omega^n = 1 (root of unity for n) 
/// 	l_j = \prod^{n-1}_0 (x-omega^i) / \prod_{i\neq j} (x_i - x_j)
/// Let z(x) = \prod^{n-1}_0 (x-omega^i). We have z(x) = x^n - 1
/// let v(i) = 1/\prod{i\neq j} (x_i - x_j)
/// Then v(0) = 1/n and v(i+1) = v(i) * omega
/// l_j(x) = z(x) * v(j) / (x - omega^i)
///
/// Performance: 1k: 8ms, 1M: 9 sec.
pub fn matrix_to_qap_poly_eval<F:FftField>(
	matrix: &Vec<Vec<LinearTerm<F>>>, 
	nvars: usize, ncons: usize, t: F)
	-> Vec<F>{
	//1. prep default result for each var
	let n = closest_pow2(ncons) as u64; 
	let mut res = vec![F::zero(); nvars+1];
	let z_t = t.pow(&[n]) - F::from(1u64); //z(t)
	let mut v = F::from(n).inverse().unwrap(); //v(0) 
	let mut omega_i = F::from(1u64);
	let omega = F::get_root_of_unity(n).unwrap();

	//2. process each constraint 
	for i in 0..matrix.len() as usize{
		//2.1 compute the Lagrange coef l_i
		let l_i = z_t * v * ((t - omega_i).inverse().unwrap());
		omega_i = omega_i * omega;
		v = v * omega; 

		//2.2. apply l_i to value of each term
		let row = &matrix[i];
		for item in row{//process each linear term
			let var_idx = item.index;
			res[var_idx] = res[var_idx] + l_i * item.value;
		}
	} 
	return res;
}

/// return res[i] = \sum_j mat[i][j].val * var[mat[i][j].index]
/// returned vec length is equal to the mat.len()
pub fn eval_matrix<F:FftField>(mat: &Vec<Vec<LinearTerm<F>>>, vars: &Vec<F>) 
-> Vec<F>{
	let n = mat.len();
	let mut res = vec![F::zero(); n];
	for i in 0..n{
		res[i] = R1CS::<F>::eval(&mat[i], vars);
	}
	return res;
}

/// return p(x) = x^n - 1
pub fn vanish_poly<F:FftField>(n: usize) -> DensePolynomial<F>{
	let mut vec_z = vec![];
	vec_z.push(F::zero() - F::from(1u64));
	for _i in 0..n-1{vec_z.push(F::zero());}
	vec_z.push(F::from(1u64));
	let poly_z = DensePolynomial::from_coefficients_vec(vec_z);
	return poly_z;
}
/// Given the a,b,c matrix and variable (full) assignment
/// Return the coefficients of the polynomial h(x) s.t.
/// let a_i(x) be the interpotation of variable i in matrix a ...
/// \sum vars[i] * a_i(x) * \sum vars[i] * b_i(x) = 
/// \sum vars[i]*c_i(x) h(x) t(x)
/// where t(x) = \prod (x-omega^i) and omega is the n'th root of unity
/// n is the cloest power of 2 of the number of constraints. 
/// return vec length: closet_pow2(a) [it actually has a leading 0 coef],
/// to be consistent with the compute_witness_h
/// Return a vector of size: n-1
///
/// Performance: 1k: 10ms, 1M: 30 seconds
/// It is about 5 times slower than compute_witness_h but of same complexity.
pub fn slow_compute_witness_h<F:FftField>(
	a: &Vec<Vec<LinearTerm<F>>>,
	b: &Vec<Vec<LinearTerm<F>>>,
	c: &Vec<Vec<LinearTerm<F>>>,
	vars: &Vec<F>) -> Vec<F>{
	//1. evaluate each matrix
	if a.len()!=b.len() || a.len()!=c.len() {panic!("a,b,c len not same!");}
	let sum_a = eval_matrix(a, vars);
	let sum_b = eval_matrix(b, vars);
	let sum_c = eval_matrix(c, vars);
	for i in 0..sum_a.len(){
		assert!(sum_a[i] * sum_b[i] == sum_c[i], "sum_a * sum_b != sum_c");
	}
	let n = closest_pow2(a.len());


	//2. ifft to get polys
	let ifft_a  = ifft(&sum_a);
	let ifft_b  = ifft(&sum_b);
	let ifft_c  = ifft(&sum_c);
	let poly_a = DensePolynomial::from_coefficients_vec(ifft_a);
	let poly_b = DensePolynomial::from_coefficients_vec(ifft_b);
	let poly_c = DensePolynomial::from_coefficients_vec(ifft_c);


	//3. compute z
	let poly_z = vanish_poly(n);

	//4. compute quotient h
	let diff = &(&poly_a * &poly_b) - &poly_c;
	let (q,r) = adapt_divide_with_q_and_r(&diff, &poly_z); 


	assert!(r.is_zero(), "r is not zero");
	let res = q.coeffs();
	let res2 = res.to_vec();
	assert!(res2.len()==n-1, "res2.len()!=n-1");
	return res2;
}

/// faster approach using coset fft/ifft	
/// return vec length: n-1
/// Performance: 1k: 2ms, 1M: 6 sec
pub fn compute_witness_h<F:FftField>(
	a: &Vec<Vec<LinearTerm<F>>>,
	b: &Vec<Vec<LinearTerm<F>>>,
	c: &Vec<Vec<LinearTerm<F>>>,
	vars: &Vec<F>) -> Vec<F>{

	//1. evaluate each matrix
	if a.len()!=b.len() || a.len()!=c.len() {panic!("a,b,c len not same!");}
	let sum_a = eval_matrix(a, vars);
	let sum_b = eval_matrix(b, vars);
	let sum_c = eval_matrix(c, vars);
	//disabled the following check for the function might be called to generate 
	//false instance
	//for i in 0..sum_a.len(){
	//	assert!(sum_a[i] * sum_b[i] == sum_c[i], "sum_a * sum_b != sum_c");
	//}
	let n = a.len();
	assert!(n.is_power_of_two(), "n is not power of 2");


	//2. ifft to get polys
	let ifft_a  = ifft(&sum_a);
	let ifft_b  = ifft(&sum_b);
	let ifft_c  = ifft(&sum_c);

	//3. fft coset to evaluate on a different point
	//let mut rng = gen_rng_from_seed(12793u128);
	let mut rng = gen_rng();
	let r = F::rand(&mut rng);
	let fft_a = fft_coset(&ifft_a, r);
	let fft_b = fft_coset(&ifft_b, r);
	let fft_c = fft_coset(&ifft_c, r);

	//3. compute z(t)
	let omega = F::get_root_of_unity(n as u64).unwrap();
	let t = omega * r; 	
	let t_n = t.pow(&[n as u64]); //this is essentially r^n as omega^n=1
	let z_t = t_n - F::from(1u64);
	let inv_z_t = z_t.inverse().unwrap();

	//4. compute quotient h
	let mut val_h = vec![F::zero(); n];
	for i in 0..n{
		val_h[i] = (fft_a[i] * fft_b[i] - fft_c[i]) * inv_z_t;
	}

	let h_coefs = ifft_coset(&val_h, r);
	//disabled for the function might be called to generate false instance
	//assert!(h_coefs[n-1]==F::zero(), "h_coefs leading element is not 0");
	let res = h_coefs[0..n-1].to_vec();	

	return res;
}
	
