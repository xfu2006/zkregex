/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/18/2022
	Completed: 07/19/2022
	Fixed: 07/21/2022
*/

/// This module defines the zero knowledge equality proof for 
/// a given sequence of group elements in the following form
/// y_0 = g_01^x_1 g_02^x_2 g_03^x_3... g_0n^x_n 
/// y_1 = g_11^x_1 ..... g_1m^r_m
/// y_2 = g_21^x_2 g_22^r_2 ...g_2l^r_l
/// y_3 = g_31^x_3 ...
/// ...
/// y_{n} = g_n1^x_n ... g_r5^r_r5
///
/// Where y_0 agrees with y_i on its (i-1)'th exponent (and the
/// 0'th component of y_i), e.g., Note the use of x_i as the
/// first exponent for each y_i
/// It is required that if y is the multiplication of n exponentiations,
/// then there should n subsequent group elemnets: y_1 to y_n.
/// The Fiat-Shamir heurstics is applied and the challenge is
/// generated by hashing the inputs and 1st round msg.
///
/// Performance: 7 rows, prove: 3ms, verification 3 ms (25 exponentiatios)
/// Size: 616 bytes.
/// over G1 of BN254, 616 bytes.

extern crate ark_ff;
extern crate ark_serialize;

use proto::*;
use tools::*;
use self::ark_ec::{AffineCurve, ProjectiveCurve};
use self::ark_ff::{Zero,UniformRand};
use self::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::profiler::config::*;
use self::ark_ec::msm::{VariableBaseMSM};

#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// --------------------------------------------------- 
//  Utility Functions
// --------------------------------------------------- 

/// pack a small vector of u64 (dimension<8) and each element<8
/// basic idea: each digit represents such a u64
pub fn pack_arr_small_u64(v: &Vec<u64>) -> u64{
	let n = v.len() as u64;
	assert!(n<10, "pack_arr_small_u64 ERROR: v.len(): {} >=10", n);
	let mut res:u64 = 0;
	for i in 0..v.len(){
		let x = v[v.len()-1-i];
		assert!(x<8, "pack_arr_small_utr ERROR: x: {} >=8", x);
		res = res * 10 + x;	
	}
	res = res*10 + n;
	return res;
}

/// unpack the packed u64 into array of u64
pub fn unpack_arr_small_u64(inp: u64) -> Vec<u64>{
	let mut v = inp;
	let n = v%10;
	v = v/10;
	let mut vec = vec![0u64; n as usize];
	for i in 0..vec.len(){
		vec[i] = v % 10;
		v = v / 10;
	} 
	return vec;
}

/// convert slice to array
fn slice_to_arr8(v: &[u8]) -> [u8; 8]{
	assert!(v.len()==8, "slice_arr_8 ERROR len!=8");	
	let mut arr: [u8; 8] = [0u8; 8];
	for i in 0..8{
		arr[i] = v[i];
	}
	return arr;
}


// --------------------------------------------------- 
//  Data Structures: zkSame Claim, Proof, and Input
// --------------------------------------------------- 
/// The input that are used to generate claim and proof
#[derive(Clone)]
pub struct ZkSameInput<G: AffineCurve> where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// vector of exponents, e.g., y = g_1^exps[0][0] g_2^exps[0][1] ...
	/// sizes must match the bases in ZkSame Protocol
	/// It is required that:
	/// exps[0][0] = exps[1][0], exps[0][1] = exps[2][0]
	/// exps[0][2] = exps[3][0] ....
	/// that is: exps[0][i]== exps[i+1][0]
	pub exps: Vec<Vec<G::ScalarField>>,
}

/// Built from Schnorr's DLOG protocol. It consists of random commits
/// sent in the first round, and the responses sent in the 2nd round.
#[derive(Clone)]
pub struct ZkSameProof<G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// One commitment for each y_i
	pub commits: Vec<G>,
	/// vectors of responses for each G's. Note that
	/// responds[i][0] = responds[0][i-1] for i>0
	/// TO save space in proof, we do not save it
	/// that repsonds[i][j] is actually responds[i][j+1] for i>0
	pub responds: Vec<Vec<G::ScalarField>>,
}

#[derive(Clone)]
pub struct ZkSameClaim<G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	pub y: Vec<G>,
}

/// The ZkSame protocol 
#[derive(Clone)]
pub struct ZkSame<E: PairingEngine, G: AffineCurve>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// vector of bases. e.g., bases[0] are the bases for y[0] etc.
	pub bases: Vec<Vec<G>>,
	/// This is a parameter vector, never used.
	pub _key: Rc<DisKey<E>>
}

// --------------------------------------------------- 
// Implementations 
// --------------------------------------------------- 

impl <G:AffineCurve> ProverInput for ZkSameInput<G>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>
{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }
	fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl <G:AffineCurve> ProtoObj for ZkSameProof<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serialization
	fn to_bytes(&self)->Vec<u8>{
		//1. get the length pack 
		// [len(responds), len(commits), len(responds[0]), ....len(responds[n])
		let mut b1: Vec<u8> = vec![];
		let ncom = self.commits.len();
		let n = self.responds.len();
		let mut vlen = vec![0u64; n+2];
		vlen[0] = n as u64;
		vlen[1] = ncom as u64;
		for i in 0..n {vlen[i+2] = self.responds[i].len() as u64;}
		let pack_n = pack_arr_small_u64(&vlen);

		//2. serialization
		let mut b_all = pack_n.to_le_bytes().to_vec();	
		assert!(b_all.len()==8, "b_all.len()!=8");
		for i in 0..ncom{
			G::serialize(&self.commits[i], &mut b1).unwrap();
		}
		for i in 0..n{
			for j in 0..self.responds[i].len(){
				G::ScalarField::serialize(&self.responds[i][j], 
					&mut b1).unwrap();
			}
		}
		b_all.append(&mut b1);
		return b_all;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		//1. retrieve the pack
		let s1 = &v[0..8];
		let v1 = slice_to_arr8(&s1);
		let pack_n: u64 = u64::from_le_bytes(v1);
		let vlen: Vec<u64> = unpack_arr_small_u64(pack_n);
		let n = vlen[0] as usize;
		let ncom = vlen[1] as usize;
		let mut b1 = &v[8..];

		//2. deserialize follow the structure
		let mut commits = vec![G::zero(); ncom];
		let mut responds:Vec<Vec<G::ScalarField>> = vec![vec![]; n];
		for i in 0..ncom{
			commits[i] = G::deserialize(&mut b1).unwrap();
		}
		for i in 0..n{
			let veclen = vlen[i+2] as usize;
			responds[i] = vec![G::ScalarField::zero(); veclen];
			for j in 0..veclen {
				responds[i][j] = G::ScalarField::deserialize(&mut b1).unwrap();
			}
		}
		let res = ZkSameProof::<G>{
			commits: commits,
			responds: responds
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!(" {} ZkSameProof: ", prefix);
		for i in 0..self.commits.len(){
			print!(" {} :", self.commits[i]);
		}
		print!(" , Responds: ");
		for i in 0..self.responds.len(){
			print!(" {}: ", i);
			for j in 0..self.responds[i].len(){
				print!(" {} ", self.responds[i][j]);
			}
		}
		print!(") \n");
	} 

}

impl <G:AffineCurve> Proof for ZkSameProof<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// deserialization, instance version
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.commits = res.commits.clone();
		self.responds = res.responds.clone();
	}

	/// check equals
	fn equals(&self, other: &dyn Proof)->bool{	
		let obj:&ZkSameProof::<G> = other.as_any().
			downcast_ref::<ZkSameProof<G>>().unwrap();
		return self.commits==obj.commits && self.responds==obj.responds;
	}
}

impl <G:AffineCurve> ProtoObj for ZkSameClaim<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// for downcasting	
	fn as_any(&self) -> &dyn Any { self }

	/// serlization
	fn to_bytes(&self)->Vec<u8>{
		let n: u64 = self.y.len() as u64;
		let mut b_all= n.to_le_bytes().to_vec();
		let mut b1: Vec<u8> = vec![];
		for i in 0..self.y.len(){
			G::serialize(&self.y[i], &mut b1).unwrap();
		}
		b_all.append(&mut b1);
		return b_all;
	}

	/// deserialization
	fn static_from_bytes(v: &Vec<u8>)->Box<Self>{
		//1. retrieve the pack
		let s1 = &v[0..8];
		let v1 = slice_to_arr8(&s1);
		let n = u64::from_le_bytes(v1) as usize;
		let mut v2 = &v[8..];

		//2. deserialize
		let mut y: Vec<G> = vec![G::zero(); n];
		for i in 0..n{
			y[i] = G::deserialize(&mut v2).unwrap();		
		}
		let res = ZkSameClaim::<G>{
			y: y
		};
		return Box::new(res);
	}

	/// dump
	fn dump(&self, prefix: &str){
		println!("{} (ZkSameClaim y: ", prefix);
		for i in 0..self.y.len(){
			print!(" {} ", self.y[i]);
		}
		print!(")");
	} 

}

impl <G:AffineCurve> Claim for ZkSameClaim<G> 
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// deserialization
	fn from_bytes(&mut self, v: &Vec<u8>){
		let res = Self::static_from_bytes(v);
		self.y= res.y.clone();
	}

	/// equals
	fn equals(&self, obj: &dyn Claim)->bool{	
		let other:&ZkSameClaim::<G> = obj.as_any().
			downcast_ref::<ZkSameClaim<G>>().unwrap();
		return self.y==other.y;
	}
}

impl <E: PairingEngine, G: AffineCurve> Protocol<E> for ZkSame<E, G>
where
E: PairingEngine<G1Affine=G>,
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// return the name
	fn name(&self)->&str{
		return "ZkSame";
	}

	fn prove(&self, inp: &mut dyn ProverInput) -> Box<dyn Proof> {
		//1. cast input
		let sinp:&mut ZkSameInput<G> = inp.as_any_mut().
			downcast_mut::<ZkSameInput<G>>().unwrap();

		//2. generate the random commitments for each base signature
		let n = self.bases.len();
		let mut rng = gen_rng();
		let mut commits = vec![];
		let mut vec_r:Vec<Vec<G::ScalarField>> = vec![];
		for i in 0..n{
			let vbase = &self.bases[i];
			let nexps = vbase.len();
			let mut res = G::zero();
			let mut row = vec![G::ScalarField::zero(); nexps];
			for j in 0..nexps{
				//uses same for MATCHING component for y_i: i>0
				row[j] = if i==0 || j!=0 {G::ScalarField::rand(&mut rng)}
					else {vec_r[0][i-1].clone()}; 
				let item = vbase[j].mul(row[j]).into_affine();
				res = res + item;
			}
			vec_r.push(row);
			commits.push(res);
		}
	
		//3. generate the random challenge as hash of all sigs
		let b8 = to_vecu8(&commits);
		let c = hash::<G::ScalarField>(&b8);

		//4. generate the responses
		let mut responds:Vec<Vec<G::ScalarField>> = vec![vec![]; n];
		for i in 0..responds.len(){
			let mut row_len = self.bases[i].len();
			if i>0 {row_len -=1;}  //becase we can skip responds[i][0] for i>0
			responds[i] = vec![G::ScalarField::zero(); row_len];
			for j in 0..row_len{
				if i==0{//first row (no skip)
					responds[i][j] = c*sinp.exps[i][j] +  vec_r[i][j];   
				}else{//NOTE: responds[i][0] is skiped for i>0
					responds[i][j] = c*sinp.exps[i][j+1] +  vec_r[i][j+1];   
				}
			}
		}

		//5. build up the proof 
		let prf = ZkSameProof::<G>{
			commits: commits,
			responds: responds
		};
		return Box::new(prf);
	}

	/// generate the claim
	/// NOTE only return valid result in main processor 0
	fn claim(&self, inp: &mut dyn ProverInput) -> Box<dyn Claim> {
		let kinp:&mut ZkSameInput::<G> = inp.as_any_mut().
			downcast_mut::<ZkSameInput<G>>().unwrap();
		let n = self.bases.len();
		let mut y  = vec![G::zero(); n]; 
		for i in 0..n{
			let mut res = G::zero();
			assert!(self.bases[i].len()==kinp.exps[i].len(), 
				"claim() ERR: base.len()!=exps.len()");
			for j in 0..self.bases[i].len(){
				let exp: G::ScalarField = kinp.exps[i][j];
				let item = self.bases[i][j].mul(exp).into_affine();
				res = res + item;
			} 
			y[i] = res;
		}
		let claim = ZkSameClaim::<G>{ y : y };
		return Box::new(claim);
	}

	/// verify if the proof is valid for claim
	/// NOTE only return valid result in main processor 0
	fn verify(&self, claim: &dyn Claim, proof: &dyn Proof)->bool{
		//ONLY check on main processor: 0
		if RUN_CONFIG.my_rank!=0 { return true; }

		//0. type casting
		let s_claim:&ZkSameClaim::<G> = claim.as_any().
			downcast_ref::<ZkSameClaim<G>>().unwrap();
		let s_proof:&ZkSameProof::<G> = proof.as_any().
			downcast_ref::<ZkSameProof<G>>().unwrap();

		//1. compute the challenge c
		let b8 = to_vecu8(&s_proof.commits);
		let c = hash::<G::ScalarField>(&b8);
		let zero = G::ScalarField::zero();
		let one = G::ScalarField::from(1u64);
		let none = zero - one;
		let gzero= self._key.g.into_affine().mul(zero).into_affine();

		//2. check for each i:
		//  y_i^c * commit[i] = \prod basei[j]^responds[i][j]
		// NOTE: here * in group op is +, and ^ is mul
		//	let mut t = Timer::new();
		// PACK ALL checks into ONE multi-exponentiation
		// For each i'th equation: all exponents MULTIPLY with r^i
		//let mut num_exps = 0;
		let mut rng = gen_rng();
		let r = G::ScalarField::rand(&mut rng);
		let mut factor  = r.clone();
		let mut vec_bases = vec![];
		let mut vec_exp = vec![];
		for i in 0..self.bases.len(){
			//1. compute right hand side
			let mut exps = &s_proof.responds[i];
			let mut row = vec![G::ScalarField::zero(); self.bases[i].len()];
			if i>0{//need to insert an item
				for j in 0..self.bases[i].len(){
					if j==0{
						row[j] = s_proof.responds[0][i-1].clone();
					}else {
						row[j] = exps[j-1].clone();
					}
				}
				exps = &row;
			}
			let gs = &self.bases[i];
			//let mut rhs = G::zero();
			assert!(exps.len()==gs.len(), 
				"veryfy() ERR: base.len()!=exps.len()");
			for j in 0..exps.len(){
				//OLD -- slow
				//let item = gs[j].mul(exps[j]).into_affine();
				//rhs = rhs + item;
				//num_exps += 1;
				//NEW --- multi-exponentiation
				vec_exp.push(exps[j]*factor);
				vec_bases.push(gs[j]);
			}

			//2. compute the left hand size
			let y_i = s_claim.y[i];
			let commit_i = s_proof.commits[i];
			//let item = y_i.mul(c).into_affine();
			//let lhs = commit_i + item;	
			//num_exps += 1;
			//if lhs!=rhs {
			//	return false;
			//}	
			//NEW
			vec_exp.push((zero-c)*factor);
			vec_exp.push(none*factor);
			vec_bases.push(y_i);
			vec_bases.push(commit_i);
			factor = factor * r;
		}
		//println!("DEBUG USE 888: bases.len(): {}, num_exps: {}, one exp time: {}us ", self.bases.len(), num_exps, t.time_us);

		//NEW multi-exponentiation
		let tres: _= <G::Projective as VariableBaseMSM>::msm(
            &vec_bases[0..],
            &vec_exp[0..]
		);
		let res = tres.into_affine();
		if res!=gzero{
			return false;
		}
		return true;
	}

	/// generate a random instance. n is the number of group elements
	/// in claim.y vector.
	/// seed uniquely determines the instance generated
	/// n_proposed is the proposed size (if it's bigger than 8, the 
	/// size will be set to up to 7 due to restriction in pack_small_arr_u64)
	/// Note that the protocol is to be used in several kzg related 
	/// protocols, its size will be up to 5. (no need for supporting large n)
	fn rand_inst(&self, n_proposed: usize, seed: u128, b_set_err: bool, key: Rc<DisKey<E>>) -> (Box<dyn Protocol<E>>, Box<dyn ProverInput>, Box<dyn Claim>, Box<dyn Proof>){
		//1. generate the protocol
		//NOTE: due to the pack_small_u64 restriction, n cannot be >=8
		let n = if n_proposed>=8 {7} else {n_proposed};
		let mut rng = gen_rng_from_seed(seed);
		let mut vsize= vec![2usize; n];
		vsize[0] = n-1;
		let bases = Self::gen_rand_bases(127, &vsize);
		let proto = ZkSame::<E,G>::new_with_bases(bases.clone(), key); 		

		//2. generate the input, claim, and proof
		let mut exps = vec![vec![]; n];
		for i in 0..n{
			exps[i] = vec![G::ScalarField::zero(); bases[i].len()];
			for j in 0..exps[i].len(){
				if i==0{
					exps[i][j] = G::ScalarField::rand(&mut rng);
				}else{
					//see doc for i>0: y_i's first
					//exponent should match the (i-1)'th component of y_0
					exps[i][j] = if j!=0 {G::ScalarField::rand(&mut rng)}
						else {exps[0][i-1]}; 
				}
			}
		}
		let mut inp = ZkSameInput::<G> {exps: exps};
		let mut claim = proto.claim(&mut inp);
		let prf = proto.prove(&mut inp);

		//3. introduce error
		if b_set_err{
			let one: G = G::rand(&mut rng);
			let sclaim:&ZkSameClaim::<G> = claim.as_any().
				downcast_ref::<ZkSameClaim<G>>().unwrap();
			let new_y0 = sclaim.y[0] + one;
			let mut new_y = sclaim.y.clone();
			new_y[0] = new_y0;
			let bad_claim: ZkSameClaim<G> = ZkSameClaim {y: new_y};
			claim = Box::new(bad_claim);
		}
		return (Box::new(proto), Box::new(inp), claim, prf);
	}

	/// factory method.  ONLY USED FOR testing purpose as bases are
	/// generated
	fn new(key: Rc<DisKey<E>>) -> Self{
		let vsize:Vec<usize> = vec![3, 2, 2, 2];
		let bases = Self::gen_rand_bases(127, &vsize);
		let s_proto = Self::new_with_bases(bases, key);
		return s_proto;
	}
}

impl <E:PairingEngine, G: AffineCurve> ZkSame<E,G>
where
<G as AffineCurve>::Projective: VariableBaseMSM<MSMBase=G, Scalar=<G as AffineCurve>::ScalarField>{
	/// generate a vector of random bases
	pub fn gen_rand_bases(seed: u128, vsize: &Vec<usize>)->Vec<Vec<G>>{
		let mut rng = gen_rng_from_seed(seed);
		//see requirement: y and y1...yn (matching of exponents len)
		assert!(vsize[0]==vsize.len()-1, "gen_rand_bases: required: vsize[0]==vsize.len()-1");
		let mut vec = vec![vec![]; vsize.len()];	
		for i in 0..vsize.len(){
			let nexps = vsize[i];
			vec[i] = vec![G::zero(); nexps];
			for j in 0..nexps{
				if i>1 && vsize[i]==vsize[i-1]{
					vec[i][j] = vec[i-1][j].clone();
				}else{
					vec[i][j] = G::rand(&mut rng);
				}
			}
		}
		return vec;
	}

	/// Constructor. real constructor used. 
	pub fn new_with_bases(bases: Vec<Vec<G>>, key: Rc<DisKey<E>>)->Self{
		let proto = ZkSame{
			bases: bases,
			_key : key
		};
		return proto;
	}
}