/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created: 07/14/2022
	Completed: 07/16/2022
*/

/**! This is the generic testing framework for all protocols.
	Modify get_all_protocols() when new zk-protocols are added.
*/
use crate::proto::*;
use crate::proto::kzg::*;
use crate::proto::subset::*;
use crate::proto::nonzk_sigma::*;
use crate::proto::zk_same::*;
use crate::proto::zk_prod::*;
use crate::proto::zk_poly::*;
use crate::proto::zk_kzg::*;
use crate::proto::zk_kzg_v2::*;
use crate::proto::zk_kzg_vsql::*;
use crate::proto::zk_subset::*;
use crate::proto::zk_subset_v2::*;
use crate::proto::zk_subset_v3::*;
use crate::proto::zk_sigma::*;
use crate::proto::zk_dlog::*;
use crate::proto::zk_conn::*;
use crate::profiler::config::*;
use crate::tools::*;
use self::ark_ec::msm::{VariableBaseMSM};
use self::ark_ec::{AffineCurve, PairingEngine};

/// Given the desired Prover Key Size (n), return all protocols available.
/// If necessary, the size will be adjusted to fit the min num of processors.
/// It returns an array of protocols and the Prover key in the setting.
pub fn get_all_protocols<E:PairingEngine>(n: usize)->
	(Vec<Box<dyn Protocol<E>>>, Rc<DisKey<E>>)
	where <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let mut size = n;
	let np = RUN_CONFIG.n_proc; //some would crash if size < np
	size = if size>2*np+16 {size} else {2*np+16};
	let key = Rc::new(DisKey::<E>::gen_key1(size));
	//list every protocol here
	let _arr_protols: Vec<Box<dyn Protocol<E>>> = vec![
		Box::new(KZG::<E>::new(key.clone())), //0
		Box::new(Subset::<E>::new(key.clone())), //1
		Box::new(NonzkSigma::<E>::new(key.clone())), //2
		Box::new(ZkProd::<E,E::G1Affine>::new(key.clone())), //3
		Box::new(ZkSame::<E,E::G1Affine>::new(key.clone())), //4
		Box::new(ZkPoly::<E>::new(key.clone())), //5
		Box::new(ZkKZG::<E>::new(key.clone())), //6
		Box::new(ZkSubset::<E>::new(key.clone())), //7
		Box::new(ZkSigma::<E>::new(key.clone())), //8
		Box::new(ZkKzgVsql::<E>::new(key.clone())), //9
		Box::new(ZkSubsetV2::<E>::new(key.clone())), //10
		Box::new(ZkDLOG::<E,E::G1Affine>::new(key.clone())), //11
		Box::new(ZkSubsetV3::<E>::new(key.clone())), //12
		Box::new(ZkKZGV2::<E>::new(key.clone())), //13
		Box::new(ZkConn::<E>::new(key.clone())), //14
	];
	//the actual one returned
	let act_protols: Vec<Box<dyn Protocol<E>>> = vec![
/*
		Box::new(KZG::<E>::new(key.clone())), //0
		Box::new(Subset::<E>::new(key.clone())), //1
		Box::new(NonzkSigma::<E>::new(key.clone())), //2
		Box::new(ZkProd::<E,E::G1Affine>::new(key.clone())), //3
		Box::new(ZkSame::<E,E::G1Affine>::new(key.clone())), //4
		Box::new(ZkPoly::<E>::new(key.clone())), //5
		Box::new(ZkKZG::<E>::new(key.clone())), //6
		Box::new(ZkSubset::<E>::new(key.clone())), //7
		Box::new(ZkSigma::<E>::new(key.clone())), //8
		Box::new(ZkKzgVsql::<E>::new(key.clone())), //9
		Box::new(ZkSubsetV2::<E>::new(key.clone())), //10
		Box::new(ZkDLOG::<E,E::G1Affine>::new(key.clone())), //11
		Box::new(ZkSubsetV3::<E>::new(key.clone())), //12
		Box::new(ZkKZGV2::<E>::new(key.clone())), //13
*/
		Box::new(ZkConn::<E>::new(key.clone())), //14
	];
	return (act_protols, key);
}
/// if the size is too small adjust it based on number of processors
pub fn get_adjusted_key_size(n: usize) -> usize{
	let np = RUN_CONFIG.n_proc as usize; //some would crash if size < np
	let np = np * 16;
	if n<np*2+16 {return np*2+16} else {return n;}
}

/// return the largest test size allowed by a prover key
pub fn get_max_test_size_for_key<E:PairingEngine> (key: &Rc<DisKey<E>>)->usize{
	return key.n/2-9;
}


#[cfg(test)]
mod tests {
	extern crate ark_poly;
	extern crate ark_ec;
	extern crate ark_ff;
	extern crate ark_bn254;
	extern crate ark_bls12_381;

	use std::borrow::Borrow;
	use crate::profiler::config::*;
	use crate::proto::proto_tests::*;
	use crate::proto::ripp_driver::*;
	//use crate::proto::zk_same::*;
	use poly::common::*;

	use self::ark_bn254::Bn254;
	type Fr = ark_bn254::Fr;
	type PE= Bn254;
	//use self::ark_bls12_381::Bls12_381;
	//type Fr = ark_bls12_381::Fr;
	//type PE= Bls12_381;

	
	/// test a protocol's completeness and soundness
	/// Idea: to test completeleness, generate a good instance, check
	/// verify works; to test soundness, generate a bad instance,
	/// check if verify() fails
	fn test_proto<E:PairingEngine>(inst: Box<dyn Protocol<E>>, 
	key: Rc<DisKey<E>>){
		//0. seeds and size
		let size = get_max_test_size_for_key(&key);
		let seed = 1739127;
		log(LOG1, &format!("Test protocol: {}, size: {}", inst.name(), size));

		//1. test complete (using a valid instance). verify() should be true
		let (proto, _inp, claim, prf)= inst.rand_inst(
			size,seed,false, key.clone()); //no err injected 
		let bres = proto.verify(claim.borrow(), prf.borrow());
		if RUN_CONFIG.my_rank==0{
			let msg = format!("Completeness test failed for: {}", inst.name());
			assert!(bres==true, "{}", msg);
		}
		//2. test sound  (using an invalid instance)
		let (proto, _inp, claim, prf)= inst.rand_inst(
			size, seed,true, key.clone()); //err injected 
		let bres = proto.verify(claim.borrow(), prf.borrow());
		if RUN_CONFIG.my_rank==0{
			let msg = format!("Soundness test failed for: {}", inst.name());
			assert!(bres==false, "{}", msg);
		}
	}

	/// Test the Claim and Proof serialization and deserialization
	fn test_serialization<E:PairingEngine>(inst: Box<dyn Protocol<E>>, key:Rc<DisKey<E>>){
		//0. seeds and size
		let size = get_max_test_size_for_key(&key);
		let seed = 1739127;

		//1. create two instances.
		let (proto, _inp, claim, prf)= inst.rand_inst(size,seed,false, key.clone()); 
		let (_, _inp, mut claim2, mut prf2)=inst.rand_inst(size,seed+71,false, key.clone()); 

		//2. serialize and then deserialize
		let bclaim = claim.to_bytes();
		claim2.from_bytes(&bclaim);
	
		let bprf = prf.to_bytes();
		prf2.from_bytes(&bprf);

		let bres= proto.verify(claim2.borrow(), prf2.borrow());
		if RUN_CONFIG.my_rank==0{
			assert!(claim.equals(claim2.borrow()),
				"Claim Serialize Failed for {}", inst.name());
			assert!(prf.equals(prf2.borrow()), 
				"Prf Serialize Test Failed for {}", inst.name());
			assert!(bres, "Restored prf does not work for {}!", inst.name());
		}

	}

	#[test]
	fn test_all_proto_complete_sound(){
		let n = get_adjusted_key_size(64);
		let (arr_protols, key) = get_all_protocols::<PE>(n);
		for proto in arr_protols{
			test_proto(proto, key.clone());
		}
	}

	#[test]
	fn test_all_proto_serialize(){
		let n = get_adjusted_key_size(64);
		let (arr_protols, key) = get_all_protocols::<PE>(n);
		for proto in arr_protols{
			test_serialization(proto, key.clone());
		}
	}

	#[test]
	fn test_pack(){
		let v1: Vec<u64> = vec![3, 7, 2];
		let res = pack_arr_small_u64(&v1);
		let v2 = unpack_arr_small_u64(res);
		assert!(v1==v2, "test_pack failed");
	}
/*
	#[test]
	fn test_subset_aggregate(){
		let n = 128;
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
		let key_size = if np<16 {64} else {np*16};
		let key = Rc::new(DisKey::<PE>::gen_key1(key_size));
		let seed = 13214u128;
		let size = get_max_test_size_for_key(&key);
		let proto = ZkSubsetV3::<PE>::new(key.clone());
		let mut claims:Vec<ZkSubsetV3Claim<PE>> = vec![];
		let mut prfs:Vec<ZkSubsetV3Proof<PE>> = vec![];
		let vec_crs = create_vec_crs_verifier::<PE>(n);
		let g5s = extract_g5s(&vec_crs);
		let gipa = GIPA::<PE>::setup(n, &key, &g5s, &vec_crs);
		for i in 0..n{
			let mut g5 = vec![];
			for j in 0..5 {g5.push(g5s[j][i].clone());}
			let (_proto, _inp, cl, pr)= proto.rand_inst(
			size,seed + i as u128 ,false, key.clone()); //no err injected 
			let claim=cl.as_any().
				downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap(); 
			let proof=pr.as_any().
				downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap(); 
			let c2 = claim.clone();
			claims.push(c2);
			let p2 = proof.clone();
			prfs.push(p2);
		}
		let (c_claim, c_prf) = ZkSubsetV3::<PE>::
			agg_prove(&claims, &prfs, &gipa, &key);
		let bres = ZkSubsetV3::<PE>::
			agg_verify(&c_claim, &c_prf, &gipa, &key);
		if me==0 {assert!(bres, "aggregate prf of ZkSubsetV3 failed");}
	}
	#[test]
	fn test_kzg2_aggregate(){
		let n = 128;
		let me = RUN_CONFIG.my_rank;
		let np = RUN_CONFIG.n_proc;
		let key_size = if np<16 {64} else {np*16};
		let key = Rc::new(DisKey::<PE>::gen_key1(key_size));
		let seed = 13214u128;
		let size = get_max_test_size_for_key(&key);
		let proto = ZkKZGV2::<PE>::new(key.clone());
		let mut claims:Vec<ZkKZGV2Claim<PE>> = vec![];
		let mut prfs:Vec<ZkKZGV2Proof<PE>> = vec![];
		let vec_crs = create_vec_crs_verifier::<PE>(n);
		let g5s = extract_g5s(&vec_crs);
		let gipa = GIPA::<PE>::setup(n, &key, &g5s);
		for i in 0..n{
			let mut g5 = vec![];
			for j in 0..5 {g5.push(g5s[j][i].clone());}
			let (_proto, _inp, cl, pr)= proto.rand_inst_adv(
			size,seed + i as u128 ,false, key.clone(), &g5); //no err injected 
			let claim=cl.as_any().
				downcast_ref::<ZkSubsetV3Claim<PE>>().unwrap(); 
			let proof=pr.as_any().
				downcast_ref::<ZkSubsetV3Proof<PE>>().unwrap(); 
			let c2 = claim.clone();
			claims.push(c2);
			let p2 = proof.clone();
			prfs.push(p2);
		}
		let (c_claim, c_prf) = ZkKZGV2::<PE>::
			agg_prove(&claims, &prfs, &gipa, &key);
		let bres = ZkKZGV2::<PE>::
			agg_verify(&c_claim, &c_prf, &gipa, &key);
		if me==0 {assert!(bres, "aggregate prf of ZkSubsetV3 failed");}
	}
*/
}
