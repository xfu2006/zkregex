/** 
	Copyright Dr. CorrAuthor

	Author: Dr. CorrAuthor
	All Rights Reserved.
	Created 10/16/2022
	
	some common utility functions

*/


extern crate ark_ff;
extern crate ark_std;
extern crate ark_serialize;
extern crate ark_ec;
extern crate ark_poly;

use profiler::config::*;
use tools::*;
use self::ark_ff::{PrimeField};
use self::ark_ec::{PairingEngine,AffineCurve,ProjectiveCurve};
use self::ark_ec::msm::{FixedBase,VariableBaseMSM};
//use tools::*;
//use poly::dis_key::*;


#[cfg(feature = "parallel")]
use ark_std::cmp::max;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// return [g^arr[0], ..., g^arr[n-1]
pub fn msm_g1<E:PairingEngine>(g: E::G1Projective, arr: &Vec<E::Fr>) 
	-> Vec<E::G1Affine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let n = arr.len();
	let window_size = FixedBase::get_mul_window_size(n+1);
	let scalar_bits = E::Fr::MODULUS_BIT_SIZE as usize;
	let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
	let powers_proj= FixedBase::msm::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &arr,
	);
	let res = E::G1Projective::batch_normalization_into_affine(&powers_proj);
	return res;
}

/// return [g^arr[0], ..., g^arr[n-1]
pub fn msm_g2<E:PairingEngine>(g: E::G2Projective, arr: &Vec<E::Fr>) 
	-> Vec<E::G2Affine> where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField>{
	let n = arr.len();
	let window_size = FixedBase::get_mul_window_size(n+1);
	let scalar_bits = E::Fr::MODULUS_BIT_SIZE as usize;
	let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
	let powers_proj= FixedBase::msm::<E::G2Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &arr,
	);
	let res = E::G2Projective::batch_normalization_into_affine(&powers_proj);
	return res;
}


/// return [g_0^arr[0], ..., g_{n-1}^arr[n-1]
pub fn vmsm_g1<E:PairingEngine>(g: &Vec<E::G1Affine>, arr: &Vec<E::Fr>) 
-> E::G1Affine
where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField> {
		let b_perf = false;
		let mut timer = Timer::new();
		timer.start();
        let res: _ = <E::G1Projective as VariableBaseMSM>::msm(
            &g[..],
			arr
        );
		let res = res.into_affine();
		if b_perf {log_perf(LOG1, &format!("------ msm: size: {}", &g.len()), &mut timer);}
		return res;
}

/// return [g_0^arr[0], ..., g_{n-1}^arr[n-1]
pub fn vmsm_g2<E:PairingEngine>(g: &Vec<E::G2Affine>, arr: &Vec<E::Fr>) 
-> E::G2Affine
where
 <<E as PairingEngine>::G1Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G1Affine, Scalar=<<E  as PairingEngine>::G1Affine as AffineCurve>::ScalarField>,
 <<E as PairingEngine>::G2Affine as AffineCurve>::Projective: VariableBaseMSM<MSMBase=E::G2Affine, Scalar=<<E  as PairingEngine>::G2Affine as AffineCurve>::ScalarField> {
		let b_perf = false;
		let mut timer = Timer::new();
		timer.start();
        let res: _ = <E::G2Projective as VariableBaseMSM>::msm(
            &g[..],
			arr
        );
		let res = res.into_affine();
		if b_perf {log_perf(LOG1, &format!("------ msm_g2: size: {}", &g.len()), &mut timer);}
		return res;
}
