#ifndef UTIL_HPP_
#define UTIL_HPP_

#include <libff/common/default_types/ec_pp.hpp>
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;


//1. default bn128 curve prime field
#ifndef FIELD_DEFS
#define FIELD_DEFS
typedef libff::Fr<libff::default_ec_pp> FieldT_Default;

//2. Prime field for libspartan
const mp_size_t limb_size = 4;
typedef libff::bigint<limb_size> bigint_r;
bigint_r mod_spartan = bigint_r("7237005577332262213973186563042994240857116359379907606001950938285454250989"); //curve 25519 for libspartan
typedef libff::Fp_model<limb_size, mod_spartan> FieldT_Spartan;

//3. Prime field for Aurora (alt_bn128)
bigint_r mod_aurora= bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617"); //curve alt_bn_128 Fr
typedef libff::Fp_model<limb_size, mod_aurora> FieldT_Aurora;

//4. Prime field for Bls12381
bigint_r mod_bls381= bigint_r("52435875175126190479447740508185965837690552500527637822603658699938581184513"); //curve Bls12-381
typedef libff::Fp_model<limb_size, mod_bls381> FieldT_Bls381;


#endif


void readIds(char* str, std::vector<unsigned int>& vec);

template <class Fp>
Fp readFieldElementFromHex(char* str);

#include <libsnark/genr1cs_interface/Util.tcc>
#endif
