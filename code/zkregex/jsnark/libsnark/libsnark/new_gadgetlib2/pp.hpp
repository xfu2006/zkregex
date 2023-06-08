/** @file
 *****************************************************************************
 Declaration of PublicParams for Fp field arithmetic
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

//MODS by CorrAuthor
// remove depending on ec_pp

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_PP_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_PP_HPP_

#include <memory>
#include <vector>

#include <libff/common/default_types/ec_pp.hpp>

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P World                           ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/* curve-specific public parameters */
//typedef libff::Fr<libff::default_ec_pp> Fp;
//typedef std::vector<Fp> FpVector;

typedef libff::default_ec_pp DefaultPp; //such as bn128_pp
typedef libff::Fr<libff::default_ec_pp> DefaultFp;
template<class Fp>
class PublicParams {
public:
    size_t log_p;
    PublicParams(const std::size_t log_p);
    Fp getFp(long x) const; // to_support changes later
    ~PublicParams();
};

PublicParams<DefaultFp> initPublicParamsFromDefaultPp();

} // namespace new_gadgetlib2

#include <libsnark/new_gadgetlib2/pp.tcc>
#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_PP_HPP_
