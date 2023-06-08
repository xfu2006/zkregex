/** @file
 *****************************************************************************
 Implementation of PublicParams for Fp field arithmetic
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cassert>
#include <vector>

#include <libsnark/new_gadgetlib2/pp.hpp>

namespace new_gadgetlib2 {

template <class Fp>
PublicParams<Fp>::PublicParams(const std::size_t log_p) : log_p(log_p) {}

template<class Fp>
Fp PublicParams<Fp>::getFp(long x) const {
    return Fp(x);
}

template<class Fp>
PublicParams<Fp>::~PublicParams() {}

PublicParams<DefaultFp> initPublicParamsFromDefaultPp() {
    DefaultPp::init_public_params();
    const std::size_t log_p = DefaultFp::size_in_bits();
    return PublicParams<DefaultFp>(log_p);
}

} // namespace new_gadgetlib2
