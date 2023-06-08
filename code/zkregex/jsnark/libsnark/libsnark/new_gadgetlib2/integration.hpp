/** @file
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef INTEGRATION_HPP_
#define INTEGRATION_HPP_

#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/new_gadgetlib2/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

template <class Fp>
r1cs_constraint_system<Fp> get_constraint_system_from_new_gadgetlib2(const new_gadgetlib2::Protoboard<Fp> &pb);
template <class Fp>
r1cs_variable_assignment<Fp> get_variable_assignment_from_new_gadgetlib2(const new_gadgetlib2::Protoboard<Fp> &pb);

} // libsnark

#include <libsnark/new_gadgetlib2/integration.tcc>
#endif // INTEGRATION_HPP_
