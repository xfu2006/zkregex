/** @file
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <libsnark/new_gadgetlib2/adapters.hpp>
#include <libsnark/new_gadgetlib2/integration.hpp>

namespace libsnark {

template <class Fp>
linear_combination<Fp> convert_new_gadgetlib2_linear_combination(const new_gadgetlib2::GadgetLibAdapter_linear_combination_t<Fp> &lc)
{
    //typedef libff::Fr<libff::default_ec_pp> FieldT;
    //typedef new_gadgetlib2::GadgetLibAdapter GLA;

    linear_combination<Fp> result = lc.second * variable<Fp>(0);
    for (const new_gadgetlib2::GadgetLibAdapter_linear_term_t<Fp> &lt : lc.first)
    {
        result = result + lt.second * variable<Fp>(lt.first+1);
    }

    return result;
}

template <class Fp>
r1cs_constraint_system<Fp> get_constraint_system_from_new_gadgetlib2(const new_gadgetlib2::Protoboard<Fp> &pb)
{

    r1cs_constraint_system<Fp> result;
    const new_gadgetlib2::GadgetLibAdapter<Fp> adapter;

    new_gadgetlib2::GadgetLibAdapter_protoboard_t<Fp> converted_pb = adapter.convert(pb);
    for (const new_gadgetlib2::GadgetLibAdapter_constraint_t<Fp> &constr : converted_pb.first)
    {
        result.constraints.emplace_back(r1cs_constraint<Fp>(convert_new_gadgetlib2_linear_combination(std::get<0>(constr)),
                                                                convert_new_gadgetlib2_linear_combination(std::get<1>(constr)),
                                                                convert_new_gadgetlib2_linear_combination(std::get<2>(constr))));
    }
    //The number of variables is the highest index created.
    //TODO: If there are multiple protoboards, or variables not assigned to a protoboard, then getNextFreeIndex() is *not* the number of variables! See also in get_variable_assignment_from_new_gadgetlib2.
    const size_t num_variables = new_gadgetlib2::GadgetLibAdapter<Fp>::getNextFreeIndex();
    result.primary_input_size = pb.numInputs();
    result.auxiliary_input_size = num_variables - pb.numInputs();
    return result;
}

template <class Fp>
r1cs_variable_assignment<Fp> get_variable_assignment_from_new_gadgetlib2(const new_gadgetlib2::Protoboard<Fp> &pb)
{
    typedef Fp FieldT; //by CorrAuthor: here Fp is FieldT is mixed to reduce
		//the work needed for syntax fix
    typedef new_gadgetlib2::GadgetLibAdapter<Fp> GLA;

    //The number of variables is the highest index created. This is also the required size for the assignment vector.
    //TODO: If there are multiple protoboards, or variables not assigned to a protoboard, then getNextFreeIndex() is *not* the number of variables! See also in get_constraint_system_from_new_gadgetlib2.
    const size_t num_vars = GLA::getNextFreeIndex();
    const GLA adapter;
    r1cs_variable_assignment<FieldT> result(num_vars, FieldT::zero());
    VariableAssignment<FieldT> assignment = pb.assignment();

    //Go over all assigned values of the protoboard, from every variable-value pair, put the value in the variable.index place of the new assignment.
    //for(auto VariableAssignment<Fp>::iterator iter = assignment.begin(); iter != assignment.end(); ++iter){
    for(auto iter = assignment.begin(); iter != assignment.end(); ++iter){
    	result[GLA::getVariableIndex(iter->first)] = adapter.convert(iter->second);
    }

    return result;
}

}
