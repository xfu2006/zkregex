/** @file
 *****************************************************************************
 Implementation of an adapter for interfacing to SNARKs.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

//#include <libsnark/new_gadgetlib2/adapters.hpp>

using new_gadgetlib2::Variable;
using new_gadgetlib2::Rank1Constraint;

namespace new_gadgetlib2 {


template <class Fp>
GadgetLibAdapter_linear_term_t<Fp> GadgetLibAdapter<Fp>::convert(const LinearTerm<Fp>& lt) const {
    const GadgetLibAdapter_variable_index_t var = lt.variable_.index_;
    const Fp coeff = convert(lt.coeff_);
    return{ var, coeff };
}

template <class Fp>
GadgetLibAdapter_linear_combination_t<Fp> GadgetLibAdapter<Fp>::convert(const LinearCombination<Fp>& lc) const {
    GadgetLibAdapter_sparse_vec_t<Fp> sparse_vec;
    sparse_vec.reserve(lc.linearTerms_.size());
    for (auto lt : lc.linearTerms_) {
        sparse_vec.emplace_back(convert(lt));
    }
    const Fp offset = convert(lc.constant_);
    return{ sparse_vec, offset };
}

template <class Fp>
GadgetLibAdapter_constraint_t<Fp> GadgetLibAdapter<Fp>::convert(const Constraint<Fp>& constraint) const {
    const auto rank1_constraint = dynamic_cast<const Rank1Constraint<Fp>&>(constraint);
    return GadgetLibAdapter_constraint_t<Fp>(convert(rank1_constraint.a()),
        convert(rank1_constraint.b()),
        convert(rank1_constraint.c()));
}

template <class Fp>
GadgetLibAdapter_constraint_sys_t<Fp> GadgetLibAdapter<Fp>::convert(const ConstraintSystem<Fp>& constraint_sys) const {
    GadgetLibAdapter_constraint_sys_t<Fp> retval;
    retval.reserve(constraint_sys.constraintsPtrs_.size());
    for (auto constraintPtr : constraint_sys.constraintsPtrs_) {
        retval.emplace_back(convert(*constraintPtr));
    }
    return retval;
}

template <class Fp>
GadgetLibAdapter_assignment_t<Fp> GadgetLibAdapter<Fp>::convert(const VariableAssignment<Fp>& assignment) const {
    GadgetLibAdapter_assignment_t<Fp> retval;
    for (const auto assignmentPair : assignment) {
        const GadgetLibAdapter_variable_index_t var = assignmentPair.first.index_;
        const Fp elem = convert(assignmentPair.second);
        retval[var] = elem;
    }
    return retval;
}

template <class Fp>
void GadgetLibAdapter<Fp>::resetVariableIndex() { // This is a hack, used for testing
    Variable<Fp>::nextFreeIndex_ = 0;
}

/***TODO: Remove reliance of GadgetLibAdapter conversion on global variable indices, and the resulting limit of single protoboard instance at a time.
This limitation is to prevent a logic bug that may occur if the variables used are given different indices in different generations of the same constraint system.
The indices are assigned on the Variable constructor, using the global variable nextFreeIndex. Thus, creating two protoboards in the same program may cause
unexpected behavior when converting.
Moreover, the bug will create more variables than needed in the converted system, e.g. if variables 0,1,3,4 were used in the new_gadgetlib2
generated system, then the conversion will create a new r1cs system with variables 0,1,2,3,4 and assign variable 2 the value zero
(when converting the assignment).
Everything should be fixed soon.
If you are sure you know what you are doing, you can comment out the ASSERT line.
*/
template <class Fp>
GadgetLibAdapter_protoboard_t<Fp> GadgetLibAdapter<Fp>::convert(const Protoboard<Fp>& pb) const {
	//GADGETLIB_ASSERT(pb.numVars()==getNextFreeIndex(), "Some Variables were created and not used, or, more than one protoboard was used.");
    return GadgetLibAdapter_protoboard_t<Fp>(convert(pb.constraintSystem()), convert(pb.assignment()));
}

template <class Fp>
Fp GadgetLibAdapter<Fp>::convert(FElem<Fp> fElem) const {
    using new_gadgetlib2::R1P_Elem;
    fElem.promoteToFieldType(new_gadgetlib2::R1P); // convert fElem from FConst to R1P_Elem
    const R1P_Elem<Fp>* pR1P = dynamic_cast<R1P_Elem<Fp>*>(fElem.elem_.get());
    return pR1P->elem_;
}

template <class Fp>
bool operator==(const GadgetLibAdapter_linear_combination_t<Fp>& lhs,
    const GadgetLibAdapter_linear_term_t<Fp>& rhs) {
    return lhs.first.size() == 1 &&
        lhs.first.at(0) == rhs &&
        lhs.second == Fp(0);
}

}
