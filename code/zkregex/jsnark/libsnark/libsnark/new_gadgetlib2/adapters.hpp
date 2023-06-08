/** @file
 *****************************************************************************
 Declaration of an adapter to POD types for interfacing to SNARKs
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_ADAPTERS_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_ADAPTERS_HPP_

#include <map>
#include <tuple>
#include <utility>

#include <libsnark/new_gadgetlib2/constraint.hpp>
#include <libsnark/new_gadgetlib2/pp.hpp>
#include <libsnark/new_gadgetlib2/protoboard.hpp>
#include <libsnark/new_gadgetlib2/variable.hpp>

using new_gadgetlib2::LinearTerm;
using new_gadgetlib2::LinearCombination;
using new_gadgetlib2::Constraint;
using new_gadgetlib2::ConstraintSystem;
using new_gadgetlib2::VariableAssignment;
using new_gadgetlib2::Protoboard;
using new_gadgetlib2::FElem;


namespace new_gadgetlib2 {

/**
 * This class is a temporary hack for quick integration of Fp constraints with ppsnark. It is the
 * IDDQD of classes and has "god mode" friend access to many of the gadgetlib classes. This will
 * be refactored out in the future. --Shaul
 */
typedef unsigned long GadgetLibAdapter_variable_index_t;
template <class Fp>
//typedef ::std::pair<variable_index_t, Fp_elem_t> linear_term_t;
using GadgetLibAdapter_linear_term_t = ::std::pair<GadgetLibAdapter_variable_index_t, Fp>;

template <class Fp>
//typedef ::std::vector<linear_term_t> sparse_vec_t;
using GadgetLibAdapter_sparse_vec_t = ::std::vector<GadgetLibAdapter_linear_term_t<Fp>>; 

template <class Fp>
//typedef ::std::pair<sparse_vec_t, Fp_elem_t> linear_combination_t;
using GadgetLibAdapter_linear_combination_t = ::std::pair<GadgetLibAdapter_sparse_vec_t<Fp>, Fp>;

template <class Fp>
using GadgetLibAdapter_constraint_t = ::std::tuple<GadgetLibAdapter_linear_combination_t<Fp>, GadgetLibAdapter_linear_combination_t<Fp>, GadgetLibAdapter_linear_combination_t<Fp>>;

template <class Fp>
 //typedef ::std::vector<GadgetLibAdapter_constraint_t<Fp>> constraint_sys_t;
using GadgetLibAdapter_constraint_sys_t = ::std::vector<GadgetLibAdapter_constraint_t<Fp>>;

template <class Fp>
using GadgetLibAdapter_assignment_t = ::std::map<GadgetLibAdapter_variable_index_t, Fp>;

template <class Fp>
using GadgetLibAdapter_protoboard_t= ::std::pair<GadgetLibAdapter_constraint_sys_t<Fp>, GadgetLibAdapter_assignment_t<Fp>>;

template <class Fp>
class GadgetLibAdapter {
public:
	//MOVE UP 
    //typedef ::std::pair<variable_index_t, Fp_elem_t> linear_term_t;
    //typedef ::std::vector<linear_term_t> sparse_vec_t;
    //typedef ::std::pair<sparse_vec_t, Fp_elem_t> linear_combination_t;
    //typedef ::std::tuple<GadgetLibAdapter_linear_combination_t<Fp>,
     //                    GadgetLibAdapter_linear_combination_t<Fp>,
      //                   GadgetLibAdapter_linear_combination_t<Fp>> constraint_t;
    //typedef ::std::vector<GadgetLibAdapter_constraint_t<Fp>> constraint_sys_t;
    //typedef ::std::map<GadgetLibAdapter_variable_index_t, Fp> assignment_t;
    //typedef ::std::pair<GadgetLibAdapter_constraint_sys_t<Fp>, GadgetLibAdapter_assignment_t<Fp>> protoboard_t;

    GadgetLibAdapter() {};

    GadgetLibAdapter_linear_term_t<Fp> convert(const LinearTerm<Fp>& lt) const;
    GadgetLibAdapter_linear_combination_t<Fp> convert(const LinearCombination<Fp>& lc) const;
    GadgetLibAdapter_constraint_t<Fp> convert(const Constraint<Fp>& constraint) const;
    GadgetLibAdapter_constraint_sys_t<Fp> convert(const ConstraintSystem<Fp>& constraint_sys) const;
    GadgetLibAdapter_assignment_t<Fp> convert(const VariableAssignment<Fp>& assignment) const;
    static void resetVariableIndex(); ///< Resets variable index to 0 to make variable indices deterministic.
                                      //TODO: Kill GadgetLibAdapter::resetVariableIndex()
    static size_t getNextFreeIndex(){return Variable<Fp>::nextFreeIndex_;}
    GadgetLibAdapter_protoboard_t<Fp> convert(const Protoboard<Fp>& pb) const;
    Fp convert(FElem<Fp> fElem) const;
    static size_t getVariableIndex(const Variable<Fp>& v){return v.index_;}
};

template <class Fp>
//typedef ::std::pair<sparse_vec_t, Fp_elem_t> linear_combination_t;
using GadgetLibAdapter_linear_combination_t = ::std::pair<GadgetLibAdapter_sparse_vec_t<Fp>, Fp>;

template <class Fp>
//bool operator==(const GadgetLibAdapter<Fp>::linear_combination_t& lhs,
//               const GadgetLibAdapter<Fp>::linear_term_t& rhs);
bool operator==(const GadgetLibAdapter_linear_combination_t<Fp>& lhs,
               const GadgetLibAdapter_linear_term_t<Fp>& rhs);


}

//Added by CorrAuthor to avoid instantiation problem of template functions
#include <libsnark/new_gadgetlib2/adapters.tcc>
//Added by CorrAuthor to avoid instantiation problem of template functions --
#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_ADAPTERS_HPP_
