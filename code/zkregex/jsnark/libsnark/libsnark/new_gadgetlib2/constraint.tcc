/** @file
 *****************************************************************************
 Implementation of the Constraint class.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>
#include <set>

#include <libsnark/new_gadgetlib2/constraint.hpp>
#include <libsnark/new_gadgetlib2/variable.hpp>

using ::std::string;
using ::std::vector;
using ::std::set;
using ::std::cout;
using ::std::cerr;
using ::std::endl;
using ::std::shared_ptr;

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    class Constraint                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

#ifdef DEBUG
template <class Fp>
Constraint<Fp>::Constraint(const string& name) : name_(name) {}
#else
template <class Fp>
Constraint<Fp>::Constraint(const string& name) { libff::UNUSED(name); }
#endif

template <class Fp>
string Constraint<Fp>::name() const {
#   ifdef DEBUG
        return name_;
#   else
        return "";
#   endif
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 class Rank1Constraint                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
Rank1Constraint<Fp>::Rank1Constraint(const LinearCombination<Fp> &a,
                               const LinearCombination<Fp> &b,
                               const LinearCombination<Fp> &c,
                               const string& name)
    : Constraint<Fp>(name), a_(a), b_(b), c_(c) {}

template <class Fp>
LinearCombination<Fp> Rank1Constraint<Fp>::a() const {return a_;}
template <class Fp>
LinearCombination<Fp> Rank1Constraint<Fp>::b() const {return b_;}
template <class Fp>
LinearCombination<Fp> Rank1Constraint<Fp>::c() const {return c_;}

template <class Fp>
bool Rank1Constraint<Fp>::isSatisfied(const VariableAssignment<Fp>& assignment,
                                  const PrintOptions& printOnFail) const {
    const FElem<Fp> ares = a_.eval(assignment);
    const FElem<Fp> bres = b_.eval(assignment);
    const FElem<Fp> cres = c_.eval(assignment);
    if (ares*bres != cres) {
#       ifdef DEBUG
        if (printOnFail == PrintOptions::DBG_PRINT_IF_NOT_SATISFIED) {
            cerr << GADGETLIB2_FMT("Constraint named \"%s\" not satisfied. Constraint is:",
                name().c_str()) << endl;
            cerr << annotation() << endl;
            cerr << "Variable assignments are:" << endl;
            const Variable_set<Fp> varSet = getUsedVariables();
            for(const Variable& var : varSet) {
                cerr <<  var.name() << ": " << assignment.at(var).asString() << endl;
            }
            cerr << "a:   " << ares.asString() << endl;
            cerr << "b:   " << bres.asString() << endl;
            cerr << "a*b: " << (ares*bres).asString() << endl;
            cerr << "c:   " << cres.asString() << endl;
        }
#       else
        libff::UNUSED(printOnFail);
#       endif
        return false;
    }
    return true;
}

template <class Fp>
string Rank1Constraint<Fp>::annotation() const {
#   ifndef DEBUG
        return "";
#   endif
    return string("( ") + a_.asString() + " ) * ( " + b_.asString() + " ) = "+ c_.asString();
}

template <class Fp>
const Variable_set<Fp> Rank1Constraint<Fp>::getUsedVariables() const {
    Variable_set<Fp> retSet;
    const Variable_set<Fp> aSet = a_.getUsedVariables();
    retSet.insert(aSet.begin(), aSet.end());
    const Variable_set<Fp> bSet = b_.getUsedVariables();
    retSet.insert(bSet.begin(), bSet.end());
    const Variable_set<Fp> cSet = c_.getUsedVariables();
    retSet.insert(cSet.begin(), cSet.end());
    return retSet;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 class PolynomialConstraint                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
PolynomialConstraint<Fp>::PolynomialConstraint(const Polynomial<Fp>& a, const Polynomial<Fp>& b,
        const string& name) : Constraint<Fp>(name), a_(a), b_(b) {}

template <class Fp>
bool PolynomialConstraint<Fp>::isSatisfied(const VariableAssignment<Fp>& assignment,
                                       const PrintOptions& printOnFail) const {
    const FElem<Fp> aEval = a_.eval(assignment);
    const FElem<Fp> bEval = b_.eval(assignment);
    if (aEval != bEval) {
#       ifdef DEBUG
            if(printOnFail == PrintOptions::DBG_PRINT_IF_NOT_SATISFIED) {
                cerr << GADGETLIB2_FMT("Constraint named \"%s\" not satisfied. Constraint is:",
                    name().c_str()) << endl;
                cerr << annotation() << endl;
				cerr << "Expecting: " << aEval << " == " << bEval << endl;
                cerr << "Variable assignments are:" << endl;
                const Variable_set<Fp> varSet = getUsedVariables();
                for(const Variable& var : varSet) {
                    cerr <<  var.name() << ": " << assignment.at(var).asString() << endl;
                }
            }
#       else
            libff::UNUSED(printOnFail);
#       endif

        return false;
    }
    return true;
}

template <class Fp>
string PolynomialConstraint<Fp>::annotation() const {
#   ifndef DEBUG
        return "";
#   endif
    return a_.asString() + " == " + b_.asString();
}

template <class Fp>
const Variable_set<Fp> PolynomialConstraint<Fp>::getUsedVariables() const {
    Variable_set<Fp> retSet;
    const Variable_set<Fp> aSet = a_.getUsedVariables();
    retSet.insert(aSet.begin(), aSet.end());
    const Variable_set<Fp> bSet = b_.getUsedVariables();
    retSet.insert(bSet.begin(), bSet.end());
    return retSet;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/
template <class Fp>
void ConstraintSystem<Fp>::addConstraint(const Rank1Constraint<Fp>& c) {
    constraintsPtrs_.emplace_back(::std::shared_ptr<Constraint<Fp>>(new Rank1Constraint<Fp>(c)));
}

template <class Fp>
void ConstraintSystem<Fp>::addConstraint(const PolynomialConstraint<Fp>& c) {
    constraintsPtrs_.emplace_back(::std::shared_ptr<Constraint<Fp>>(new PolynomialConstraint<Fp>(c)));
}

template <class Fp>
bool ConstraintSystem<Fp>::isSatisfied(const VariableAssignment<Fp>& assignment,
                                   const PrintOptions& printOnFail) const {
    for(size_t i = 0; i < constraintsPtrs_.size(); ++i) {
        if (!constraintsPtrs_[i]->isSatisfied(assignment, printOnFail)){
            return false;
        }
    }
    return true;
}

template <class Fp>
string ConstraintSystem<Fp>::annotation() const {
    string retVal("\n");
    for(auto i = constraintsPtrs_.begin(); i != constraintsPtrs_.end(); ++i) {
        retVal += (*i)->annotation() + '\n';
    }
    return retVal;
}

template <class Fp>
Variable_set<Fp> ConstraintSystem<Fp>::getUsedVariables() const {
    Variable_set<Fp> retSet;
    for(auto& pConstraint : constraintsPtrs_) {
        const Variable_set<Fp> curSet = pConstraint->getUsedVariables();
        retSet.insert(curSet.begin(), curSet.end());
    }
    return retSet;
}

} // namespace new_gadgetlib2
