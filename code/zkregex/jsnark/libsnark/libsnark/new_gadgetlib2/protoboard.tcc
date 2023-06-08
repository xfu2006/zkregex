/** @file
 *****************************************************************************
 Implementation of Protoboard, a "memory manager" for building arithmetic constraints
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cstdio>

#include <libsnark/new_gadgetlib2/protoboard.hpp>

using ::std::string;
using ::std::cout;
using ::std::endl;

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                       class Protoboard                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
Protoboard<Fp>::Protoboard(const FieldType& fieldType, ParamsCPtr pParams)
    : numInputs_(0), pParams_(pParams), fieldType_(fieldType) {}


template <class Fp>
FElem<Fp>& Protoboard<Fp>::val(const Variable<Fp> &var) {
    FElem<Fp>& retval = assignment_[var];
    GADGETLIB_ASSERT(retval.fieldType() == fieldType_ || retval.fieldType() == AGNOSTIC,
                    GADGETLIB2_FMT("Assigned field element of incorrect field type in Variable<Fp> \"%s\"",
                        var.name().c_str()));
    return retval;
}

template <class Fp>
FElem<Fp> Protoboard<Fp>::val(const LinearCombination<Fp>& lc) const {
    return lc.eval(assignment_);
}

template <class Fp>
void Protoboard<Fp>::setValuesAsBitArray(const VariableArray<Fp>& varArray, const size_t srcValue) {
    GADGETLIB_ASSERT(varArray.size() >= Log2ceil(srcValue),
                 GADGETLIB2_FMT("Variable<Fp> array of size %u too small to hold value %u. Array must be of size "
                     "at least %u", varArray.size(), srcValue, Log2ceil(srcValue)));
    size_t i = 0;
    for(i = 0; i < Log2ceil(srcValue); ++i) {
        val(varArray[i]) = srcValue & (1u<<i) ? 1 : 0 ;
    }
    for(; i < varArray.size(); ++i) {
        val(varArray[i]) = 0 ;
    }
}

template <class Fp>
void Protoboard<Fp>::setDualWordValue(const DualWord<Fp>& dualWord, const size_t srcValue) {
    setMultipackedWordValue(dualWord.multipacked(), srcValue);
    setValuesAsBitArray(dualWord.unpacked(), srcValue);
}

template <class Fp>
void Protoboard<Fp>::setMultipackedWordValue(const MultiPackedWord<Fp>& multipackedWord,
                                         const size_t srcValue) {
    if (fieldType_ == R1P) {
        GADGETLIB_ASSERT(multipackedWord.size() == 1, "Multipacked word size mismatch in R1P");
        val(multipackedWord[0]) = srcValue;
    } else {
        GADGETLIB_FATAL("Unknown protoboard type in Protoboard<Fp>::setMultipackedWordValue");
    }
}

// The following 3 methods are purposely not overloaded to the same name in order to reduce
// programmer error. We want the programmer to explicitly code what type of constraint
// she wants.
template <class Fp>
void Protoboard<Fp>::addRank1Constraint(const LinearCombination<Fp>& a,
                                    const LinearCombination<Fp>& b,
                                    const LinearCombination<Fp>& c,
                                    const ::std::string& name) {
    constraintSystem_.addConstraint(Rank1Constraint<Fp>(a,b,c,name));
}

template <class Fp>
void Protoboard<Fp>::addGeneralConstraint(const Polynomial<Fp>& a,
                                      const Polynomial<Fp>& b,
                                      const ::std::string& name) {
    constraintSystem_.addConstraint(PolynomialConstraint<Fp>(a,b,name));
}

template <class Fp>
void Protoboard<Fp>::addUnaryConstraint(const LinearCombination<Fp>& a, const ::std::string& name) {
    addRank1Constraint(a, 1, 0, name);
}

template <class Fp>
bool Protoboard<Fp>::isSatisfied(const PrintOptions& printOnFail) {
    return constraintSystem_.isSatisfied(assignment_, printOnFail);
}

template <class Fp>
void Protoboard<Fp>::setFlag(const FlagVariable<Fp>& flag, bool newFlagState) {
    val(flag) = newFlagState ? 1 : 0;
}

template <class Fp>
void Protoboard<Fp>::enforceBooleanity(const Variable<Fp>& var) {
    addRank1Constraint(var , var - 1, 0 , GADGETLIB2_FMT("enforceBooleanity(%s)",var.name().c_str()));
}

template <class Fp>
string Protoboard<Fp>::annotation() const {
#   ifdef DEBUG
        string retVal = constraintSystem_.annotation();
        retVal += "Variable<Fp> Assignments:\n";
        for(const auto& assignmentPair : assignment_) {
            const string varName = assignmentPair.first.name();
            const string varAssignedValue = assignmentPair.second.asString();
            retVal +=  varName + ": " + varAssignedValue + "\n";
        }
        return retVal;
#   else // not DEBUG
        return "";
#   endif
}

bool multipackedAndUnpackedValuesDisagree(const bool multipackedEqualsValue,
                                          const bool unpackedEqualsValue) {
    return multipackedEqualsValue != unpackedEqualsValue;
}

void printInformativeNoticeMessage(const bool multipackedEqualsValue,
                                   const bool unpackedEqualsValue) {
    if (multipackedEqualsValue == true && unpackedEqualsValue == false) {
        cout << "NOTE: multipacked value equals expected value but unpacked value does not!"
             << endl;
    } else {
        GADGETLIB_ASSERT(multipackedEqualsValue == false && unpackedEqualsValue == true,
                     "printInformativeNoticeMessage(...) has been called incorrectly");
        cout << "NOTE: unpacked value equals expected value but multipacked value does not!"
             << endl;
    }
}

template <class Fp>
bool Protoboard<Fp>::dualWordAssignmentEqualsValue(const DualWord<Fp>& dualWord,
                                               const size_t expectedValue,
                                               const PrintOptions& printOption) const {
    bool multipackedEqualsValue = multipackedWordAssignmentEqualsValue(dualWord.multipacked(),
                                                                       expectedValue,
                                                                       printOption);
    bool unpackedEqualsValue = unpackedWordAssignmentEqualsValue(dualWord.unpacked(),
                                                                 expectedValue,
                                                                 printOption);
    if (multipackedAndUnpackedValuesDisagree(multipackedEqualsValue, unpackedEqualsValue)) {
        printInformativeNoticeMessage(multipackedEqualsValue, unpackedEqualsValue);
    }
    return multipackedEqualsValue && unpackedEqualsValue;
}

bool expectedToPrintValues(const bool boolValue, const PrintOptions& printOption) {
    return ((boolValue == true && printOption == PrintOptions::DBG_PRINT_IF_TRUE) ||
            (boolValue == false && printOption == PrintOptions::DBG_PRINT_IF_FALSE));
}

template <class Fp>
bool Protoboard<Fp>::multipackedWordAssignmentEqualsValue(const MultiPackedWord<Fp>& multipackedWord,
                                                      const size_t expectedValue,
                                                      const PrintOptions& printOption) const {
    bool retval = true;
    if (fieldType_ == R1P) {
        GADGETLIB_ASSERT(multipackedWord.size() == 1, "R1P multipacked size mismatch");
        if (val(multipackedWord[0]) == expectedValue) {
            retval = true;
        } else {
            retval = false;
        }
        if (expectedToPrintValues(retval, printOption)) {
            cout << "Expected value for multipacked word \"" << multipackedWord.name()
                 << "\" is: " << expectedValue << endl;
            cout << "Actual value is: " << val(multipackedWord[0]) << endl;
        }
    } else {
        GADGETLIB_FATAL("Unknown field type in Protoboard<Fp>::multipackedWordAssignmentEqualsValue(...)");
    }
    return retval;
}

template <class Fp>
bool Protoboard<Fp>::unpackedWordAssignmentEqualsValue(const UnpackedWord<Fp>& unpackedWord,
                                                   const size_t expectedValue,
                                                   const PrintOptions& printOption) const {
    bool retval = true;
    size_t expectedValueCopy = expectedValue;
    for(size_t i = 0; i < unpackedWord.size(); ++i) {
        if (val(unpackedWord[i]) != (expectedValueCopy & 1u)) {
            retval = false;
            break;
        }
        expectedValueCopy >>= 1;
    }
    if (expectedValueCopy != 0) {
        retval = false;
    }
    if (expectedToPrintValues(retval, printOption)) {
        cout << "Expected value for unpacked word \"" << unpackedWord.name()
             << "\" is: " << expectedValue << endl;
        cout << "Actual values are: " << endl;
        for(size_t i = 0; i < unpackedWord.size(); ++i) {
            cout << "bit " << i << ": " << val(unpackedWord[i]) << endl;
        }
    }
    return retval;
}


/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

ProtoboardParams::~ProtoboardParams() {}

} // namespace new_gadgetlib2
