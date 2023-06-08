/** @file
 *****************************************************************************
 Implementation of the low level objects needed for field arithmetization.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <climits>
#include <iostream>
#include <set>
#include <stdexcept>
#include <vector>

#include <libsnark/new_gadgetlib2/infrastructure.hpp>
#include <libsnark/new_gadgetlib2/pp.hpp>
#include <libsnark/new_gadgetlib2/variable.hpp>

using ::std::string;
using ::std::stringstream;
using ::std::set;
using ::std::vector;
using ::std::shared_ptr;
using ::std::cout;
using ::std::endl;
using ::std::dynamic_pointer_cast;

namespace new_gadgetlib2 {

// Optimization: In the future we may want to port most of the member functions  from this file to
// the .hpp files in order to allow for compiler inlining. As inlining has tradeoffs this should be
// profiled before doing so.

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      class FElem<Fp>                           ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
FElem<Fp>::FElem(const FElemInterface<Fp>& elem) :
		elem_(elem.clone()) {
}
template <class Fp>
FElem<Fp>::FElem() :
		elem_(new FConst<Fp>(0)) {
}
template <class Fp>
FElem<Fp>::FElem(const long n) :
		elem_(new FConst<Fp>(n)) {
}
template <class Fp>
FElem<Fp>::FElem(const int i) :
		elem_(new FConst<Fp>(i)) {
}
template <class Fp>
FElem<Fp>::FElem(const size_t n) :
		elem_(new FConst<Fp>(n)) {
}
template <class Fp>
FElem<Fp>::FElem(const Fp& elem) :
		elem_(new R1P_Elem<Fp>(elem)) {
}
template <class Fp>
FElem<Fp>::FElem(const FElem<Fp>& src) :
		elem_(src.elem_->clone()) {
}

template <class Fp>
FElem<Fp>& FElem<Fp>::operator=(const FElem<Fp>& other) {
	if (fieldType() == other.fieldType() || fieldType() == AGNOSTIC) {
		elem_ = other.elem_->clone();
	} else if (other.fieldType() != AGNOSTIC) {
		GADGETLIB_FATAL("Attempted to assign field element of incorrect type");
	} else {
		*elem_ = dynamic_cast<FConst<Fp>*>(other.elem_.get())->asLong();
	}
	return *this;
}

template <class Fp>
FElem<Fp>& FElem<Fp>::operator=(FElem<Fp>&& other) {
	if (fieldType() == other.fieldType() || fieldType() == AGNOSTIC) {
		elem_ = ::std::move(other.elem_);
	} else if (other.elem_->fieldType() != AGNOSTIC) {
		GADGETLIB_FATAL(
				"Attempted to move assign field element of incorrect type");
	} else {
		*elem_ = dynamic_cast<FConst<Fp>*>(other.elem_.get())->asLong();
	}
	return *this;
}

bool fieldMustBePromotedForArithmetic(const FieldType& lhsField,
		const FieldType& rhsField) {
	if (lhsField == rhsField)
		return false;
	if (rhsField == AGNOSTIC)
		return false;
	return true;
}

template <class Fp>
void FElem<Fp>::promoteToFieldType(FieldType type) {
	if (!fieldMustBePromotedForArithmetic(this->fieldType(), type)) {
		return;
	}
	if (type == R1P) {
		const FConst<Fp>* fConst = dynamic_cast<FConst<Fp>*>(elem_.get());
		GADGETLIB_ASSERT(fConst != NULL,
				"Cannot convert between specialized field types.");
		elem_.reset(new R1P_Elem<Fp>(fConst->asLong()));
	} else {
		GADGETLIB_FATAL("Attempted to promote to unknown field type");
	}
}

template <class Fp>
FElem<Fp>& FElem<Fp>::operator*=(const FElem<Fp>& other) {
	promoteToFieldType(other.fieldType());
	*elem_ *= *other.elem_;
	return *this;
}

template <class Fp>
FElem<Fp>& FElem<Fp>::operator+=(const FElem<Fp>& other) {
	promoteToFieldType(other.fieldType());
	*elem_ += *other.elem_;
	return *this;
}

template <class Fp>
FElem<Fp>& FElem<Fp>::operator-=(const FElem<Fp>& other) {
	promoteToFieldType(other.fieldType());
	*elem_ -= *other.elem_;
	return *this;
}

template <class Fp>
FElem<Fp> FElem<Fp>::inverse(const FieldType& fieldType) {
	promoteToFieldType(fieldType);
	return FElem<Fp>(*(elem_->inverse()));
}

template <class Fp>
int FElem<Fp>::getBit(unsigned int i, const FieldType& fieldType) {
    promoteToFieldType(fieldType);
    if (this->fieldType() == fieldType) {
        return elem_->getBit(i);
    } else {
        GADGETLIB_FATAL("Attempted to extract bits from incompatible field type.");
    }
}

template <class Fp>
FElem<Fp> power(const FElem<Fp>& base, long exponent) { // TODO .cpp
	FElem<Fp> retval(base);
	retval.elem_->power(exponent);
	return retval;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      class FConst                          ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
FConst<Fp>& FConst<Fp>::operator+=(const FElemInterface<Fp>& other) {
	contents_ += dynamic_cast<const FConst<Fp>&>(other).contents_;
	return *this;
}

template <class Fp>
FConst<Fp>& FConst<Fp>::operator-=(const FElemInterface<Fp>& other) {
	contents_ -= dynamic_cast<const FConst<Fp>&>(other).contents_;
	return *this;
}

template <class Fp>
FConst<Fp>& FConst<Fp>::operator*=(const FElemInterface<Fp>& other) {
	contents_ *= dynamic_cast<const FConst<Fp>&>(other).contents_;
	return *this;
}

template <class Fp>
FElemInterfacePtr<Fp> FConst<Fp>::inverse() const {
	GADGETLIB_FATAL("Attempted to invert an FConst element.");
}

template <class Fp>
FElemInterface<Fp>& FConst<Fp>::power(long exponent) {
	contents_ = 0.5 + ::std::pow(double(contents_), double(exponent));
	return *this;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     class R1P_Elem<Fp>                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
R1P_Elem<Fp>& R1P_Elem<Fp>::operator+=(const FElemInterface<Fp>& other) {
	if (other.fieldType() == R1P) {
		elem_ += dynamic_cast<const R1P_Elem<Fp>&>(other).elem_;
	} else if (other.fieldType() == AGNOSTIC) {
		elem_ += dynamic_cast<const FConst<Fp>&>(other).asLong();
	} else {
		GADGETLIB_FATAL("Attempted to add incompatible type to R1P_Elem<Fp>.");
	}
	return *this;
}

template <class Fp>
R1P_Elem<Fp>& R1P_Elem<Fp>::operator-=(const FElemInterface<Fp>& other) {
	if (other.fieldType() == R1P) {
		elem_ -= dynamic_cast<const R1P_Elem<Fp>&>(other).elem_;
	} else if (other.fieldType() == AGNOSTIC) {
		elem_ -= dynamic_cast<const FConst<Fp>&>(other).asLong();
	} else {
		GADGETLIB_FATAL("Attempted to add incompatible type to R1P_Elem<Fp>.");
	}
	return *this;
}

template <class Fp>
R1P_Elem<Fp>& R1P_Elem<Fp>::operator*=(const FElemInterface<Fp>& other) {
	if (other.fieldType() == R1P) {
		elem_ *= dynamic_cast<const R1P_Elem<Fp>&>(other).elem_;
	} else if (other.fieldType() == AGNOSTIC) {
		elem_ *= dynamic_cast<const FConst<Fp>&>(other).asLong();
	} else {
		GADGETLIB_FATAL("Attempted to add incompatible type to R1P_Elem<Fp>.");
	}
	return *this;
}

template <class Fp>
bool R1P_Elem<Fp>::operator==(const FElemInterface<Fp>& other) const {
	const R1P_Elem<Fp>* pOther = dynamic_cast<const R1P_Elem<Fp>*>(&other);
	if (pOther) {
		return elem_ == pOther->elem_;
	}
	const FConst<Fp>* pConst = dynamic_cast<const FConst<Fp>*>(&other);
	if (pConst) {
		return *this == *pConst;
	}
	GADGETLIB_FATAL("Attempted to Compare R1P_Elem<Fp> with incompatible type.");
}

template <class Fp>
FElemInterfacePtr<Fp> R1P_Elem<Fp>::inverse() const {
	return FElemInterfacePtr<Fp>(new R1P_Elem<Fp>(elem_.inverse()));
}

template <class Fp>
long R1P_Elem<Fp>::asLong() const {
	//GADGETLIB_ASSERT(elem_.as_ulong() <= LONG_MAX, "long overflow occured.");
	return long(elem_.as_ulong());
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    class Variable                          ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
VarIndex_t Variable<Fp>::nextFreeIndex_ = 0;

#ifdef DEBUG
template <class Fp>
Variable<Fp>::Variable(const string& name) : index_(nextFreeIndex_++), name_(name) {
	GADGETLIB_ASSERT(nextFreeIndex_ > 0, GADGETLIB2_FMT("Variable index overflow has occured, maximum number of "
					"Variables is %lu", ULONG_MAX));
}
#else
template <class Fp>
Variable<Fp>::Variable(const string& name) : index_(nextFreeIndex_++) {
    libff::UNUSED(name);
    GADGETLIB_ASSERT(nextFreeIndex_ > 0, GADGETLIB2_FMT("Variable index overflow has occured, maximum number of "
                                         "Variables is %lu", ULONG_MAX));
}
#endif

template <class Fp>
Variable<Fp>::~Variable() {
}
;

template <class Fp>
string Variable<Fp>::name() const {
#    ifdef DEBUG
	return name_;
#    else
	return "";
#    endif
}

template <class Fp>
FElem<Fp> Variable<Fp>::eval(const VariableAssignment<Fp>& assignment) const {
	try {
		return assignment.at(*this);
	} catch (::std::out_of_range) {
		GADGETLIB_FATAL(
				GADGETLIB2_FMT(
						"Attempted to evaluate unassigned Variable \"%s\", idx:%lu",
						name().c_str(), index_));
	}
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 class VariableArray<Fp>                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

#ifdef DEBUG
VariableArray<Fp>::VariableArray(const string& name) : VariableArrayContents(), name_(name) {}
VariableArray<Fp>::VariableArray(const int size, const ::std::string& name) : VariableArrayContents() {
    for (int i = 0; i < size; ++i) {
        push_back(Variable(GADGETLIB2_FMT("%s[%d]", name.c_str(), i)));
    }
}

VariableArray<Fp>::VariableArray(const size_t size, const ::std::string& name) : VariableArrayContents() {
    for (size_t i = 0; i < size; ++i) {
        push_back(Variable(GADGETLIB2_FMT("%s[%d]", name.c_str(), i)));
    }
}
::std::string VariableArray<Fp>::name() const {
	return name_;
}

#else
template <class Fp>
::std::string VariableArray<Fp>::name() const {
	return "";
}


template <class Fp>
VariableArray<Fp>::VariableArray(const string& name) : VariableArrayContents<Fp>() { libff::UNUSED(name); }
template <class Fp>
VariableArray<Fp>::VariableArray(const int size, const ::std::string& name)
    : VariableArrayContents<Fp>(size) { libff::UNUSED(name); }
template <class Fp>
VariableArray<Fp>::VariableArray(const size_t size, const ::std::string& name)
    : VariableArrayContents<Fp>(size) { libff::UNUSED(name); }
#endif

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 Custom Variable classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
MultiPackedWord<Fp>::MultiPackedWord(const FieldType& fieldType) :
		VariableArray<Fp>(), numBits_(0), fieldType_(fieldType) {
}

template <class Fp>
MultiPackedWord<Fp>::MultiPackedWord(const size_t numBits,
		const FieldType& fieldType, const ::std::string& name) :
		VariableArray<Fp>(), numBits_(numBits), fieldType_(fieldType) {
	size_t packedSize = getMultipackedSize();
	VariableArray<Fp> varArray(packedSize, name);
	VariableArray<Fp>::swap(varArray);
}

template <class Fp>
void MultiPackedWord<Fp>::resize(const size_t numBits) {
	numBits_ = numBits;
	size_t packedSize = getMultipackedSize();
	VariableArray<Fp>::resize(packedSize);
}

template <class Fp>
size_t MultiPackedWord<Fp>::getMultipackedSize() const {
	size_t packedSize = 0;
	if (fieldType_ == R1P) {
		packedSize = 1; // TODO add assertion that numBits can fit in the field characteristic
	} else {
		GADGETLIB_FATAL("Unknown field type for packed variable.");
	}
	return packedSize;
}

template <class Fp>
DualWord<Fp>::DualWord(const size_t numBits, const FieldType& fieldType,
		const ::std::string& name) :
		multipacked_(numBits, fieldType, name + "_p"), unpacked_(numBits,
				name + "_u") {
}

template <class Fp>
DualWord<Fp>::DualWord(const MultiPackedWord<Fp>& multipacked,
		const UnpackedWord<Fp>& unpacked) :
		multipacked_(multipacked), unpacked_(unpacked) {
}

template <class Fp>
void DualWord<Fp>::resize(size_t newSize) {
	multipacked_.resize(newSize);
	unpacked_.resize(newSize);
}

template <class Fp>
DualWordArray<Fp>::DualWordArray(const FieldType& fieldType) :
		multipackedContents_(0, MultiPackedWord<Fp>(fieldType)), unpackedContents_(
				0), numElements_(0) {
}

template <class Fp>
DualWordArray<Fp>::DualWordArray(const MultiPackedWordArray<Fp>& multipackedContents, // TODO delete, for dev
		const UnpackedWordArray<Fp>& unpackedContents) :
		multipackedContents_(multipackedContents), unpackedContents_(
				unpackedContents), numElements_(multipackedContents_.size()) {
	GADGETLIB_ASSERT(multipackedContents_.size() == numElements_,
			"Dual Variable multipacked contents size mismatch");
	GADGETLIB_ASSERT(unpackedContents_.size() == numElements_,
			"Dual Variable packed contents size mismatch");
}

template <class Fp>
MultiPackedWordArray<Fp> DualWordArray<Fp>::multipacked() const {
	return multipackedContents_;
}
template <class Fp>
UnpackedWordArray<Fp> DualWordArray<Fp>::unpacked() const {
	return unpackedContents_;
}
template <class Fp>
PackedWordArray<Fp> DualWordArray<Fp>::packed() const {
	GADGETLIB_ASSERT(numElements_ == multipackedContents_.size(),
			"multipacked contents size mismatch")
	PackedWordArray<Fp> retval(numElements_);
	for (size_t i = 0; i < numElements_; ++i) {
		const auto element = multipackedContents_[i];
		GADGETLIB_ASSERT(element.size() == 1,
				"Cannot convert from multipacked to packed");
		retval[i] = element[0];
	}
	return retval;
}

template <class Fp>
void DualWordArray<Fp>::push_back(const DualWord<Fp>& dualWord) {
	multipackedContents_.push_back(dualWord.multipacked());
	unpackedContents_.push_back(dualWord.unpacked());
	++numElements_;
}

template <class Fp>
DualWord<Fp> DualWordArray<Fp>::at(size_t i) const {
	//const MultiPackedWord multipackedRep = multipacked()[i];
	//const UnpackedWord unpackedRep = unpacked()[i];
	//const DualWord<Fp> retval(multipackedRep, unpackedRep);
	//return retval;
	return DualWord<Fp>(multipacked()[i], unpacked()[i]);
}

template <class Fp>
size_t DualWordArray<Fp>::size() const {
	GADGETLIB_ASSERT(multipackedContents_.size() == numElements_,
			"Dual Variable multipacked contents size mismatch");
	GADGETLIB_ASSERT(unpackedContents_.size() == numElements_,
			"Dual Variable packed contents size mismatch");
	return numElements_;
}

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    class LinearTerm                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
::std::string LinearTerm<Fp>::asString() const {
	if (coeff_ == 1) {
		return variable_.name();
	} else if (coeff_ == -1) {
		return GADGETLIB2_FMT("-1 * %s", variable_.name().c_str());
	} else if (coeff_ == 0) {
		return GADGETLIB2_FMT("0 * %s", variable_.name().c_str());
	} else {
		return GADGETLIB2_FMT("%s * %s", coeff_.asString().c_str(),
				variable_.name().c_str());
	}
}

template <class Fp>
FElem<Fp> LinearTerm<Fp>::eval(const VariableAssignment<Fp>& assignment) const {
	return FElem<Fp>(coeff_) *= variable_.eval(assignment);
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  class LinearCombination<Fp>                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
LinearCombination<Fp>& LinearCombination<Fp>::operator+=(
		const LinearCombination<Fp>& other) {

	// jSNARK-edit: This method is modified in order to reduce memory consumption when the same variable is
	// being added to a linear combination object multiple times.
	// This can be helpful for some of the circuits produced by the Pinocchio compiler in some cases.

	if (indexMap_.size() == 0) {
		linearTerms_.insert(linearTerms_.end(), other.linearTerms_.cbegin(),
				other.linearTerms_.cend());
		constant_ += other.constant_;
	} else {
		for (const LinearTerm<Fp>& lt : other.linearTerms_) {
			if (indexMap_.find(lt.variable().getIndex()) != indexMap_.end()) {
				linearTerms_[indexMap_[lt.variable().getIndex()]] += lt.coeff();
			} else {
				linearTerms_.push_back(lt);
				int k = indexMap_.size();
				indexMap_[lt.variable().getIndex()] = k;
			}
		}
		constant_ += other.constant_;
	}

	// heuristic threshold
	if (linearTerms_.size() > 10 && indexMap_.size() == 0) {
		int i = 0;
		::std::vector<LinearTerm<Fp>> newVec;
		typename ::std::vector<LinearTerm<Fp>>::iterator lt = (linearTerms_.begin());
		while (lt != linearTerms_.end()) {

			if (indexMap_.find(lt->variable().getIndex()) != indexMap_.end()) {
				newVec[indexMap_[lt->variable().getIndex()]] += lt->coeff();
			} else {
				newVec.push_back(*lt);
				indexMap_[lt->variable().getIndex()] = i++;

			}
			++lt;
		}
		linearTerms_ = newVec;
	}
	return *this;
}

template <class Fp>
LinearCombination<Fp>& LinearCombination<Fp>::operator-=(
		const LinearCombination<Fp>& other) {

	// jSNARK-edit: This method is rewritten in order to reduce memory consumption when the same variable is
	// being added to a linear combination object multiple times.
	// This can be helpful for some of the circuits produced by the Pinocchio compiler in some cases.
	if (indexMap_.size() == 0) {
		for (const LinearTerm<Fp>& lt : other.linearTerms_) {
			linearTerms_.push_back(-lt);
		}
		constant_ -= other.constant_;
	} else {
		for (const LinearTerm<Fp>& lt : other.linearTerms_) {
			if (indexMap_.find(lt.variable().getIndex()) != indexMap_.end()) {
				linearTerms_[indexMap_[lt.variable().getIndex()]] -= lt.coeff();
			} else {
				linearTerms_.push_back(-lt);
				int k = indexMap_.size();
				indexMap_[lt.variable().getIndex()] = k;
			}
		}
		constant_ -= other.constant_;
	}

	// heuristic threshold
	if (linearTerms_.size() > 10 && indexMap_.size() == 0) {
		int i = 0;
		::std::vector<LinearTerm<Fp>> newVec;
		typename ::std::vector<LinearTerm<Fp>>::iterator lt = (linearTerms_.begin());

		while (lt != linearTerms_.end()) {

			if (indexMap_.find(lt->variable().getIndex()) != indexMap_.end()) {
				newVec[indexMap_[lt->variable().getIndex()]] += lt->coeff();
			} else {
				newVec.push_back(*lt);
				indexMap_[lt->variable().getIndex()] = i++;
			}
			++lt;
		}
		linearTerms_ = newVec;
	}

	return *this;

}

template <class Fp>
LinearCombination<Fp>& LinearCombination<Fp>::operator*=(const FElem<Fp>& other) {
	constant_ *= other;
	for (LinearTerm<Fp>& lt : linearTerms_) {
		lt *= other;
	}
	return *this;
}

template <class Fp>
FElem<Fp> LinearCombination<Fp>::eval(const VariableAssignment<Fp>& assignment) const {
	FElem<Fp> evaluation = constant_;
	for (const LinearTerm<Fp>& lt : linearTerms_) {
		evaluation += lt.eval(assignment);
	}
	return evaluation;
}

template <class Fp>
::std::string LinearCombination<Fp>::asString() const {
#ifdef DEBUG
	::std::string retval;
	auto it = linearTerms_.begin();
	if (it == linearTerms_.end()) {
		return constant_.asString();
	} else {
		retval += it->asString();
	}
	for(++it; it != linearTerms_.end(); ++it) {
		retval += " + " + it->asString();
	}
	if (constant_ != 0) {
		retval += " + " + constant_.asString();
	}
	return retval;
#else // ifdef DEBUG
	return "";
#endif // ifdef DEBUG
}

template <class Fp>
const Variable_set<Fp> LinearCombination<Fp>::getUsedVariables() const {
	Variable_set<Fp> retSet;
	for (const LinearTerm<Fp>& lt : linearTerms_) {
		retSet.insert(lt.variable());
	}
	return retSet;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

template <class Fp>
LinearCombination<Fp> sum(const VariableArray<Fp>& inputs) {
	LinearCombination<Fp> retval(0);
	for (const Variable<Fp>& var : inputs) {
		retval += var;
	}
	return retval;
}

template <class Fp>
LinearCombination<Fp> negate(const LinearCombination<Fp>& lc) {
	return (1 - lc);
}

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        class Monomial<Fp>                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
Monomial<Fp>::Monomial(const LinearTerm<Fp>& linearTerm) :
		coeff_(linearTerm.coeff_), variables_() {
	variables_.insert(linearTerm.variable_);
}

template <class Fp>
FElem<Fp> Monomial<Fp>::eval(const VariableAssignment<Fp>& assignment) const {
	FElem<Fp> retval = coeff_;
	for (const Variable<Fp>& var : variables_) {
		retval *= var.eval(assignment);
	}
	return retval;
}

template <class Fp>
const Variable_set<Fp> Monomial<Fp>::getUsedVariables() const {
	return Variable_set<Fp>(variables_.begin(), variables_.end());
}

template <class Fp>
const FElem<Fp> Monomial<Fp>::getCoefficient() const {
	return coeff_;
}

template <class Fp>
::std::string Monomial<Fp>::asString() const {
#ifdef DEBUG
	if (variables_.size() == 0) {
		return coeff_.asString();
	}
	string retval;
	if (coeff_ != 1) {
		retval += coeff_.asString() + "*";
	}
	auto iter = variables_.begin();
	retval += iter->name();
	for(++iter; iter != variables_.end(); ++iter) {
		retval += "*" + iter->name();
	}
	return retval;
#else // ifdef DEBUG
	return "";
#endif // ifdef DEBUG
}

template <class Fp>
Monomial<Fp> Monomial<Fp>::operator-() const {
	Monomial<Fp> retval = *this;
	retval.coeff_ = -retval.coeff_;
	return retval;
}

template <class Fp>
Monomial<Fp>& Monomial<Fp>::operator*=(const Monomial<Fp>& other) {
	coeff_ *= other.coeff_;
	variables_.insert(other.variables_.begin(), other.variables_.end());
	return *this;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      class Polynomial<Fp>                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
Polynomial<Fp>::Polynomial(const LinearCombination<Fp>& linearCombination) :
		monomials_(), constant_(linearCombination.constant_) {
	for (const LinearTerm<Fp>& linearTerm : linearCombination.linearTerms_) {
		monomials_.push_back(Monomial<Fp>(linearTerm));
	}
}

template <class Fp>
FElem<Fp> Polynomial<Fp>::eval(const VariableAssignment<Fp>& assignment) const {
	FElem<Fp> retval = constant_;
	for (const Monomial<Fp>& monomial : monomials_) {
		retval += monomial.eval(assignment);
	}
	return retval;
}

template <class Fp>
const Variable_set<Fp> Polynomial<Fp>::getUsedVariables() const {
	Variable_set<Fp> retset;
	for (const Monomial<Fp>& monomial : monomials_) {
		const Variable_set<Fp> curSet = monomial.getUsedVariables();
		retset.insert(curSet.begin(), curSet.end());
	}
	return retset;
}

template <class Fp>
const vector<Monomial<Fp>>& Polynomial<Fp>::getMonomials() const {
	return monomials_;
}

template <class Fp>
const FElem<Fp> Polynomial<Fp>::getConstant() const {
	return constant_;
}

template <class Fp>
::std::string Polynomial<Fp>::asString() const {
#   ifndef DEBUG
	return "";
#   endif
	if (monomials_.size() == 0) {
		return constant_.asString();
	}
	string retval;
	auto iter = monomials_.begin();
	retval += iter->asString();
	for (++iter; iter != monomials_.end(); ++iter) {
		retval += " + " + iter->asString();
	}
	if (constant_ != 0) {
		retval += " + " + constant_.asString();
	}
	return retval;
}

template <class Fp>
Polynomial<Fp>& Polynomial<Fp>::operator+=(const Polynomial<Fp>& other) {
	constant_ += other.constant_;
	monomials_.insert(monomials_.end(), other.monomials_.begin(),
			other.monomials_.end());
	return *this;
}

template <class Fp>
Polynomial<Fp>& Polynomial<Fp>::operator*=(const Polynomial<Fp>& other) {
	vector<Monomial<Fp>> newMonomials;
	for (const Monomial<Fp>& thisMonomial : monomials_) {
		for (const Monomial<Fp>& otherMonomial : other.monomials_) {
			newMonomials.push_back(thisMonomial * otherMonomial);
		}
		newMonomials.push_back(thisMonomial * other.constant_);
	}
	for (const Monomial<Fp>& otherMonomial : other.monomials_) {
		newMonomials.push_back(otherMonomial * this->constant_);
	}
	constant_ *= other.constant_;
	monomials_ = ::std::move(newMonomials);
	return *this;
}

template <class Fp>
Polynomial<Fp>& Polynomial<Fp>::operator-=(const Polynomial<Fp>& other) {
	constant_ -= other.constant_;
	for (const Monomial<Fp>& otherMonomial : other.monomials_) {
		monomials_.push_back(-otherMonomial);
	}
	return *this;
}

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

} // namespace new_gadgetlib2
