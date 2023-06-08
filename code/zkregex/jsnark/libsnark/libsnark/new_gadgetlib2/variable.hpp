/** @file
 *****************************************************************************
 Declaration of the low level objects needed for field arithmetization.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLE_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLE_HPP_

#include <cstddef>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <libsnark/new_gadgetlib2/infrastructure.hpp>
#include <libsnark/new_gadgetlib2/pp.hpp>

namespace new_gadgetlib2 {
template <class Fp>
class GadgetLibAdapter;

// Forward declarations
template <class Fp>
class Protoboard;
template <class Fp>
class FElemInterface;
template <class Fp>
class FConst;
template <class Fp>
class Variable;
template <class Fp>
class FElem;
template <class Fp>
class VariableArray;
template <class Fp>
class Polynomial;
template <class Fp>
class Monomial;

typedef enum {R1P, AGNOSTIC} FieldType;

template <class Fp>
using VariablePtr = ::std::shared_ptr<Variable<Fp>>;
template <class Fp>
using VariableArrayPtr = ::std::shared_ptr<VariableArray<Fp>>;
template <class Fp>
using FElemInterfacePtr = ::std::unique_ptr<FElemInterface<Fp>>;
template <class Fp>
//typedef ::std::shared_ptr<Protoboard<Fp>> ProtoboardPtr;
using ProtoboardPtr = ::std::shared_ptr<Protoboard<Fp>>;
typedef unsigned long VarIndex_t;

// Naming Conventions:
// R1P == Rank 1 Prime characteristic

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                   class FElemInterface                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/**
    An interface class for field elements.
    Currently 2 classes will derive from this interface:
    R1P_Elem - Elements of a field of prime characteristic
    FConst - Formally not a field, only placeholders for field agnostic constants, such as 0 and 1.
             Can be used for -1 or any other constant which makes semantic sense in all fields.
 */
template <class Fp>
class FElemInterface {
public:
    virtual FElemInterface& operator=(const long n) = 0;
    /// FConst will be field agnostic, allowing us to hold values such as 0 and 1 without knowing
    /// the underlying field. This assignment operator will convert to the correct field element.
    virtual FElemInterface& operator=(const FConst<Fp>& src) = 0;
    virtual ::std::string asString() const = 0;
    virtual FieldType fieldType() const = 0;
    virtual FElemInterface& operator+=(const FElemInterface& other) = 0;
    virtual FElemInterface& operator-=(const FElemInterface& other) = 0;
    virtual FElemInterface& operator*=(const FElemInterface& other) = 0;
    virtual bool operator==(const FElemInterface& other) const = 0;
    virtual bool operator==(const FConst<Fp>& other) const = 0;
    /// This operator is not always mathematically well defined. 'n' will be checked in runtime
    /// for fields in which integer values are not well defined.
    virtual bool operator==(const long n) const = 0;
    /// @returns a unique_ptr to a copy of the current element.
    virtual FElemInterfacePtr<Fp> clone() const = 0;
    virtual FElemInterfacePtr<Fp> inverse() const = 0;
    virtual long asLong() const = 0;
    virtual int getBit(unsigned int i) const = 0;
    virtual FElemInterface& power(long exponent) = 0;
    virtual ~FElemInterface(){};

	//Added by CorrAuthor -----------
	virtual void print() const;
	//Added by CorrAuthor ----------- AOBVE
}; // class FElemInterface

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/
template <class Fp>
inline bool operator==(const long first, const FElemInterface<Fp>& second) {return second == first;}
template <class Fp>
inline bool operator!=(const long first, const FElemInterface<Fp>& second) {return !(first == second);}
template <class Fp>
inline bool operator!=(const FElemInterface<Fp>& first, const long second) {return !(first == second);}
template <class Fp>
inline bool operator!=(const FElemInterface<Fp>& first, const FElemInterface<Fp>& second) {
    return !(first == second);
}

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      class FElem<Fp>                          ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/


// CorrAuthor: Add the template to class
/// A wrapper class for field elements. Can hold any derived type of FieldElementInterface
template <class Fp>
class FElem {
private:
    FElemInterfacePtr<Fp> elem_;
public:
	//Added by CorrAuthor -----------
	void print() const{
		elem_->print();
	}
	//Added by CorrAuthor ----------- ABOVE
    explicit FElem(const FElemInterface<Fp>& elem);
    /// Helper method. When doing arithmetic between a constant and a field specific element
    /// we want to "promote" the constant to the same field. This function changes the unique_ptr
    /// to point to a field specific element with the same value as the constant which it held.
    void promoteToFieldType(FieldType type);
    FElem();
    FElem(const long n);
    FElem(const int i);
    FElem(const size_t n);
    FElem(const Fp& elem);
    FElem(const FElem& src);

    FElem& operator=(const FElem& other);
    FElem& operator=(FElem&& other);
    FElem& operator=(const long i) { *elem_ = i; return *this;}
    ::std::string asString() const {return elem_->asString();}
    FieldType fieldType() const {return elem_->fieldType();}
    bool operator==(const FElem& other) const {return *elem_ == *other.elem_;}
    FElem& operator*=(const FElem& other);
    FElem& operator+=(const FElem& other);
    FElem& operator-=(const FElem& other);
    FElem operator-() const {FElem retval(0); retval -= FElem(*elem_); return retval;}
    FElem inverse(const FieldType& fieldType);
    long asLong() const {return elem_->asLong();}
    int getBit(unsigned int i, const FieldType& fieldType);
    friend FElem power(const FElem& base, long exponent);

    inline friend ::std::ostream& operator<<(::std::ostream& os, const FElem& elem) {
       return os << elem.elem_->asString();
    }

    friend class GadgetLibAdapter<Fp>;
}; // class FElem

template <class Fp>
inline bool operator!=(const FElem<Fp>& first, const FElem<Fp>& second) {return !(first == second);}

/// These operators are not always mathematically well defined. The long will be checked in runtime
/// for fields in which values other than 0 and 1 are not well defined.
template <class Fp>
inline bool operator==(const FElem<Fp>& first, const long second) {return first == FElem<Fp>(second);}

template <class Fp>
inline bool operator==(const long first, const FElem<Fp>& second) {return second == first;}

template <class Fp>
inline bool operator!=(const FElem<Fp>& first, const long second) {return !(first == second);}

template <class Fp>
inline bool operator!=(const long first, const FElem<Fp>& second) {return !(first == second);}

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
/**
    A field agnostic constant. All fields have constants 1 and 0 and this class allows us to hold
    an element agnostically while the context field is not known. For example, when given the
    very useful expression '1 - x' where x is a field agnostic formal variable, we must store the
    constant '1' without knowing over which field this expression will be evaluated.
    Constants can also hold integer values, which will be evaluated if possible, in runtime. For
    instance the expression '42 + x' will be evaluated in runtime in the trivial way when working
    over the prime characteristic Galois Field GF_43 but will cause a runtime error when evaluated
    over a GF2 extension field in which '42' has no obvious meaning, other than being the answer to
    life, the universe and everything.
*/
template <class Fp>
class FConst : public FElemInterface<Fp> {
private:
    long contents_;
    explicit FConst(const long n) : contents_(n) {}
public:
    virtual FConst& operator=(const long n) {contents_ = n; return *this;}
    virtual FConst& operator=(const FConst& src) {contents_ = src.contents_; return *this;}
    virtual ::std::string asString() const {return GADGETLIB2_FMT("%ld",contents_);}
	//Added by CorrAuthor -----------
	virtual void print() const{
		printf("%ld",contents_);
	}
	//Added by CorrAuthor ----------- AOBVE
    virtual FieldType fieldType() const {return AGNOSTIC;}
    virtual FConst& operator+=(const FElemInterface<Fp>& other);
    virtual FConst& operator-=(const FElemInterface<Fp>& other);
    virtual FConst& operator*=(const FElemInterface<Fp>& other);
    virtual bool operator==(const FElemInterface<Fp>& other) const {return other == *this;}
    virtual bool operator==(const FConst& other) const {return contents_ == other.contents_;}
    virtual bool operator==(const long n) const {return contents_ == n;}
    /// @return a unique_ptr to a new copy of the element
    virtual FElemInterfacePtr<Fp> clone() const {return FElemInterfacePtr<Fp>(new FConst<Fp>(*this));}
    /// @return a unique_ptr to a new copy of the element's multiplicative inverse
    virtual FElemInterfacePtr<Fp> inverse() const;
    long asLong() const {return contents_;}
    int getBit(unsigned int i) const { libff::UNUSED(i); GADGETLIB_FATAL("Cannot get bit from FConst."); }
    virtual FElemInterface<Fp>& power(long exponent);

    friend class FElem<Fp>; // allow constructor call
}; // class FConst

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     class R1P_Elem                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
/**
    Holds elements of a prime characteristic field. Currently implemented using the gmp (Linux) and
    mpir (Windows) libraries.
 */
template <class Fp>
class R1P_Elem : public FElemInterface<Fp>{
private:
    Fp elem_;
public:
	//Added by CorrAuthor -----------
	virtual void print() const{
		//printf("%u", elem_.as_ulong());
		elem_.print();
	}
	//Added by CorrAuthor ----------- AOBVE

    explicit R1P_Elem(const Fp& elem) : elem_(elem) {}
    virtual R1P_Elem& operator=(const FConst<Fp>& src) {elem_ = src.asLong(); return *this;}
    virtual R1P_Elem& operator=(const long n) {elem_ = Fp(n); return *this;}
    virtual ::std::string asString() const {
		return GADGETLIB2_FMT("%u", elem_.as_ulong());
	}
    virtual FieldType fieldType() const {return R1P;}
    virtual R1P_Elem& operator+=(const FElemInterface<Fp>& other);
    virtual R1P_Elem& operator-=(const FElemInterface<Fp>& other);
    virtual R1P_Elem& operator*=(const FElemInterface<Fp>& other);
    virtual bool operator==(const FElemInterface<Fp>& other) const;
    virtual bool operator==(const FConst<Fp>& other) const {return elem_ == Fp(other.asLong());}
    virtual bool operator==(const long n) const {return elem_ == Fp(n);}
    /// @return a unique_ptr to a new copy of the element
    virtual FElemInterfacePtr<Fp> clone() const {return FElemInterfacePtr<Fp>(new R1P_Elem(*this));}
    /// @return a unique_ptr to a new copy of the element's multiplicative inverse
    virtual FElemInterfacePtr<Fp> inverse() const;
    long asLong() const;
    int getBit(unsigned int i) const {return elem_.as_bigint().test_bit(i);}
    virtual FElemInterface<Fp>& power(long exponent) {elem_^= exponent; return *this;}

    friend class FElem<Fp>; // allow constructor call
    friend class GadgetLibAdapter<Fp>;
};

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
struct VariableStrictOrderNew {
	bool operator()(const Variable<Fp>& first, const Variable<Fp>& second)const {
		return first.index_ < second.index_;
	}
};

template <class Fp>
//typedef ::std::map<Variable<Fp>, FElem<Fp>, Variable<Fp>::VariableStrictOrder> VariableAssignment;
using VariableAssignment =  ::std::map<Variable<Fp>, FElem<Fp>, VariableStrictOrderNew<Fp>>;

//typedef ::std::set<Variable, VariableStrictOrder> set;
template <class Fp>
using Variable_set = ::std::set<Variable<Fp>,VariableStrictOrderNew<Fp>>;
//typedef ::std::multiset<Variable, VariableStrictOrder> multiset;
template <class Fp>
using Variable_multiset = ::std::multiset<Variable<Fp>,VariableStrictOrderNew<Fp>>;
/**
    @brief A formal variable, field agnostic.

    Each variable is specified by an index. This can be imagined as the index in x_1, x_2,..., x_i
    These are formal variables and do not hold an assignment, later the class VariableAssignment
    will give each formal variable its own assignment.
    Variables have no comparison and assignment operators as evaluating (x_1 == x_2) has no sense
    without specific assignments.
    Variables are field agnostic, this means they can be used regardless of the context field,
    which will also be determined by the assignment.
 */
template <class Fp>
class Variable {
private:
    static VarIndex_t nextFreeIndex_; ///< Monotonically-increasing counter to allocate disinct indices.
#ifdef DEBUG
    ::std::string name_;
#endif

   /**
    * @brief allocates the variable
    */
public:
    VarIndex_t index_;  ///< This index differentiates and identifies Variable instances. //MOVE IT TO PUBLIC FOR TYPE CHECK PURPOSE TO LET COMPARATOR PASS
    explicit Variable(const ::std::string& name = "");
    virtual ~Variable();

    ::std::string name() const;

    /// A functor for strict ordering of Variables. Needed for STL containers.
    /// This is not an ordering of Variable assignments and has no semantic meaning.
    struct VariableStrictOrder {
        bool operator()(const Variable& first, const Variable& second)const {
            return first.index_ < second.index_;
        }
    };

    //typedef ::std::map<Variable, FElem<Fp>, Variable::VariableStrictOrder> VariableAssignment;
    FElem<Fp>eval(const VariableAssignment<Fp>& assignment) const;

    /// A set of Variables should be declared as follows:    Variable::set s1;
	//MOVE UP due to template
    //typedef ::std::set<Variable, VariableStrictOrder> set;
    //typedef ::std::multiset<Variable, VariableStrictOrder> multiset;

    // jSNARK-edit: A simple getter for the Variable index
    int getIndex() const { return index_;}

    friend class GadgetLibAdapter<Fp>;
}; // class Variable
/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 class VariableArray                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
using VariableArrayContents =  ::std::vector<Variable<Fp>>;

template <class Fp>
class VariableArray : public VariableArrayContents<Fp> {
private:
#   ifdef DEBUG
    ::std::string name_;
#   endif
public:
    explicit VariableArray(const ::std::string& name = "");
    explicit VariableArray(const int size, const ::std::string& name = "");
    explicit VariableArray(const size_t size, const ::std::string& name = "");
    explicit VariableArray(const size_t size, const Variable<Fp>& contents)
            : VariableArrayContents<Fp>(size, contents) {}

    using VariableArrayContents<Fp>::operator[];
    using VariableArrayContents<Fp>::at;
    using VariableArrayContents<Fp>::push_back;
    using VariableArrayContents<Fp>::size;

    ::std::string name() const;
}; // class VariableArray

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
using FlagVariable = Variable<Fp>;
///< Holds variable whose purpose is to be populated with a boolean
                               ///< value, Field(0) or Field(1)

template <class Fp>
using FlagVariableArray = VariableArray<Fp>;

template <class Fp>
using PackedWord = Variable<Fp>;
///< Represents a packed word that can fit in a field element.
                               ///< For a word representing an unsigned integer for instance this
                               ///< means we require (int < fieldSize)

template <class Fp>
using PackedWordArray = VariableArray<Fp>;

/// Holds variables whose purpose is to be populated with the unpacked form of some word, bit by bit
template<class Fp>
class UnpackedWord : public VariableArray<Fp> {
public:
    UnpackedWord() : VariableArray<Fp>() {}
    UnpackedWord(const size_t numBits, const ::std::string& name) : VariableArray<Fp>(numBits, name) {}
}; // class UnpackedWord

//typedef ::std::vector<UnpackedWord> UnpackedWordArray;
template <class Fp>
using UnpackedWordArray = ::std::vector<UnpackedWord<Fp>> ;

/// Holds variables whose purpose is to be populated with the packed form of some word.
/// word representation can be larger than a single field element in small enough fields
template<class Fp>
class MultiPackedWord : public VariableArray<Fp> {
private:
    size_t numBits_;
    FieldType fieldType_;
    size_t getMultipackedSize() const;
public:
    MultiPackedWord(const FieldType& fieldType = AGNOSTIC);
    MultiPackedWord(const size_t numBits, const FieldType& fieldType, const ::std::string& name);
    void resize(const size_t numBits);
    ::std::string name() const {return VariableArray<Fp>::name();}
}; // class MultiPackedWord

//typedef ::std::vector<MultiPackedWord> MultiPackedWordArray;
template<class Fp>
using MultiPackedWordArray = ::std::vector<MultiPackedWord<Fp>>;

/// Holds both representations of a word, both multipacked and unpacked
template<class Fp>
class DualWord {
private:
    MultiPackedWord<Fp> multipacked_;
    UnpackedWord<Fp> unpacked_;
public:
    DualWord(const FieldType& fieldType) : multipacked_(fieldType), unpacked_() {}
    DualWord(const size_t numBits, const FieldType& fieldType, const ::std::string& name);
    DualWord(const MultiPackedWord<Fp>& multipacked, const UnpackedWord<Fp>& unpacked);
    MultiPackedWord<Fp> multipacked() const {return multipacked_;}
    UnpackedWord<Fp> unpacked() const {return unpacked_;}
    FlagVariable<Fp> bit(size_t i) const {return unpacked_[i];} //syntactic sugar, same as unpacked()[i]
    size_t numBits() const { return unpacked_.size(); }
    void resize(size_t newSize);
}; // class DualWord

template<class Fp>
class DualWordArray {
private:
    // kept as 2 separate arrays because the more common usecase will be to request one of these,
    // and not dereference a specific DualWord
    MultiPackedWordArray<Fp> multipackedContents_;
    UnpackedWordArray<Fp> unpackedContents_;
    size_t numElements_;
public:
    DualWordArray(const FieldType& fieldType);
    DualWordArray(const MultiPackedWordArray<Fp>& multipackedContents, // TODO delete, for dev
                  const UnpackedWordArray<Fp>& unpackedContents);
    MultiPackedWordArray<Fp> multipacked() const;
    UnpackedWordArray<Fp> unpacked() const;
    PackedWordArray<Fp> packed() const; //< For cases in which we can assume each unpacked value fits
                                    //< in 1 packed Variable
    void push_back(const DualWord<Fp>& dualWord);
    DualWord<Fp> at(size_t i) const;
    size_t size() const;
}; // class DualWordArray


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     class LinearTerm                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
class LinearTerm {
private:
    Variable<Fp> variable_;
    FElem<Fp> coeff_;
public:
    LinearTerm(const Variable<Fp>& v) : variable_(v), coeff_(1) { }
    LinearTerm(const Variable<Fp>& v, const FElem<Fp>& coeff) : variable_(v), coeff_(coeff) { }
    LinearTerm(const Variable<Fp>& v, long n) : variable_(v), coeff_(n) { }
    LinearTerm operator-() const {return LinearTerm(variable_, -coeff_);}

    // jSNARK-edit: These two operators are overloaded to support combining common factors for the same variables.
    LinearTerm& operator-=(const FElem<Fp>& other) {coeff_ -= other; return *this;}
    LinearTerm& operator+=(const FElem<Fp>& other) {coeff_ += other; return *this;}

    LinearTerm& operator*=(const FElem<Fp>& other) {
		coeff_ *= other; 
		return *this;
	}
    FieldType fieldtype() const {return coeff_.fieldType();}
    ::std::string asString() const;
    FElem<Fp>eval(const VariableAssignment<Fp>& assignment) const;
    Variable<Fp> variable() const {return variable_;}

    // jSNARK-edit: A simple getter for the coefficient
    FElem<Fp> coeff() const {return coeff_;}

	//Added By CorrAuthor ------------
	void print() const {
		cout << "x_" << variable_.index_ << " x ";
		//cout <<coeff_.asLong();
		coeff_.print();
		printf("\n");
	}
	//Added By CorrAuthor ------------ ABOVE

    friend class Monomial<Fp>;
    friend class GadgetLibAdapter<Fp>;
}; // class LinearTerm

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/



/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  class LinearCombination                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
class LinearCombination {
protected:
    ::std::vector<LinearTerm<Fp>> linearTerms_;
    std::map<int, int> indexMap_; // jSNARK-edit: This map is used to reduce memory consumption. Can be helpful for some circuits produced by Pinocchio compiler.
    FElem<Fp> constant_;
    //typedef ::std::vector<LinearTerm<Fp>>::size_type size_type;
public:
	//Added by CorrAuthor --------------
	//search for the linear term which contains variable idx and
	//print its co-eff, return true if found
	bool searchForVar(int idx){
		for(int i=0; i<linearTerms_.size(); i++){
			if(linearTerms_[i].variable().index_==idx){
				printf("DEBUG USE 9191: FOUND var: %d, coeff: ", idx);
				linearTerms_[i].coeff().print();
				printf("\t,\t");
				return true;
			}
		}
		return false;
	}
	//Added by CorrAuthor -------------- ABOVE

    LinearCombination() : linearTerms_(), constant_(0) {}
    LinearCombination(const Variable<Fp>& var) : linearTerms_(1,var), constant_(0) {}
    LinearCombination(const LinearTerm<Fp>& linTerm) : linearTerms_(1,linTerm), constant_(0) {}
    LinearCombination(long i) : linearTerms_(), constant_(i) {}
    LinearCombination(const FElem<Fp>& elem) : linearTerms_(), constant_(elem) {}

    LinearCombination& operator+=(const LinearCombination& other);
    LinearCombination& operator-=(const LinearCombination& other);
    LinearCombination& operator*=(const FElem<Fp>& other);
    FElem<Fp> eval(const VariableAssignment<Fp>& assignment) const;
    ::std::string asString() const;
    const Variable_set<Fp> getUsedVariables() const;
    //Variable_set<Fp> getUsedVariables() const;

	//Added By CorrAuthor ------------
	void print() const {
		printf("---- Linear Combination: ----\n");
		for(int i=0; i<linearTerms_.size(); i++){
			linearTerms_[i].print();
		}
		printf("---- Linear Combination ABOVE: ----\n");
	}
	//Added By CorrAuthor ------------ ABOVE

    friend class Polynomial<Fp>;
    friend class GadgetLibAdapter<Fp>;
}; // class LinearCombination

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& lc){return LinearCombination<Fp>(0) -= lc;}

template <class Fp>
LinearCombination<Fp> sum(const VariableArray<Fp>& inputs);

//TODO : change this to member function
template <class Fp>
LinearCombination<Fp> negate(const LinearCombination<Fp>& lc);

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                       class Monomial                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
class Monomial {
private:
    FElem<Fp> coeff_;
    Variable_multiset<Fp> variables_; // currently just a vector of variables. This can
                                   // surely be optimized e.g. hold a variable-degree pair
                                   // but is not needed for concrete efficiency as we will
                                   // only be invoking degree 2 constraints in the near
                                   // future.
public:
    Monomial(const Variable<Fp>& var) : coeff_(1), variables_() {variables_.insert(var);}
    Monomial(const Variable<Fp>& var, const FElem<Fp>& coeff) : coeff_(coeff), variables_() {variables_.insert(var);}
    Monomial(const FElem<Fp>& val) : coeff_(val), variables_() {}
    Monomial(const LinearTerm<Fp>& linearTerm);

    FElem<Fp>eval(const VariableAssignment<Fp>& assignment) const;
    const Variable_set<Fp> getUsedVariables() const;
    const FElem<Fp>getCoefficient() const;
    ::std::string asString() const;
    Monomial operator-() const;
    Monomial& operator*=(const Monomial& other);
}; // class Monomial

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      class Polynomial                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
class Polynomial {
private:
    ::std::vector<Monomial<Fp>> monomials_;
    FElem<Fp> constant_;
public:
    Polynomial() : monomials_(), constant_(0) {}
    Polynomial(const Monomial<Fp>& monomial) : monomials_(1, monomial), constant_(0) {}
    Polynomial(const Variable<Fp>& var) : monomials_(1, Monomial<Fp>(var)), constant_(0) {}
    Polynomial(const FElem<Fp>& val) : monomials_(), constant_(val) {}
    Polynomial(const LinearCombination<Fp>& linearCombination);
    Polynomial(const LinearTerm<Fp>& linearTerm) : monomials_(1, Monomial<Fp>(linearTerm)), constant_(0) {}
    Polynomial(int i) : monomials_(), constant_(i) {}

    FElem<Fp>eval(const VariableAssignment<Fp>& assignment) const;
    const Variable_set<Fp> getUsedVariables() const;
    const std::vector<Monomial<Fp>>& getMonomials()const;
    const FElem<Fp> getConstant()const;
    ::std::string asString() const;
    Polynomial& operator+=(const Polynomial& other);
    Polynomial& operator*=(const Polynomial& other);
    Polynomial& operator-=(const Polynomial& other);
    Polynomial& operator+=(const LinearTerm<Fp>& other) {return *this += Polynomial(Monomial<Fp>(other));}
}; // class Polynomial

/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

template <class Fp>
inline Polynomial<Fp> operator-(const Polynomial<Fp>& src) {return Polynomial<Fp>(FElem<Fp>(0)) -= src;}

} // namespace new_gadgetlib2

#include <libsnark/new_gadgetlib2/variable_operators.hpp>

#include <libsnark/new_gadgetlib2/variable.tcc>
#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLE_HPP_
