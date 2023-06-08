/** @file
 *****************************************************************************
 Interfaces and basic gadgets for R1P (Rank 1 prime characteristic)
 constraint systems.

 These interfaces have been designed to allow later adding other fields or constraint
 structures while allowing high level design to stay put.

 A gadget represents (and generates) the constraints, constraint "wiring", and
 witness for a logical task. This is best explained using the physical design of a printed
 circuit. The Protoboard is the board on which we will "solder" our circuit. The wires
 (implemented by Variables) can hold any element of the underlying field. Each constraint
 enforces a relation between wires. These can be thought of as gates.

 The delegation of tasks is as follows:

 -   Constructor - Allocates all Variables to a Protoboard. Creates all sub-gadgets
     that will be needed and wires their inputs and outputs.
     generateConstraints - Generates the constraints which define the
     necessary relations between the previously allocated Variables.

 -   generateWitness - Generates an assignment for all non-input Variables which is
     consistent with the assignment of the input Variables and satisfies
     all of the constraints. In essence, this computes the logical
     function of the Gadget.

 -   create - A static factory method used for construction of the Gadget. This is
     used in order to create a Gadget without explicit knowledge of the
     underlying algebraic field.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_GADGET_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_GADGET_HPP_

#include <vector>

#include <libsnark/new_gadgetlib2/gadgetMacros.hpp>
#include <libsnark/new_gadgetlib2/protoboard.hpp>
#include <libsnark/new_gadgetlib2/variable.hpp>

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                         class Gadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/**
 Gadget class, representing the constraints and witness generation for a logical task.

 Gadget hierarchy:
 (Here and elsewhere: R1P = Rank 1 constraints over a prime-characteristic field.)
 Gadgets have a somewhat cumbersome class hierarchy, for the sake of clean gadget construction.
 (1) A field agnostic, concrete (as opposed to interface) gadget will derive from Gadget. For
     instance NAND needs only AND and NOT and does not care about the field, thus it derives from
     Gadget.
 (2) Field specific interface class R1P_Gadget derives from Gadget using virtual
     inheritance, in order to avoid the Dreaded Diamond problem (see
     http://stackoverflow.com/a/21607/1756254 for more info)
 (3) Functional interface classes such as LooseMUX_GadgetBase virtually derive from Gadget and
     define special gadget functionality. For gadgets with no special interfaces we use the macro
     CREATE_GADGET_BASE_CLASS() for the sake of code consistency (these gadgets can work the same
     without this base class). This is an interface only and the implementation of AND_Gadget is
     field specific.
 (4) These field specific gadgets will have a factory class with static method create, such as
     AND_Gadget::create(...) in order to agnostically create this gadget for use by a field
     agnostic gadget.
 (5) Concrete field dependent gadgets derive via multiple inheritance from two interfaces.
     e.g. R1P_AND_Gadget derives from both AND_Gadget and R1P_Gadget. This was done to allow usage
     of AND_Gadget's field agnostic create() method and R1P_Gadget's field specific val() method.
*/
template <class Fp>
class Gadget {
private:
    DISALLOW_COPY_AND_ASSIGN(Gadget);
protected:
    ProtoboardPtr<Fp> pb_;
public:
    Gadget(ProtoboardPtr<Fp> pb);
    virtual void init() = 0;
    /* generate constraints must have this interface, however generateWitness for some gadgets
       (like CTime) will take auxiliary information (like memory contents). We do not want to force
       the interface for generateWitness but do want to make sure it is never invoked from base
       class.
    */
    virtual void generateConstraints() = 0;
    virtual void generateWitness(); // Not abstract as this method may have different signatures.
    void addUnaryConstraint(const LinearCombination<Fp>& a, const ::std::string& name);
    void addRank1Constraint(const LinearCombination<Fp>& a,
                            const LinearCombination<Fp>& b,
                            const LinearCombination<Fp>& c,
                            const ::std::string& name);
    void enforceBooleanity(const Variable<Fp>& var) {pb_->enforceBooleanity(var);}
    FElem<Fp>& val(const Variable<Fp>& var) {return pb_->val(var);}
    FElem<Fp> val(const LinearCombination<Fp>& lc) {return pb_->val(lc);}
    FieldType fieldType() const {return pb_->fieldType_;}
    bool flagIsSet(const FlagVariable<Fp>& flag) const {return pb_->flagIsSet(flag);}
};

template <class Fp>
//typedef ::std::shared_ptr<Gadget<Fp>> GadgetPtr; // Not a unique_ptr because sometimes we need to cast
using GadgetPtr = ::std::shared_ptr<Gadget<Fp>>;
                                             // these pointers for specific gadget operations.
/***********************************/
/***   END OF CLASS DEFINITION   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      Gadget Interfaces                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
   We use multiple inheritance in order to use much needed syntactic sugar. We want val() to be
   able to return different types depending on the field so we need to differentiate the interfaces
   between R1P and other fields. We also want the interfaces of specific logical gadgets
   (for instance AND_Gadget which has n inputs and 1 output) in order to construct higher level
   gadgets without specific knowledge of the underlying field. Both interfaces (for instance
   R1P_gadget and AND_Gadget) inherit from Gadget using virtual inheritance (this means only one
   instance of Gadget will be created. For a more thorough discussion on virtual inheritance see
   http://www.phpcompiler.org/articles/virtualinheritance.html
 */

template <class Fp>
class R1P_Gadget : virtual public Gadget<Fp> {
public:
    R1P_Gadget(ProtoboardPtr<Fp> pb) : Gadget<Fp>(pb) {}
    virtual ~R1P_Gadget() = 0;

    virtual void addRank1Constraint(const LinearCombination<Fp>& a,
                                    const LinearCombination<Fp>& b,
                                    const LinearCombination<Fp>& c,
                                    const ::std::string& name);
private:
    virtual void init() = 0; // private in order to force programmer to invoke from a Gadget* only
    DISALLOW_COPY_AND_ASSIGN(R1P_Gadget);
}; // class R1P_Gadget

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     AND_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

CREATE_GADGET_BASE_CLASS(AND_GadgetBase);

/// Specific case for and AND with two inputs. Field agnostic
template <class Fp>
class BinaryAND_Gadget : public AND_GadgetBase<Fp> {
private:
    BinaryAND_Gadget(ProtoboardPtr<Fp> pb,
                     const LinearCombination<Fp>& input1,
                     const LinearCombination<Fp>& input2,
                     const Variable<Fp>& result);
    void init();
    void generateConstraints();
    void generateWitness();
public:
    friend class AND_Gadget;
private:
    //external variables
    const LinearCombination<Fp> input1_;
    const LinearCombination<Fp> input2_;
    const Variable<Fp> result_;

    DISALLOW_COPY_AND_ASSIGN(BinaryAND_Gadget);
}; // class BinaryAND_Gadget


template <class Fp>
class R1P_AND_Gadget : public AND_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    R1P_AND_Gadget(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result);
    virtual void init();
public:
    void generateConstraints();
    void generateWitness();
    friend class AND_Gadget;
private:
    //external variables
    const VariableArray<Fp> input_;
    const Variable<Fp> result_;
    //internal variables
    LinearCombination<Fp> sum_;
    Variable<Fp> sumInverse_;

    DISALLOW_COPY_AND_ASSIGN(R1P_AND_Gadget);
};


template <class Fp>
class AND_Gadget {
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result);
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& input1,
                            const LinearCombination<Fp>& input2,
                            const Variable<Fp>& result);
private:
    DISALLOW_CONSTRUCTION(AND_Gadget);
    DISALLOW_COPY_AND_ASSIGN(AND_Gadget);
}; // class GadgetType


/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     OR_Gadget classes                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

CREATE_GADGET_BASE_CLASS(OR_GadgetBase);

/// Specific case for and OR with two inputs. Field agnostic
template <class Fp>
class BinaryOR_Gadget : public OR_GadgetBase<Fp> {
private:
    BinaryOR_Gadget(ProtoboardPtr<Fp> pb,
                    const LinearCombination<Fp>& input1,
                    const LinearCombination<Fp>& input2,
                    const Variable<Fp>& result);
    void init();
    void generateConstraints();
    void generateWitness();
public:
    friend class OR_Gadget;
private:
    //external variables
    const LinearCombination<Fp> input1_;
    const LinearCombination<Fp> input2_;
    const Variable<Fp> result_;

    DISALLOW_COPY_AND_ASSIGN(BinaryOR_Gadget);
}; // class BinaryOR_Gadget

template <class Fp>
class R1P_OR_Gadget : public OR_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    LinearCombination<Fp> sum_;
    Variable<Fp> sumInverse_;
    R1P_OR_Gadget(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result);
    virtual void init();
public:
    const VariableArray<Fp> input_;
    const Variable<Fp> result_;
    void generateConstraints();
    void generateWitness();
    friend class OR_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_OR_Gadget);
};

template <class Fp>
class OR_Gadget {
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result);
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& input1,
                            const LinearCombination<Fp>& input2,
                            const Variable<Fp>& result);
private:
    DISALLOW_CONSTRUCTION(OR_Gadget);
    DISALLOW_COPY_AND_ASSIGN(OR_Gadget);
}; // class GadgetType

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************               InnerProduct_Gadget classes                  ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

CREATE_GADGET_BASE_CLASS(InnerProduct_GadgetBase);

template <class Fp>
class R1P_InnerProduct_Gadget : public InnerProduct_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    VariableArray<Fp> partialSums_;
    R1P_InnerProduct_Gadget(ProtoboardPtr<Fp> pb,
                            const VariableArray<Fp>& A,
                            const VariableArray<Fp>& B,
                            const Variable<Fp>& result);
    virtual void init();
public:
    const VariableArray<Fp> A_, B_;
    const Variable<Fp> result_;
    void generateConstraints();
    void generateWitness();
    friend class InnerProduct_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_InnerProduct_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(InnerProduct_Gadget, VariableArray<Fp>, A,
                                                   VariableArray<Fp>, B,
                                                   Variable<Fp>, result);

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                LooseMUX_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
    Loose Multiplexer (MUX):
    Multiplexes one Variable
    index not in bounds -> success_flag = 0
    index in bounds && success_flag = 1 -> result is correct
    index is in bounds, we can also set success_flag to 0 -> result will be forced to 0
*/

template <class Fp>
class LooseMUX_GadgetBase : virtual public Gadget<Fp> {
protected:
    LooseMUX_GadgetBase(ProtoboardPtr<Fp> pb) : Gadget<Fp>(pb) {}
public:
    virtual ~LooseMUX_GadgetBase() = 0;
    virtual VariableArray<Fp> indicatorVariables() const = 0;
private:
    virtual void init() = 0;
    DISALLOW_COPY_AND_ASSIGN(LooseMUX_GadgetBase);
}; // class LooseMUX_GadgetBase


template <class Fp>
class R1P_LooseMUX_Gadget : public LooseMUX_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    VariableArray<Fp> indicators_;
    ::std::vector<GadgetPtr<Fp>> computeResult_; // Inner product gadgets
    R1P_LooseMUX_Gadget(ProtoboardPtr<Fp> pb,
                        const MultiPackedWordArray<Fp>& inputs,
                        const Variable<Fp>& index,
                        const VariableArray<Fp>& output,
                        const Variable<Fp>& successFlag);
    virtual void init();
public:
    MultiPackedWordArray<Fp> inputs_;
    const Variable<Fp> index_;
    const VariableArray<Fp> output_;
    const Variable<Fp> successFlag_;
    void generateConstraints();
    void generateWitness();
    virtual VariableArray<Fp> indicatorVariables() const;
    friend class LooseMUX_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_LooseMUX_Gadget);
};

template <class Fp>
class LooseMUX_Gadget {
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const MultiPackedWordArray<Fp>& inputs,
                            const Variable<Fp>& index,
                            const VariableArray<Fp>& output,
                            const Variable<Fp>& successFlag);
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const VariableArray<Fp>& inputs,
                            const Variable<Fp>& index,
                            const Variable<Fp>& output,
                            const Variable<Fp>& successFlag);
private:
    DISALLOW_CONSTRUCTION(LooseMUX_Gadget);
    DISALLOW_COPY_AND_ASSIGN(LooseMUX_Gadget);
}; // class GadgetType


/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************            CompressionPacking_Gadget classes               ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO change class name to bitpacking
enum class PackingMode : bool {PACK, UNPACK};

CREATE_GADGET_BASE_CLASS(CompressionPacking_GadgetBase);

template <class Fp>
class R1P_CompressionPacking_Gadget : public CompressionPacking_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    PackingMode packingMode_;
    R1P_CompressionPacking_Gadget(ProtoboardPtr<Fp> pb,
                                  const VariableArray<Fp>& unpacked,
                                  const VariableArray<Fp>& packed,
                                  PackingMode packingMode);
    virtual void init();
public:
    const VariableArray<Fp> unpacked_;
    const VariableArray<Fp> packed_;
    void generateConstraints();
    void generateWitness();
    friend class CompressionPacking_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_CompressionPacking_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(CompressionPacking_Gadget, VariableArray<Fp>, unpacked, VariableArray<Fp>,
                              packed, PackingMode, packingMode);


/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************            IntegerPacking_Gadget classes                ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

CREATE_GADGET_BASE_CLASS(IntegerPacking_GadgetBase);

// In R1P compression and arithmetic packing are implemented the same, hence this gadget simply
// instantiates an R1P_CompressionPacking_Gadget
template <class Fp>
class R1P_IntegerPacking_Gadget : public IntegerPacking_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    PackingMode packingMode_;
    GadgetPtr<Fp> compressionPackingGadget_;
    R1P_IntegerPacking_Gadget(ProtoboardPtr<Fp> pb,
                              const VariableArray<Fp>& unpacked,
                              const VariableArray<Fp>& packed,
                              PackingMode packingMode);
    virtual void init();
public:
    const VariableArray<Fp> unpacked_;
    const VariableArray<Fp> packed_;
    void generateConstraints();
    void generateWitness();
    friend class IntegerPacking_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_IntegerPacking_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(IntegerPacking_Gadget, VariableArray<Fp>, unpacked, VariableArray<Fp>,
                              packed, PackingMode, packingMode);

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 EqualsConst_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
    Gadgets recieve a constant field element n, and an input.
    input == n ==> result = 1
    input != n ==> result = 0
*/

// TODO change to take LinearCombination<Fp> as input and change AND/OR to use this
CREATE_GADGET_BASE_CLASS(EqualsConst_GadgetBase);

template <class Fp>
class R1P_EqualsConst_Gadget : public EqualsConst_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    const FElem<Fp> n_;
    Variable<Fp> aux_;
    R1P_EqualsConst_Gadget(ProtoboardPtr<Fp> pb,
                           const FElem<Fp>& n,
                           const LinearCombination<Fp>& input,
                           const Variable<Fp>& result);
    virtual void init();
public:
    const LinearCombination<Fp> input_;
    const Variable<Fp> result_;
    void generateConstraints();
    void generateWitness();
    friend class EqualsConst_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_EqualsConst_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(EqualsConst_Gadget, FElem<Fp>, n, LinearCombination<Fp>, input,
                              Variable<Fp>, result);

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                   DualWord_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
//TODO add test

template <class Fp>
class DualWord_Gadget : public Gadget<Fp> {

private:
    const DualWord<Fp> var_;
    const PackingMode packingMode_;

    GadgetPtr<Fp> packingGadget_;

    DualWord_Gadget(ProtoboardPtr<Fp> pb, const DualWord<Fp>& var, PackingMode packingMode);
    virtual void init();
    DISALLOW_COPY_AND_ASSIGN(DualWord_Gadget);
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb, const DualWord<Fp>& var, PackingMode packingMode);
    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 DualWordArray_Gadget                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
//TODO add test

template <class Fp>
class DualWordArray_Gadget : public Gadget<Fp> {

private:
    const DualWordArray<Fp> vars_;
    const PackingMode packingMode_;

    ::std::vector<GadgetPtr<Fp>> packingGadgets_;

    DualWordArray_Gadget(ProtoboardPtr<Fp> pb,
                             const DualWordArray<Fp>& vars,
                             PackingMode packingMode);
    virtual void init();
    DISALLOW_COPY_AND_ASSIGN(DualWordArray_Gadget);
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const DualWordArray<Fp>& vars,
                            PackingMode packingMode);
    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        Toggle_Gadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

//TODO add test

/// A gadget for the following semantics:
/// If toggle is 0, zeroValue --> result
/// If toggle is 1, oneValue --> result
/// Uses 1 constraint

template <class Fp>
class Toggle_Gadget : public Gadget<Fp> {
private:
    FlagVariable<Fp> toggle_;
    LinearCombination<Fp> zeroValue_;
    LinearCombination<Fp> oneValue_;
    Variable<Fp> result_;

    Toggle_Gadget(ProtoboardPtr<Fp> pb,
                  const FlagVariable<Fp>& toggle,
                  const LinearCombination<Fp>& zeroValue,
                  const LinearCombination<Fp>& oneValue,
                  const Variable<Fp>& result);

    virtual void init() {}
    DISALLOW_COPY_AND_ASSIGN(Toggle_Gadget);
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const FlagVariable<Fp>& toggle,
                            const LinearCombination<Fp>& zeroValue,
                            const LinearCombination<Fp>& oneValue,
                            const Variable<Fp>& result);

    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                   ConditionalFlag_Gadget                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/// A gadget for the following semantics:
/// condition != 0  --> flag = 1
/// condition == 0 --> flag = 0
/// Uses 2 constraints

template <class Fp>
class ConditionalFlag_Gadget : public Gadget<Fp> {
private:
    FlagVariable<Fp> flag_;
    LinearCombination<Fp> condition_;
    Variable<Fp> auxConditionInverse_;

    ConditionalFlag_Gadget(ProtoboardPtr<Fp> pb,
                           const LinearCombination<Fp>& condition,
                           const FlagVariable<Fp>& flag);

    virtual void init() {}
    DISALLOW_COPY_AND_ASSIGN(ConditionalFlag_Gadget);
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& condition,
                            const FlagVariable<Fp>& flag);

    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  LogicImplication_Gadget                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/// A gadget for the following semantics:
/// condition == 1 --> flag = 1
/// Uses 1 constraint

template <class Fp>
class LogicImplication_Gadget : public Gadget<Fp>{
private:
    FlagVariable<Fp> flag_;
    LinearCombination<Fp> condition_;

    LogicImplication_Gadget(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& condition,
                            const FlagVariable<Fp>& flag);

    virtual void init() {}
    DISALLOW_COPY_AND_ASSIGN(LogicImplication_Gadget);
public:
    static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& condition,
                            const FlagVariable<Fp>& flag);

    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        Compare_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

// TODO create unit test
CREATE_GADGET_BASE_CLASS(Comparison_GadgetBase);

template <class Fp>
class R1P_Comparison_Gadget : public Comparison_GadgetBase<Fp>, public R1P_Gadget<Fp> {
private:
    const size_t wordBitSize_;
    const PackedWord<Fp> lhs_;
    const PackedWord<Fp> rhs_;
    const FlagVariable<Fp> less_;
    const FlagVariable<Fp> lessOrEqual_;
	const PackedWord<Fp> alpha_p_;
	UnpackedWord<Fp> alpha_u_;
    const FlagVariable<Fp> notAllZeroes_;
    GadgetPtr<Fp> allZeroesTest_;
    GadgetPtr<Fp> alphaDualVariablePacker_;

    R1P_Comparison_Gadget(ProtoboardPtr<Fp> pb,
                          const size_t& wordBitSize,
                          const PackedWord<Fp>& lhs,
                          const PackedWord<Fp>& rhs,
                          const FlagVariable<Fp>& less,
                          const FlagVariable<Fp>& lessOrEqual);
    virtual void init();
public:

	static GadgetPtr<Fp> create(ProtoboardPtr<Fp> pb,
							const size_t& wordBitSize,
							const PackedWord<Fp>& lhs,
							const PackedWord<Fp>& rhs,
							const FlagVariable<Fp>& less,
							const FlagVariable<Fp>& lessOrEqual);

    void generateConstraints();
    void generateWitness();
    friend class Comparison_Gadget;
private:
    DISALLOW_COPY_AND_ASSIGN(R1P_Comparison_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_5(Comparison_Gadget, // TODO uncomment this
                              size_t, wordBitSize,
                              PackedWord<Fp>, lhs,
                              PackedWord<Fp>, rhs,
                              FlagVariable<Fp>, less,
                              FlagVariable<Fp>, lessOrEqual);

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

} // namespace new_gadgetlib2

#include <libsnark/new_gadgetlib2/gadget.tcc>
#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_GADGET_HPP_
