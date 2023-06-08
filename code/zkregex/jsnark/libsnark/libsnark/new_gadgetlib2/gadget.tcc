/** @file
 *****************************************************************************
 Declarations of the interfaces and basic gadgets for R1P (Rank 1 prime characteristic)
 constraint systems.

 See details in gadget.hpp .
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cmath>
#include <memory>

#include <libsnark/new_gadgetlib2/gadget.hpp>

using ::std::shared_ptr;
using ::std::string;
using ::std::vector;
using ::std::cout;
using ::std::cerr;
using ::std::endl;

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      Gadget Interfaces                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/***********************************/
/***          Gadget             ***/
/***********************************/

template <class Fp>
Gadget<Fp>::Gadget(ProtoboardPtr<Fp> pb) : pb_(pb) {
    GADGETLIB_ASSERT(pb != NULL, "Attempted to create gadget with uninitialized Protoboard.");
}

template <class Fp>
void Gadget<Fp>::generateWitness() {
    GADGETLIB_FATAL("Attempted to generate witness for an incomplete Gadget type.");
}

template <class Fp>
void Gadget<Fp>::addUnaryConstraint(const LinearCombination<Fp>& a, const ::std::string& name) {
    pb_->addUnaryConstraint(a, name);
}

template <class Fp>
void Gadget<Fp>::addRank1Constraint(const LinearCombination<Fp>& a,
                                const LinearCombination<Fp>& b,
                                const LinearCombination<Fp>& c,
                                const ::std::string& name) {
    pb_->addRank1Constraint(a, b, c, name);
}

/***********************************/
/***        R1P_Gadget           ***/
/***********************************/
template <class Fp>
R1P_Gadget<Fp>::~R1P_Gadget<Fp>() {};

template <class Fp>
void R1P_Gadget<Fp>::addRank1Constraint(const LinearCombination<Fp>& a,
                                    const LinearCombination<Fp>& b,
                                    const LinearCombination<Fp>& c,
                                    const string& name) {
    this->pb_->addRank1Constraint(a,b,c, name);
}

/***********************************/
/***  End of Gadget Interfaces   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      AND Gadgets                           ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
AND_GadgetBase<Fp>::~AND_GadgetBase() {};

/*
    Constraint breakdown:
    (1) input1 * input2 = result
*/
template <class Fp>
BinaryAND_Gadget<Fp>::BinaryAND_Gadget(ProtoboardPtr<Fp> pb,
                                   const LinearCombination<Fp>& input1,
                                   const LinearCombination<Fp>& input2,
                                   const Variable<Fp>& result)
        : Gadget<Fp>(pb), AND_GadgetBase<Fp>(pb), input1_(input1), input2_(input2), result_(result) {}

template <class Fp>
void BinaryAND_Gadget<Fp>::init() {}

template <class Fp>
void BinaryAND_Gadget<Fp>::generateConstraints() {
    addRank1Constraint(input1_, input2_, result_, "result = AND(input1, input2)");
}

template <class Fp>
void BinaryAND_Gadget<Fp>::generateWitness() {
    if (val(input1_) == 1 && val(input2_) == 1) {
        val(result_) = 1;
    } else {
        val(result_) = 0;
    }
}

/*
    Constraint breakdown:

    (*) sum = sum(input[i]) - n
    (1) sum * result = 0
    (2) sum * sumInverse = 1 - result

    [ AND(inputs) == 1 ] (*)==> [sum == 0] (2)==> [result == 1]
    [ AND(inputs) == 0 ] (*)==> [sum != 0] (1)==> [result == 0]
*/

template <class Fp>
R1P_AND_Gadget<Fp>::R1P_AND_Gadget(ProtoboardPtr<Fp> pb,
                               const VariableArray<Fp> &input,
                               const Variable<Fp> &result)
    : Gadget<Fp>(pb), AND_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), input_(input), result_(result),
      sumInverse_("sumInverse") {
    GADGETLIB_ASSERT(input.size() > 0, "Attempted to create an R1P_AND_Gadget with 0 inputs.");
    GADGETLIB_ASSERT(input.size() <= Fp(-1).as_ulong(), "Attempted to create R1P_AND_Gadget with too "
                                                              "many inputs. Will cause overflow!");
}

template <class Fp>
void R1P_AND_Gadget<Fp>::init() {
    const int numInputs = input_.size();
    sum_ = sum(input_) - numInputs;
}

template <class Fp>
void R1P_AND_Gadget<Fp>::generateConstraints() {
    addRank1Constraint(sum_, result_, 0,
                      "sum * result = 0 | sum == sum(input[i]) - n");
    addRank1Constraint(sumInverse_, sum_, 1-result_,
                      "sumInverse * sum = 1-result | sum == sum(input[i]) - n");
}

template <class Fp>
void R1P_AND_Gadget<Fp>::generateWitness() {
    FElem<Fp> sum = 0;
    for(size_t i = 0; i < input_.size(); ++i) {
        sum += val(input_[i]);
    }
    sum -= input_.size(); // sum(input[i]) - n ==> sum
    if (sum == 0) { // AND(input[0], input[1], ...) == 1
        val(sumInverse_) = 0;
        val(result_) = 1;
    } else {                   // AND(input[0], input[1], ...) == 0
        val(sumInverse_) = sum.inverse(R1P);
        val(result_) = 0;
    }
}

template <class Fp>
GadgetPtr<Fp> AND_Gadget<Fp>::create(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result){
    GadgetPtr<Fp> pGadget;
    if (pb->fieldType_ == R1P) {
        pGadget.reset(new R1P_AND_Gadget<Fp>(pb, input, result));
    } else {
        GADGETLIB_FATAL("Attempted to create gadget of undefined Protoboard type.");
    }
        pGadget->init();
    return pGadget;
}

template <class Fp>
GadgetPtr<Fp> AND_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                             const LinearCombination<Fp>& input1,
                             const LinearCombination<Fp>& input2,
                             const Variable<Fp>& result) {
    GadgetPtr<Fp> pGadget(new BinaryAND_Gadget<Fp>(pb, input1, input2, result));
    pGadget->init();
    return pGadget;
}

/***********************************/
/***     End of AND Gadgets      ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      OR Gadgets                            ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
OR_GadgetBase<Fp>::~OR_GadgetBase() {};

/*
    Constraint breakdown:
    (1) result = input1 + input2 - input1 * input2
        input1 * input2 = input1 + input2 - result
*/
template <class Fp>
BinaryOR_Gadget<Fp>::BinaryOR_Gadget(ProtoboardPtr<Fp> pb,
                                 const LinearCombination<Fp>& input1,
                                 const LinearCombination<Fp>& input2,
                                 const Variable<Fp>& result)
        : Gadget<Fp>(pb), OR_GadgetBase<Fp>(pb), input1_(input1), input2_(input2), result_(result) {}

template <class Fp>
void BinaryOR_Gadget<Fp>::init() {}

template <class Fp>
void BinaryOR_Gadget<Fp>::generateConstraints() {
    addRank1Constraint(input1_, input2_, input1_ + input2_ - result_,
                       "result = OR(input1, input2)");
}

template <class Fp>
void BinaryOR_Gadget<Fp>::generateWitness() {
    if (val(input1_) == 1 || val(input2_) == 1) {
        val(result_) = 1;
    } else {
        val(result_) = 0;
    }
}

/*
    Constraint breakdown:

    (*) sum = sum(input[i])
    (1) sum * (1 - result) = 0
    (2) sum * sumInverse = result

    [ OR(inputs) == 1 ] (*)==> [sum != 0] (1)==> [result == 1]
    [ OR(inputs) == 0 ] (*)==> [sum == 0] (2)==> [result == 0]
*/

template <class Fp>
R1P_OR_Gadget<Fp>::R1P_OR_Gadget(ProtoboardPtr<Fp> pb,
                             const VariableArray<Fp> &input,
                             const Variable<Fp> &result)
        : Gadget<Fp>(pb), OR_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), sumInverse_("sumInverse"), input_(input),
          result_(result) {
    GADGETLIB_ASSERT(input.size() > 0, "Attempted to create an R1P_OR_Gadget with 0 inputs.");
    GADGETLIB_ASSERT(input.size() <= Fp(-1).as_ulong(), "Attempted to create R1P_OR_Gadget with too "
                                                              "many inputs. Will cause overflow!");

    }

template <class Fp>
void R1P_OR_Gadget<Fp>::init() {
    sum_ = sum(input_);
}

template <class Fp>
void R1P_OR_Gadget<Fp>::generateConstraints() {
    addRank1Constraint(sum_, 1 - result_, 0,
                       "sum * (1 - result) = 0 | sum == sum(input[i])");
    addRank1Constraint(sumInverse_, sum_, result_,
                       "sum * sumInverse = result | sum == sum(input[i])");
}

template <class Fp>
void R1P_OR_Gadget<Fp>::generateWitness() {
    FElem<Fp> sum = 0;
    for(size_t i = 0; i < input_.size(); ++i) { // sum(input[i]) ==> sum
        sum += val(input_[i]);
    }
    if (sum == 0) { // OR(input[0], input[1], ...) == 0
        val(sumInverse_) = 0;
        val(result_) = 0;
    } else {                   // OR(input[0], input[1], ...) == 1
        val(sumInverse_) = sum.inverse(R1P);
        val(result_) = 1;
    }
}

template <class Fp>
GadgetPtr<Fp> OR_Gadget<Fp>::create(ProtoboardPtr<Fp> pb, const VariableArray<Fp>& input, const Variable<Fp>& result) {
    GadgetPtr<Fp> pGadget;
    if (pb->fieldType_ == R1P) {
        pGadget.reset(new R1P_OR_Gadget<Fp>(pb, input, result));
    } else {
        GADGETLIB_FATAL("Attempted to create gadget of undefined Protoboard type.");
    }
        pGadget->init();
    return pGadget;
}

template <class Fp>
GadgetPtr<Fp> OR_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                            const LinearCombination<Fp>& input1,
                            const LinearCombination<Fp>& input2,
                            const Variable<Fp>& result) {
    GadgetPtr<Fp> pGadget(new BinaryOR_Gadget<Fp>(pb, input1, input2, result));
    pGadget->init();
    return pGadget;
}

/***********************************/
/***     End of OR Gadgets       ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 InnerProduct Gadgets                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
InnerProduct_GadgetBase<Fp>::~InnerProduct_GadgetBase() {};

/*
    Constraint breakdown:

    (1) partialSums[0] = A[0] * B[0]
    (2) partialSums[i] = partialSums[i-1] + A[0] * B[0] ==>                     i = 1..n-2
        partialSums[i] - partialSums[i-1] = A[i] * B[i]
    (3) result = partialSums[n-1] = partialSums[n-2] + A[n-1] * B[n-1] ==>
        result - partialSums[n-2] = A[n-1] * B[n-1]

*/

template <class Fp>
R1P_InnerProduct_Gadget<Fp>::R1P_InnerProduct_Gadget(ProtoboardPtr<Fp> pb,
                                                 const VariableArray<Fp>& A,
                                                 const VariableArray<Fp>& B,
                                                 const Variable<Fp>& result)
        : Gadget<Fp>(pb), InnerProduct_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), partialSums_(A.size(),
          "partialSums"), A_(A), B_(B), result_(result) {
    GADGETLIB_ASSERT(A.size() > 0, "Attempted to create an R1P_InnerProduct_Gadget with 0 inputs.");
    GADGETLIB_ASSERT(A.size() == B.size(), GADGETLIB2_FMT("Inner product vector sizes not equal. Sizes are: "
                                                        "(A) - %u, (B) - %u", A.size(), B.size()));
}

template <class Fp>
void R1P_InnerProduct_Gadget<Fp>::init() {}

template <class Fp>
void R1P_InnerProduct_Gadget<Fp>::generateConstraints() {
    const int n = A_.size();
    if (n == 1) {
        addRank1Constraint(A_[0], B_[0], result_, "A[0] * B[0] = result");
        return;
    }
    // else (n > 1)
    addRank1Constraint(A_[0], B_[0], partialSums_[0], "A[0] * B[0] = partialSums[0]");
    for(int i = 1; i <= n-2; ++i) {
        addRank1Constraint(A_[i], B_[i], partialSums_[i] - partialSums_[i-1],
            GADGETLIB2_FMT("A[%u] * B[%u] = partialSums[%u] - partialSums[%u]", i, i, i, i-1));
    }
    addRank1Constraint(A_[n-1], B_[n-1], result_ - partialSums_[n-2],
        "A[n-1] * B[n-1] = result - partialSums[n-2]");
}

template <class Fp>
void R1P_InnerProduct_Gadget<Fp>::generateWitness() {
    const int n = A_.size();
    if (n == 1) {
        val(result_) = val(A_[0]) * val(B_[0]);
        return;
    }
    // else (n > 1)
    val(partialSums_[0]) = val(A_[0]) * val(B_[0]);
    for(int i = 1; i <= n-2; ++i) {
        val(partialSums_[i]) = val(partialSums_[i-1]) + val(A_[i]) * val(B_[i]);
    }
    val(result_) = val(partialSums_[n-2]) + val(A_[n-1]) * val(B_[n-1]);
}

/***********************************/
/*** End of InnerProduct Gadgets ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                   LooseMUX Gadgets                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
LooseMUX_GadgetBase<Fp>::~LooseMUX_GadgetBase() {};

/*
    Constraint breakdown:
    (1) indicators[i] * (index - i) = 0  | i = 0..n-1 ==> only indicators[index] will be non-zero
    (2) sum(indicators[i]) = successFlag ==> successFlag = indicators[index]
    (3) successFlag is boolean
    (4) result[j] = <indicators> * <inputs[index][j]>  |  j = 1..output.size()   ==>
        result[j] = inputs[index][j]

*/

template <class Fp>
R1P_LooseMUX_Gadget<Fp>::R1P_LooseMUX_Gadget(ProtoboardPtr<Fp> pb,
                                         const MultiPackedWordArray<Fp>& inputs,
                                         const Variable<Fp>& index,
                                         const VariableArray<Fp>& output,
                                         const Variable<Fp>& successFlag)
        : Gadget<Fp>(pb), LooseMUX_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb),
          indicators_(inputs.size(), "indicators"), inputs_(inputs.size()), index_(index),
          output_(output), successFlag_(successFlag) {
    GADGETLIB_ASSERT(inputs.size() <= Fp(-1).as_ulong(), "Attempted to create R1P_LooseMUX_Gadget "
                                                      "with too many inputs. May cause overflow!");
//    for(const VariableArray<Fp>& inpArr : inputs) {
    for(size_t i = 0; i < inputs.size(); ++i) {
        GADGETLIB_ASSERT(inputs[i].size() == output.size(), "Input VariableArray<Fp> is of incorrect size.");
    }
    ::std::copy(inputs.begin(), inputs.end(), inputs_.begin()); // change type to R1P_VariableArray
}

template <class Fp>
void R1P_LooseMUX_Gadget<Fp>::init() {
    // create inputs for the inner products and initialize them. Each iteration creates a
    // VariableArray<Fp> for the i'th elements from each of the vector's VariableArrays.
    for(size_t i = 0; i < output_.size(); ++i) {
        VariableArray<Fp> curInput;
        for(size_t j = 0; j < inputs_.size(); ++j) {
            curInput.push_back(inputs_[j][i]);
        }
        computeResult_.push_back(InnerProduct_Gadget<Fp>::create(this->pb_, indicators_, curInput,
                                                             output_[i]));
    }
}

template <class Fp>
void R1P_LooseMUX_Gadget<Fp>::generateConstraints() {
    const size_t n = inputs_.size();
    for(size_t i = 0; i < n; ++i) {
        addRank1Constraint(indicators_[i], (index_-i), 0,
            GADGETLIB2_FMT("indicators[%u] * (index - %u) = 0", i, i));
    }
    addRank1Constraint(sum(indicators_), 1, successFlag_, "sum(indicators) * 1 = successFlag");
    enforceBooleanity(successFlag_);
    for(auto& curGadget : computeResult_) {
        curGadget->generateConstraints();
    }
}

template <class Fp>
void R1P_LooseMUX_Gadget<Fp>::generateWitness() {
    const size_t n = inputs_.size();
    /* assumes that idx can be fit in ulong; true for our purposes for now */
    const size_t index = val(index_).asLong();
    const FElem<Fp> arraySize = n;
    for(size_t i = 0; i < n; ++i) {
        val(indicators_[i]) = 0; // Redundant, but just in case.
    }
    if (index >= n) { //  || index < 0
        val(successFlag_) = 0;
    } else { // index in bounds
        val(indicators_[index]) = 1;
        val(successFlag_) = 1;
    }
    for(auto& curGadget : computeResult_) {
        curGadget->generateWitness();
    }
}

template <class Fp>
VariableArray<Fp> R1P_LooseMUX_Gadget<Fp>::indicatorVariables() const {return indicators_;}

template <class Fp>
GadgetPtr<Fp> LooseMUX_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                  const MultiPackedWordArray<Fp>& inputs,
                                  const Variable<Fp>& index,
                                  const VariableArray<Fp>& output,
                                  const Variable<Fp>& successFlag) {
    GadgetPtr<Fp> pGadget;
    if (pb->fieldType_ == R1P) {
        pGadget.reset(new R1P_LooseMUX_Gadget<Fp>(pb, inputs, index, output, successFlag));
    } else {
        GADGETLIB_FATAL("Attempted to create gadget of undefined Protoboard type.");
    }
    pGadget->init();
    return pGadget;
}

/**
    An overload for the private case in which we only want to multiplex one Variable. This is
    usually the case in R1P.
**/
template <class Fp>
GadgetPtr<Fp> LooseMUX_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                  const VariableArray<Fp>& inputs,
                                  const Variable<Fp>& index,
                                  const Variable<Fp>& output,
                                  const Variable<Fp>& successFlag) {
    MultiPackedWordArray<Fp> inpVec;
    for(size_t i = 0; i < inputs.size(); ++i) {
        MultiPackedWord<Fp> cur(pb->fieldType_);
        cur.push_back(inputs[i]);
        inpVec.push_back(cur);
    }
    VariableArray<Fp> outVec;
    outVec.push_back(output);
    auto result = LooseMUX_Gadget<Fp>::create(pb, inpVec, index, outVec, successFlag);
    return result;
}

/***********************************/
/***   End of LooseMUX Gadgets   ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************               CompressionPacking Gadgets                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
    Compression Packing gadgets have two modes, which differ in the way the witness and constraints
    are created. In PACK mode  gerateWitness() will take the bits and create a packed element (or
    number of elements) while generateConstraints() will not enforce that bits are indeed Boolean.
    In UNPACK mode generateWitness() will take the packed representation and unpack it to bits while
    generateConstraints will in addition enforce that unpacked bits are indeed Boolean.
*/

template <class Fp>
CompressionPacking_GadgetBase<Fp>::~CompressionPacking_GadgetBase() {};

/*
    Constraint breakdown:

    (1) packed = sum(unpacked[i] * 2^i)
    (2) (UNPACK only) unpacked[i] is Boolean.
*/

template <class Fp>
R1P_CompressionPacking_Gadget<Fp>::R1P_CompressionPacking_Gadget(ProtoboardPtr<Fp> pb,
                                                             const VariableArray<Fp>& unpacked,
                                                             const VariableArray<Fp>& packed,
                                                             PackingMode packingMode)
    : Gadget<Fp>(pb), CompressionPacking_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), packingMode_(packingMode),
      unpacked_(unpacked), packed_(packed) {
    const int n = unpacked.size();
    GADGETLIB_ASSERT(n > 0, "Attempted to pack 0 bits in R1P.")
    GADGETLIB_ASSERT(packed.size() == 1,
                 "Attempted to pack into more than 1 Variable<Fp> in R1P_CompressionPacking_Gadget.")
    // TODO add assertion that 'n' bits can fit in the field characteristic
}

template <class Fp>
void R1P_CompressionPacking_Gadget<Fp>::init() {}

template <class Fp>
void R1P_CompressionPacking_Gadget<Fp>::generateConstraints() {
    const int n = unpacked_.size();
    LinearCombination<Fp> packed;
    FElem<Fp> two_i(R1P_Elem<Fp>(1)); // Will hold 2^i
    for (int i = 0; i < n; ++i) {
        packed += unpacked_[i]*two_i;
        two_i += two_i;
        if (packingMode_ == PackingMode::UNPACK) {enforceBooleanity(unpacked_[i]);}
    }
    addRank1Constraint(packed_[0], 1, packed, "packed[0] = sum(2^i * unpacked[i])");
}

template <class Fp>
void R1P_CompressionPacking_Gadget<Fp>::generateWitness() {
    const int n = unpacked_.size();
    if (packingMode_ == PackingMode::PACK) {
        FElem<Fp> packedVal = 0;
        FElem<Fp> two_i(R1P_Elem<Fp>(1)); // will hold 2^i
        for(int i = 0; i < n; ++i) {
            GADGETLIB_ASSERT(val(unpacked_[i]).asLong() == 0 || val(unpacked_[i]).asLong() == 1,
                         GADGETLIB2_FMT("unpacked[%u]  = %u. Expected a Boolean value.", i,
                             val(unpacked_[i]).asLong()));
            packedVal += two_i * val(unpacked_[i]).asLong();
            two_i += two_i;
        }
        val(packed_[0]) = packedVal;
        return;
    }
    // else (UNPACK)
    GADGETLIB_ASSERT(packingMode_ == PackingMode::UNPACK, "Packing gadget created with unknown packing mode.");
    for(int i = 0; i < n; ++i) {
        val(unpacked_[i]) = val(packed_[0]).getBit(i, R1P);
    }
}

/*****************************************/
/*** End of CompressionPacking Gadgets ***/
/*****************************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                IntegerPacking Gadgets                   ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
    Arithmetic Packing gadgets have two modes, which differ in the way the witness and constraints
    are created. In PACK mode  gerateWitness() will take the bits and create a packed element (or
    number of elements) while generateConstraints() will not enforce that bits are indeed Boolean.
    In UNPACK mode generateWitness() will take the packed representation and unpack it to bits while
    generateConstraints will in addition enforce that unpacked bits are indeed Boolean.
*/

template <class Fp>
IntegerPacking_GadgetBase<Fp>::~IntegerPacking_GadgetBase() {};

/*
    Constraint breakdown:

    (1) packed = sum(unpacked[i] * 2^i)
    (2) (UNPACK only) unpacked[i] is Boolean.
*/

template <class Fp>
R1P_IntegerPacking_Gadget<Fp>::R1P_IntegerPacking_Gadget(ProtoboardPtr<Fp> pb,
                                                           const VariableArray<Fp>& unpacked,
                                                           const VariableArray<Fp>& packed,
                                                           PackingMode packingMode)
    : Gadget<Fp>(pb), IntegerPacking_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), packingMode_(packingMode),
      unpacked_(unpacked), packed_(packed) {
    const int n = unpacked.size();
    GADGETLIB_ASSERT(n > 0, "Attempted to pack 0 bits in R1P.")
    GADGETLIB_ASSERT(packed.size() == 1,
                 "Attempted to pack into more than 1 Variable<Fp> in R1P_IntegerPacking_Gadget.")
}

template <class Fp>
void R1P_IntegerPacking_Gadget<Fp>::init() {
    compressionPackingGadget_ = CompressionPacking_Gadget<Fp>::create(this->pb_, unpacked_, packed_,
                                                                  packingMode_);
}

template <class Fp>
void R1P_IntegerPacking_Gadget<Fp>::generateConstraints() {
    compressionPackingGadget_->generateConstraints();
}

template <class Fp>
void R1P_IntegerPacking_Gadget<Fp>::generateWitness() {
    compressionPackingGadget_->generateWitness();
}


/*****************************************/
/*** End of IntegerPacking Gadgets  ***/
/*****************************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 EqualsConst Gadgets                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
template <class Fp>
EqualsConst_GadgetBase<Fp>::~EqualsConst_GadgetBase() {};

/*
    Constraint breakdown:

    (1) (input - n) * result = 0
    (2) (input - n) * aux = 1 - result

    [ input == n ] (2)==> [result == 1]    (aux can ake any value)
    [ input != n ] (1)==> [result == 0]    (aux == inverse(input - n))
*/

template <class Fp>
R1P_EqualsConst_Gadget<Fp>::R1P_EqualsConst_Gadget(ProtoboardPtr<Fp> pb,
                                               const FElem<Fp>& n,
                                               const LinearCombination<Fp> &input,
                                               const Variable<Fp> &result)
        : Gadget<Fp>(pb), EqualsConst_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), n_(n),
          aux_("aux (R1P_EqualsConst_Gadget)"), input_(input), result_(result) {}

template <class Fp>
void R1P_EqualsConst_Gadget<Fp>::init() {}

template <class Fp>
void R1P_EqualsConst_Gadget<Fp>::generateConstraints() {
    addRank1Constraint(input_ - n_, result_, 0, "(input - n) * result = 0");
    addRank1Constraint(input_ - n_, aux_, 1 - result_, "(input - n) * aux = 1 - result");
}

template <class Fp>
void R1P_EqualsConst_Gadget<Fp>::generateWitness() {
    val(aux_) = val(input_) == n_ ? 0 : (val(input_) - n_).inverse(R1P) ;
    val(result_) = val(input_) == n_ ? 1 : 0 ;
}

/***********************************/
/*** End of EqualsConst Gadgets  ***/
/***********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                   DualWord_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

template <class Fp>
DualWord_Gadget<Fp>::DualWord_Gadget(ProtoboardPtr<Fp> pb,
                                         const DualWord<Fp>& var,
                                         PackingMode packingMode)
        : Gadget<Fp>(pb), var_(var), packingMode_(packingMode), packingGadget_() {}

template <class Fp>
void DualWord_Gadget<Fp>::init() {
    packingGadget_ = CompressionPacking_Gadget<Fp>::create(this->pb_, var_.unpacked(), var_.multipacked(),
                                                        packingMode_);
}

template <class Fp>
GadgetPtr<Fp> DualWord_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                      const DualWord<Fp>& var,
                                      PackingMode packingMode) {
    GadgetPtr<Fp> pGadget(new DualWord_Gadget<Fp>(pb, var, packingMode));
    pGadget->init();
    return pGadget;
}

template <class Fp>
void DualWord_Gadget<Fp>::generateConstraints() {
    packingGadget_->generateConstraints();
}

template <class Fp>
void DualWord_Gadget<Fp>::generateWitness() {
    packingGadget_->generateWitness();
}

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
template <class Fp>
DualWordArray_Gadget<Fp>::DualWordArray_Gadget(ProtoboardPtr<Fp> pb,
                                           const DualWordArray<Fp>& vars,
                                           PackingMode packingMode)
        : Gadget<Fp>(pb), vars_(vars), packingMode_(packingMode), packingGadgets_() {}

template <class Fp>
void DualWordArray_Gadget<Fp>::init() {
    const UnpackedWordArray<Fp> unpacked = vars_.unpacked();
    const MultiPackedWordArray<Fp> packed = vars_.multipacked();
    for(size_t i = 0; i < vars_.size(); ++i) {
        const auto curGadget = CompressionPacking_Gadget<Fp>::create(this->pb_, unpacked[i], packed[i],
                                                                 packingMode_);
        packingGadgets_.push_back(curGadget);
    }
}

template <class Fp>
GadgetPtr<Fp> DualWordArray_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                           const DualWordArray<Fp>& vars,
                                           PackingMode packingMode) {
    GadgetPtr<Fp> pGadget(new DualWordArray_Gadget<Fp>(pb, vars, packingMode));
    pGadget->init();
    return pGadget;
}

template <class Fp>
void DualWordArray_Gadget<Fp>::generateConstraints() {
    for(auto& gadget : packingGadgets_) {
        gadget->generateConstraints();
    }
}

template <class Fp>
void DualWordArray_Gadget<Fp>::generateWitness() {
    for(auto& gadget : packingGadgets_) {
        gadget->generateWitness();
    }
}

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

/*
    Constraint breakdown:

    (1) result = (1 - toggle) * zeroValue + toggle * oneValue
        (rank 1 format) ==> toggle * (oneValue - zeroValue) = result - zeroValue

*/

template <class Fp>
Toggle_Gadget<Fp>::Toggle_Gadget(ProtoboardPtr<Fp> pb,
                             const FlagVariable<Fp>& toggle,
                             const LinearCombination<Fp>& zeroValue,
                             const LinearCombination<Fp>& oneValue,
                             const Variable<Fp>& result)
        : Gadget<Fp>(pb), toggle_(toggle), zeroValue_(zeroValue), oneValue_(oneValue),
          result_(result) {}

template <class Fp>
GadgetPtr<Fp> Toggle_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                const FlagVariable<Fp>& toggle,
                                const LinearCombination<Fp>& zeroValue,
                                const LinearCombination<Fp>& oneValue,
                                const Variable<Fp>& result) {
    GadgetPtr<Fp> pGadget(new Toggle_Gadget<Fp>(pb, toggle, zeroValue, oneValue, result));
    pGadget->init();
    return pGadget;
}

template <class Fp>
void Toggle_Gadget<Fp>::generateConstraints() {
    this->pb_->addRank1Constraint(toggle_, oneValue_ - zeroValue_, result_ - zeroValue_,
                            "result = (1 - toggle) * zeroValue + toggle * oneValue");
}

template <class Fp>
void Toggle_Gadget<Fp>::generateWitness() {
    if (val(toggle_) == 0) {
        val(result_) = val(zeroValue_);
    } else if (val(toggle_) == 1) {
        val(result_) = val(oneValue_);
    } else {
        GADGETLIB_FATAL("Toggle value must be Boolean.");
    }
}


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

/*
    semantics: condition != 0 --> flag = 1
               condition == 0 --> flag = 0

    Constraint breakdown:
    (1) condition * not(flag) = 0
    (2) condition * auxConditionInverse = flag

 */

template <class Fp>
ConditionalFlag_Gadget<Fp>::ConditionalFlag_Gadget(ProtoboardPtr<Fp> pb,
                                               const LinearCombination<Fp>& condition,
                                               const FlagVariable<Fp>& flag)
        : Gadget<Fp>(pb), flag_(flag), condition_(condition),
          auxConditionInverse_("ConditionalFlag_Gadget<Fp>::auxConditionInverse_") {}

template <class Fp>
GadgetPtr<Fp> ConditionalFlag_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                         const LinearCombination<Fp>& condition,
                                         const FlagVariable<Fp>& flag) {
    GadgetPtr<Fp> pGadget(new ConditionalFlag_Gadget<Fp>(pb, condition, flag));
    pGadget->init();
    return pGadget;
}

template <class Fp>
void ConditionalFlag_Gadget<Fp>::generateConstraints() {
    this->pb_->addRank1Constraint(condition_, negate(flag_), 0, "condition * not(flag) = 0");
    this->pb_->addRank1Constraint(condition_, auxConditionInverse_, flag_,
                            "condition * auxConditionInverse = flag");
}

template <class Fp>
void ConditionalFlag_Gadget<Fp>::generateWitness() {
    if (val(condition_) == 0) {
        val(flag_) = 0;
        val(auxConditionInverse_) = 0;
    } else {
        val(flag_) = 1;
        val(auxConditionInverse_) = val(condition_).inverse(this->fieldType());
    }
}

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

/*
    semantics: condition == 1 --> flag = 1

    Constraint breakdown:
    (1) condition * (1 - flag) = 0

 */

template <class Fp>
LogicImplication_Gadget<Fp>::LogicImplication_Gadget(ProtoboardPtr<Fp> pb,
                                                 const LinearCombination<Fp>& condition,
                                                 const FlagVariable<Fp>& flag)
    : Gadget<Fp>(pb), flag_(flag), condition_(condition) {}

template <class Fp>
GadgetPtr<Fp> LogicImplication_Gadget<Fp>::create(ProtoboardPtr<Fp> pb,
                                          const LinearCombination<Fp>& condition,
                                          const FlagVariable<Fp>& flag) {
    GadgetPtr<Fp> pGadget(new LogicImplication_Gadget<Fp>(pb, condition, flag));
    pGadget->init();
    return pGadget;
}

template <class Fp>
void LogicImplication_Gadget<Fp>::generateConstraints() {
    this->pb_->addRank1Constraint(condition_, negate(flag_), 0, "condition * not(flag) = 0");
}

template <class Fp>
void LogicImplication_Gadget<Fp>::generateWitness() {
    if (val(condition_) == 1) {
        val(flag_) = 1;
    }
}

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

template <class Fp>
Comparison_GadgetBase<Fp>::~Comparison_GadgetBase() {}

template <class Fp>
R1P_Comparison_Gadget<Fp>::R1P_Comparison_Gadget(ProtoboardPtr<Fp> pb,
                                             const size_t& wordBitSize,
                                             const PackedWord<Fp>& lhs,
                                             const PackedWord<Fp>& rhs,
                                             const FlagVariable<Fp>& less,
                                             const FlagVariable<Fp>& lessOrEqual)
        : Gadget<Fp>(pb), Comparison_GadgetBase<Fp>(pb), R1P_Gadget<Fp>(pb), wordBitSize_(wordBitSize),
          lhs_(lhs), rhs_(rhs), less_(less), lessOrEqual_(lessOrEqual),
          alpha_u_(wordBitSize,  "alpha"), notAllZeroes_("notAllZeroes") {}

template <class Fp>
void R1P_Comparison_Gadget<Fp>::init() {
    allZeroesTest_ = OR_Gadget<Fp>::create(this->pb_, alpha_u_, notAllZeroes_);
	alpha_u_.emplace_back(lessOrEqual_);
	alphaDualVariablePacker_ = CompressionPacking_Gadget<Fp>::create(this->pb_, alpha_u_,VariableArray<Fp>(1,alpha_p_), PackingMode::UNPACK);
}
/*
    Constraint breakdown:

    for succinctness we shall define:
    (1) wordBitSize == n
    (2) lhs == A
    (3) rhs == B

    packed(alpha) = 2^n + B - A
    not_all_zeros = OR(alpha.unpacked)

    if B - A > 0, then: alpha > 2^n,
    so alpha[n] = 1 and notAllZeroes = 1
    if B - A = 0, then: alpha = 2^n,
    so alpha[n] = 1 and notAllZeroes = 0
    if B - A < 0, then: 0 <= alpha <= 2^n-1
    so alpha[n] = 0

    therefore:
    (1) alpha[n] = lessOrEqual
    (2) alpha[n] * notAllZeroes = less


*/
template <class Fp>
void R1P_Comparison_Gadget<Fp>::generateConstraints() {
    enforceBooleanity(notAllZeroes_);
    const FElem<Fp> two_n = long(POW2(wordBitSize_));
    addRank1Constraint(1, alpha_p_, two_n + rhs_ - lhs_,
							 "packed(alpha) = 2^n + B - A");
    alphaDualVariablePacker_->generateConstraints();
    allZeroesTest_->generateConstraints();
    addRank1Constraint(1, alpha_u_[wordBitSize_], lessOrEqual_, "alpha[n] = lessOrEqual");
    addRank1Constraint(alpha_u_[wordBitSize_], notAllZeroes_, less_,
                       "alpha[n] * notAllZeroes = less");
}

template <class Fp>
void R1P_Comparison_Gadget<Fp>::generateWitness() {
    const FElem<Fp> two_n = long(POW2(wordBitSize_));
    val(alpha_p_) = two_n + val(rhs_) - val(lhs_);
    alphaDualVariablePacker_->generateWitness();
    allZeroesTest_->generateWitness();
    val(lessOrEqual_) = val(alpha_u_[wordBitSize_]);
    val(less_) = val(lessOrEqual_) * val(notAllZeroes_);
}

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

} // namespace new_gadgetlib2
