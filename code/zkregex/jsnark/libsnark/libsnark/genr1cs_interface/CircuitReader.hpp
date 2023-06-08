/*
 * CircuitReader.hpp
 *
 *      Author: Ahmed Kosba
 */

#include "Util.hpp"
#include <libsnark/new_gadgetlib2/integration.hpp>
#include <libsnark/new_gadgetlib2/adapters.hpp>
#include <libff/common/profiling.hpp>


#include <memory.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <ctime>

#include <termios.h>
#include <unistd.h>
#include <stdio.h>


#ifndef NO_PROCPS
#include <proc/readproc.h>
#endif


using namespace libsnark;
using namespace new_gadgetlib2;
using namespace std;

typedef unsigned int Wire;

//MODS by CorrAuthor
//REMOVED THE DEPENDENCE ON EC_PP (default bn128 curve)
//TAKES  a prime field
//! WE DO NOT RELY ON CURVE PAIRING FOR ZK-PROOF
//! JUST GENERATE THE R1CS using basic prime field arithmetics

template <class Fp>
//typedef ::std::shared_ptr<LinearCombination<Fp>> LinearCombinationPtr;
using LinearCombinationPtr = ::std::shared_ptr<LinearCombination<Fp>>;
typedef ::std::map<Wire, unsigned int> WireMap;

#define ADD_OPCODE 1
#define MUL_OPCODE 2
#define SPLIT_OPCODE 3
#define NONZEROCHECK_OPCODE 4
#define PACK_OPCODE 5
#define MULCONST_OPCODE 6
#define XOR_OPCODE 7
#define OR_OPCODE 8
#define CONSTRAINT_OPCODE 9

template <class Fp>
class CircuitReader {
public:
	CircuitReader(char* arithFilepath, char* inputsFilepath, ProtoboardPtr<Fp> pb);

	int getNumInputs() { return numInputs;}
	int getNumOutputs() { return numOutputs;}
	std::vector<Wire> getInputWireIds() const { return inputWireIds; }
	std::vector<Wire> getOutputWireIds() const { return outputWireIds; }

//ADDED BY XIANG FU --
	unsigned int num_segments;  //number of variables in each segment
	unsigned int *seg_size = NULL; 
//Added by CorrAuthor Above


private:
	ProtoboardPtr<Fp> pb;

	std::vector<VariablePtr<Fp>> variables;
	std::vector<LinearCombinationPtr<Fp>> wireLinearCombinations;
	std::vector<LinearCombinationPtr<Fp>> zeroPwires;

	WireMap variableMap;
	WireMap zeropMap;

	std::vector<unsigned int> wireUseCounters;
	std::vector<Fp> wireValues;

	std::vector<Wire> toClean;

	std::vector<Wire> inputWireIds;
	std::vector<Wire> nizkWireIds;
	std::vector<Wire> outputWireIds;

	unsigned int numWires;
	unsigned int numInputs, numNizkInputs, numOutputs;

	unsigned int currentVariableIdx, currentLinearCombinationIdx;
	void parseAndEval(char* arithFilepath, char* inputsFilepath);
	void constructCircuit(char*);  // Second Pass:
	void mapValuesToProtoboard();

	void find(unsigned int, LinearCombinationPtr<Fp>&, bool intentionToEdit = false);
	void clean();

	void addMulConstraint(char*, char*);
	void addXorConstraint(char*, char*);

	void addOrConstraint(char*, char*);
	void addAssertionConstraint(char*, char*);

	void addSplitConstraint(char*, char*, unsigned short, int debug);
	// void addPackConstraint(char*, char*, unsigned short);
	void addNonzeroCheckConstraint(char*, char*);

	void handleAddition(char*, char*);
	void handlePackOperation(char*, char*, unsigned short);
	void handleMulConst(char*, char*, char*);
	void handleMulNegConst(char*, char*, char*);

};

#include <libsnark/genr1cs_interface/CircuitReader.tcc>
