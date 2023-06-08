/*
 * CircuitReader.cpp
 *
 *      Author: Ahmed Kosba
 */

//#include "CircuitReader.hpp"

template <class Fp>
CircuitReader<Fp>::CircuitReader(char* arithFilepath, char* inputsFilepath,
		ProtoboardPtr<Fp> pb) {

	this->pb = pb;
	numWires = 0;
	numInputs = numNizkInputs = numOutputs = 0;

	parseAndEval(arithFilepath, inputsFilepath);
	constructCircuit(arithFilepath);
	mapValuesToProtoboard();

	//Added by CorrAuthor - 12/28/2022 -------------
	char *mapFile = new char [strlen(inputsFilepath) + 16];
	sprintf(mapFile, "%s.varmap", inputsFilepath);
	FILE *fpath = fopen(mapFile, "w");
	for (WireMap::iterator iter = variableMap.begin();
			iter != variableMap.end(); ++iter) {
		Wire wireId = iter->first;
		unsigned int var_id = iter->second;
		fprintf(fpath, "%d\n", wireId);
		fprintf(fpath, "%d\n", var_id);
	}
	//Added Above ------------------

	wireLinearCombinations.clear();
	wireValues.clear();
	variables.clear();
	variableMap.clear();
	zeropMap.clear();
	zeroPwires.clear();
}

template <class Fp>
void CircuitReader<Fp>::parseAndEval(char* arithFilepath, char* inputsFilepath) {

	libff::enter_block("Parsing and Evaluating the circuit");

	ifstream arithfs(arithFilepath, ifstream::in);
	ifstream inputfs(inputsFilepath, ifstream::in);
	string line;

	if (!arithfs.good()) {
		printf("Unable to open circuit file %s \n", arithFilepath);
		exit(-1);
	}

	getline(arithfs, line);
	int ret = sscanf(line.c_str(), "total %u", &numWires);

	if (ret != 1) {
		printf("File Format Does not Match\n");
		exit(-1);
	}

	wireValues.resize(numWires);
	wireUseCounters.resize(numWires);
	wireLinearCombinations.resize(numWires);

	if (!inputfs.good()) {
		printf("Unable to open input file %s \n", inputsFilepath);
		exit(-1);
	} else {
		char* inputStr;
		while (getline(inputfs, line)) {
			if (line.length() == 0) {
				continue;
			}
			Wire wireId;
			inputStr = new char[line.size()];
			if (2 == sscanf(line.c_str(), "%u %s", &wireId, inputStr)) {
				wireValues[wireId] = readFieldElementFromHex<Fp>(inputStr);
			} else {
				printf("Error in Input\n");
				exit(-1);
			}
			delete[] inputStr;
		}
		inputfs.close();
	}

	if (wireValues[0] != Fp::one()) {
		printf(">> Warning: when using jsnark circuit generator, the first input wire (#0) must have the value of 1.\n");
		printf("\t If the circuit was generated using Pinocchio *without modification*, you can ignore this warning. Pinocchio uses a different indexing for the one-wire input. \n");
	}

	char type[200];
	char* inputStr;
	char* outputStr;
	unsigned int numGateInputs, numGateOutputs;

	Wire wireId;

	Fp oneElement = Fp::one();
	Fp zeroElement = Fp::zero();
	Fp negOneElement = Fp(-1);

	// long long evalTime;
	// long long begin, end;
	// evalTime = 0;

	// Parse the circuit: few lines were imported from Pinocchio's code.

	while (getline(arithfs, line)) {
		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];
		outputStr = new char[line.size()];

		if (line[0] == '#') {
			continue;
//Added by CorrAuthor -----------------
		}else if (1 == sscanf(line.c_str(), "num_segments %u", &num_segments)){
			seg_size = new unsigned int [num_segments];
			for(int i=0; i<num_segments; i++){
				getline(arithfs, line);
				sscanf(line.c_str(),"segment_size %u", &(seg_size[i]));
			}
			//at this moment: seg_size corresponds to the
			//number of WIRES in each segment
//Added by CorrAuthor ----------------- ABOVE
		} else if (1 == sscanf(line.c_str(), "input %u", &wireId)) {
			numInputs++;
			inputWireIds.push_back(wireId);
		} else if (1 == sscanf(line.c_str(), "nizkinput %u", &wireId)) {
			numNizkInputs++;
			nizkWireIds.push_back(wireId);
		} else if (1 == sscanf(line.c_str(), "output %u", &wireId)) {
			numOutputs++;
			outputWireIds.push_back(wireId);
			wireUseCounters[wireId]++;
		} else if (5
				== sscanf(line.c_str(), "%s in %u <%[^>]> out %u <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {

			istringstream iss_i(inputStr, istringstream::in);
			std::vector<Fp> inValues;
			std::vector<Wire> outWires;
			Wire inWireId;
			while (iss_i >> inWireId) {
				wireUseCounters[inWireId]++;
				inValues.push_back(wireValues[inWireId]);
			}
			readIds(outputStr, outWires);

			short opcode;
			Fp constant;
			if (strcmp(type, "add") == 0) {
				opcode = ADD_OPCODE;
			} else if (strcmp(type, "mul") == 0) {
				opcode = MUL_OPCODE;
			} else if (strcmp(type, "xor") == 0) {
				opcode = XOR_OPCODE;
			} else if (strcmp(type, "or") == 0) {
				opcode = OR_OPCODE;
			} else if (strcmp(type, "assert") == 0) {
				wireUseCounters[outWires[0]]++;
				opcode = CONSTRAINT_OPCODE;
			} else if (strcmp(type, "pack") == 0) {
				opcode = PACK_OPCODE;
			} else if (strcmp(type, "zerop") == 0) {
				opcode = NONZEROCHECK_OPCODE;
			} else if (strcmp(type, "split") == 0) {
				opcode = SPLIT_OPCODE;
			} else if (strstr(type, "const-mul-neg-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-neg-") - 1;
				constant = readFieldElementFromHex<Fp>(constStr) * negOneElement;
			} else if (strstr(type, "const-mul-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-") - 1;
				constant = readFieldElementFromHex<Fp>(constStr);
			} else {
				printf("Error: unrecognized line: %s\n", line.c_str());
				assert(0);
			}

			// TODO: separate evaluation from parsing completely to get accurate evaluation cost
			//	 Calling  libff::get_nsec_time(); repetitively as in the old version adds much overhead 
			// TODO 2: change circuit format to enable skipping some lines during evaluation
			//       Not all intermediate wire values need to be computed in this phase
			// TODO 3: change circuit format to make common constants defined once			
	
			//begin = libff::get_nsec_time();
			if (opcode == ADD_OPCODE) {
				Fp sum;
				for (auto &v : inValues)
					sum += v;
				wireValues[outWires[0]] = sum;
			} else if (opcode == MUL_OPCODE) {
				wireValues[outWires[0]] = inValues[0] * inValues[1];
			} else if (opcode == XOR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == inValues[1]) ? zeroElement : oneElement;
			} else if (opcode == OR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == zeroElement
								&& inValues[1] == zeroElement) ?
								zeroElement : oneElement;
			} else if (opcode == NONZEROCHECK_OPCODE) {
				wireValues[outWires[1]] =
						(inValues[0] == zeroElement) ? zeroElement : oneElement;
			} else if (opcode == PACK_OPCODE) {
				Fp sum, coeff;
				Fp two = oneElement;
				for (auto &v : inValues) {
					sum += two * v;
					two += two;
				}
				wireValues[outWires[0]] = sum;
			} else if (opcode == SPLIT_OPCODE) {
				int size = outWires.size();
				//FElem<Fp> inVal = inValues[0];
				FElem<Fp> inVal(inValues[0]);
				for (int i = 0; i < size; i++) {
					wireValues[outWires[i]] = inVal.getBit(i, R1P);
				}
			} else if (opcode == MULCONST_OPCODE) {
				wireValues[outWires[0]] = constant * inValues[0];
			}
			//end =  libff::get_nsec_time();
			//evalTime += (end - begin);
		} else {
			printf("Error: unrecognized line: %s\n", line.c_str());
			assert(0);
		}
		delete[] inputStr;
		delete[] outputStr;
	}
	arithfs.close();

	// printf("\t Evaluation Done in %lf seconds \n", (double) (evalTime) * 1e-9);
	 libff::leave_block("Parsing and Evaluating the circuit");
}

template <class Fp>
void CircuitReader<Fp>::constructCircuit(char* arithFilepath) {



	cout << "Translating Constraints ... " << endl;

	
	#ifndef NO_PROCPS
	struct proc_t usage1, usage2;
	look_up_our_self(&usage1);
        #endif
	

	unsigned int i;

	currentVariableIdx = currentLinearCombinationIdx = 0;
	for (i = 0; i < numInputs; i++) {
		variables.push_back(make_shared<Variable<Fp>>("input"));
		variableMap[inputWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}
	for (i = 0; i < numOutputs; i++) {
		variables.push_back(make_shared<Variable<Fp>>("output"));
		variableMap[outputWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}
	for (i = 0; i < numNizkInputs; i++) {
		variables.push_back(make_shared<Variable<Fp>>("nizk input"));
		variableMap[nizkWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}

	char type[200];
	char* inputStr;
	char* outputStr;
	string line;
	unsigned int numGateInputs, numGateOutputs;

	ifstream ifs2(arithFilepath, ifstream::in);

	if (!ifs2.good()) {
		printf("Unable to open circuit file:\n");
		exit(5);
	}

	// Parse the circuit: few lines were imported from Pinocchio's code.

	getline(ifs2, line);
	sscanf(line.c_str(), "total %d", &numWires);

	int lineCount = 0;
	while (getline(ifs2, line)) {
		lineCount++;
//		if (lineCount % 100000 == 0) {
//			printf("At Line:: %d\n", lineCount);
//		}

		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];
		outputStr = new char[line.size()];

		if (5
				== sscanf(line.c_str(), "%s in %d <%[^>]> out %d <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {
			if (strcmp(type, "add") == 0) {
				assert(numGateOutputs == 1);
				handleAddition(inputStr, outputStr);
			} else if (strcmp(type, "mul") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addMulConstraint(inputStr, outputStr);
			} else if (strcmp(type, "xor") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addXorConstraint(inputStr, outputStr);
			} else if (strcmp(type, "or") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addOrConstraint(inputStr, outputStr);
			} else if (strcmp(type, "assert") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addAssertionConstraint(inputStr, outputStr);
			} else if (strstr(type, "const-mul-neg-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulNegConst(type, inputStr, outputStr);
			} else if (strstr(type, "const-mul-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulConst(type, inputStr, outputStr);
			} else if (strcmp(type, "zerop") == 0) {
				assert(numGateInputs == 1 && numGateOutputs == 2);
				addNonzeroCheckConstraint(inputStr, outputStr);
			} else if (strstr(type, "split")) {
				assert(numGateInputs == 1);
				int debug = 0;
				addSplitConstraint(inputStr, outputStr, numGateOutputs, debug);
			} else if (strstr(type, "pack")) {
				assert(numGateOutputs == 1);
				// addPackConstraint(inputStr, outputStr, numGateInputs);
				handlePackOperation(inputStr, outputStr, numGateInputs);

			}
		} else {
//			assert(0);
		}
		delete[] inputStr;
		delete[] outputStr;
		clean();
	}

	ifs2.close();

	printf("\tConstraint translation done\n");


	
	#ifndef NO_PROCPS
	look_up_our_self(&usage2);
	unsigned long diff = usage2.vsize - usage1.vsize;
	printf("\tMemory usage for constraint translation: %lu MB\n", diff >> 20);
        #endif

	//ADDED by CorrAuthor ---------------------
	//We make final adjustment of segment_size here
	//We assume that ALL intermediate wires generated from gate operations
	//are in the LAST segment (all witness wires are split into segments)
	//thus, we just need to adjust the LAST segment size as
	//they have NEW intermediate wires but the NIZK prover witness numbers
	//do not change, each of them is mapped into a separate variable in
	//R1CS
	int total_used = 0;
	total_used += numInputs + numOutputs;
	for(int i=0; i<num_segments-1; i++){
		total_used += seg_size[i]; 
	}
	int left = currentVariableIdx - total_used;
	seg_size[num_segments-1] = left; 
	//Added by CorrAuthor ----------------------
        
}

template <class Fp>
void CircuitReader<Fp>::mapValuesToProtoboard() {

	int zeropGateIndex = 0;
	for (WireMap::iterator iter = variableMap.begin();
			iter != variableMap.end(); ++iter) {
		Wire wireId = iter->first;
		pb->val(*variables[variableMap[wireId]]) = wireValues[wireId];
		if (zeropMap.find(wireId) != zeropMap.end()) {
			LinearCombination<Fp> l = *zeroPwires[zeropGateIndex++];
			if (pb->val(l) == Fp::zero()) {
				pb->val(*variables[zeropMap[wireId]]) = Fp::zero();
			} else {
				pb->val(*variables[zeropMap[wireId]]) = pb->val(l).inverse(
						pb->fieldType_);
			}
		}
	}
	if (!pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED)) {
		printf("Note: Protoboard Not Satisfied .. \n");
		// assert(false);
	}
	printf("Assignment of values done .. \n");

}

template <class Fp>
void CircuitReader<Fp>::find(Wire wireId, LinearCombinationPtr<Fp>& lc,
		bool intentionToEdit) {

	if (!wireLinearCombinations[wireId]){
		wireLinearCombinations[wireId] = make_shared<LinearCombination<Fp>>(
				LinearCombination<Fp>(*variables[variableMap[wireId]]));
	}
	wireUseCounters[wireId]--;
	if (wireUseCounters[wireId] == 0) {
		toClean.push_back(wireId);
		lc = wireLinearCombinations[wireId];
	} else {
		if (intentionToEdit) {
			lc = make_shared<LinearCombination<Fp>>(*wireLinearCombinations[wireId]);
		} else {
			lc = wireLinearCombinations[wireId];
		}
	}
}



template <class Fp>
void CircuitReader<Fp>::clean() {

	for (Wire wireId : toClean) {
		wireLinearCombinations[wireId].reset();
	}
	toClean.clear();
}

template <class Fp>
void CircuitReader<Fp>::addMulConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr<Fp> l1, l2;
	find(inWireId1, l1);
	find(inWireId2, l2);

	if (variableMap.find(outputWireId) == variableMap.end()) {
		variables.push_back(make_shared<Variable<Fp>>("mul out"));
		variableMap[outputWireId] = currentVariableIdx;
		pb->addRank1Constraint(*l1, *l2, *variables[currentVariableIdx],
				"Mul ..");
		currentVariableIdx++;
	} else {
		pb->addRank1Constraint(*l1, *l2, *variables[variableMap[outputWireId]],
				"Mul ..");
	}
}

template <class Fp>
void CircuitReader<Fp>::addXorConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr<Fp> lp1, lp2;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	LinearCombination<Fp> l1, l2;
	l1 = *lp1;
	l2 = *lp2;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		variables.push_back(make_shared<Variable<Fp>>("xor out"));
		variableMap[outputWireId] = currentVariableIdx;
		pb->addRank1Constraint(2 * l1, l2,
				l1 + l2 - *variables[currentVariableIdx], "XOR ..");
		currentVariableIdx++;
	} else {
		pb->addRank1Constraint(2 * l1, l2,
				l1 + l2 - *variables[variableMap[outputWireId]], "XOR ..");
	}
}

template <class Fp>
void CircuitReader<Fp>::addOrConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr<Fp> lp1, lp2;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	LinearCombination<Fp> l1, l2;
	l1 = *lp1;
	l2 = *lp2;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		variables.push_back(make_shared<Variable<Fp>>("or out"));
		variableMap[outputWireId] = currentVariableIdx;
		pb->addRank1Constraint(l1, l2, l1 + l2 - *variables[currentVariableIdx],
				"OR ..");
		currentVariableIdx++;
	} else {
		pb->addRank1Constraint(l1, l2,
				l1 + l2 - *variables[variableMap[outputWireId]], "OR ..");
	}
}

template <class Fp>
void CircuitReader<Fp>::addAssertionConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr<Fp> lp1, lp2, lp3;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	find(outputWireId, lp3);

	LinearCombination<Fp> l1, l2, l3;
	l1 = *lp1;
	l2 = *lp2;
	l3 = *lp3;
	pb->addRank1Constraint(l1, l2, l3, "Assertion ..");

}

template <class Fp>
void CircuitReader<Fp>::addSplitConstraint(char* inputStr, char* outputStr,
		unsigned short n, int debug) {

	Wire inWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	LinearCombinationPtr<Fp> l;
	find(inWireId, l);
	istringstream iss_o(outputStr, istringstream::in);

	LinearCombination<Fp> sum;
	FElem<Fp> two_i = Fp("1");


	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_o >> bitWireId;
		VariablePtr<Fp> vptr;
		if (variableMap.find(bitWireId) == variableMap.end()) {
			variables.push_back(make_shared<Variable<Fp>>("bit out"));
			variableMap[bitWireId] = currentVariableIdx;
			vptr = variables[currentVariableIdx];
			currentVariableIdx++;
		} else {
			vptr = variables[variableMap[bitWireId]];
		}
		pb->enforceBooleanity(*vptr);
		LinearTerm<Fp> term = LinearTerm<Fp>(*vptr, two_i);
		sum += term;
		two_i += two_i;
	}

	pb->addRank1Constraint(*l, 1, sum, "Split Constraint");
}

/*
template <class Fp>
void CircuitReader<Fp>::addPackConstraint(char* inputStr, char* outputStr,
		unsigned short n) {

	Wire outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	istringstream iss_i(inputStr, istringstream::in);
	LinearCombination<Fp> sum;
	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_i >> bitWireId;
		LinearCombinationPtr<Fp> l;
		find(bitWireId, l);
		sum += two_i * (*l);
		two_i += two_i;
	}

	VariablePtr<Fp> vptr;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		variables.push_back(make_shared<Variable<Fp>>("pack out"));
		variableMap[outputWireId] = currentVariableIdx;
		vptr = variables[currentVariableIdx];
		currentVariableIdx++;
	} else {

		vptr = variables[variableMap[outputWireId]];
	}

	pb->addRank1Constraint(*vptr, 1, sum, "Pack Constraint");

}
*/

template <class Fp>
void CircuitReader<Fp>::addNonzeroCheckConstraint(char* inputStr, char* outputStr) {

	Variable<Fp> auxConditionInverse_;
	Wire outputWireId, inWireId;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	iss_o >> outputWireId;
	LinearCombinationPtr<Fp> l;

	find(inWireId, l);
	VariablePtr<Fp> vptr;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		variables.push_back(make_shared<Variable<Fp>>("zerop out"));
		variableMap[outputWireId] = currentVariableIdx;
		vptr = variables[currentVariableIdx];
		currentVariableIdx++;
	} else {
		vptr = variables[variableMap[outputWireId]];
	}
	variables.push_back(make_shared<Variable<Fp>>("zerop aux"));
	pb->addRank1Constraint(*l, 1 - *vptr, 0, "condition * not(output) = 0");
	pb->addRank1Constraint(*l, *variables[currentVariableIdx], *vptr,
			"condition * auxConditionInverse = output");

	zeroPwires.push_back(make_shared<LinearCombination<Fp>>(*l));
	zeropMap[outputWireId] = currentVariableIdx;
	currentVariableIdx++;

}


template <class Fp>
void CircuitReader<Fp>::handlePackOperation(char* inputStr, char* outputStr, unsigned short n){

	Wire outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	if (variableMap.find(outputWireId) != variableMap.end()) {
		printf("An output of a pack operation was either defined before, or is declared directly as circuit output. Non-compliant Circuit.\n");
                printf("\t If the second, the wire has to be multiplied by a wire the has the value of 1 first (input #0 in circuits generated by jsnark) . \n");
		exit(-1);
	}


	istringstream iss_i(inputStr, istringstream::in);
	LinearCombinationPtr<Fp> sum;
	Wire bitWireId;
	iss_i >> bitWireId;
	find(bitWireId, sum, true);	       
	FElem<Fp> two_i = Fp("1");
	for (int i = 1; i < n; i++) {
		iss_i >> bitWireId;
		LinearCombinationPtr<Fp> l;
		find(bitWireId, l);
		two_i += two_i;
		*sum += two_i * (*l);

	}
	wireLinearCombinations[outputWireId] = sum;
}

template <class Fp>
void CircuitReader<Fp>::handleAddition(char* inputStr, char* outputStr) {

	Wire inWireId, outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	if (variableMap.find(outputWireId) != variableMap.end()) {
		printf("An output of an add operation was either defined before, or is declared directly as circuit output. Non-compliant Circuit.\n");
                printf("\t If the second, the wire has to be multiplied by a wire the has the value of 1 first (input #0 in circuits generated by jsnark) . \n");
		exit(-1);
	}

	istringstream iss_i(inputStr, istringstream::in);
	LinearCombinationPtr<Fp> s, l;
	iss_i >> inWireId;
	find(inWireId, l, true);
	s = l;
	while (iss_i >> inWireId) {
		find(inWireId, l);
		*s += *l;
	}
	wireLinearCombinations[outputWireId] = s;
}

template <class Fp>
void CircuitReader<Fp>::handleMulConst(char* type, char* inputStr,
		char* outputStr) {

	char* constStr = type + sizeof("const-mul-") - 1;
	Wire outputWireId, inWireId;

	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	if (variableMap.find(outputWireId) != variableMap.end()) {
		printf("An output of a const-mul operation was either defined before, or is declared directly as a circuit output. Non-compliant Circuit.\n");
                printf("\t If the second, the wire has to be multiplied by a wire the has the value of 1 first (input #0 in circuits generated by jsnark) . \n");
		exit(-1);
	}

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;
	LinearCombinationPtr<Fp> l;
	find(inWireId, l, true);
	wireLinearCombinations[outputWireId] = l;
	*(wireLinearCombinations[outputWireId]) *= readFieldElementFromHex<Fp>(
			constStr);
}

template <class Fp>
void CircuitReader<Fp>::handleMulNegConst(char* type, char* inputStr,
		char* outputStr) {

	char* constStr = type + sizeof("const-mul-neg-") - 1;
	Wire outputWireId, inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	if (variableMap.find(outputWireId) != variableMap.end()) {
		printf("An output of a const-mul-neg operation was either defined before, or is declared directly as circuit output. Non-compliant Circuit.\n");
                printf("\t If the second, the wire has to be multiplied by a wire the has the value of 1 first (input #0 in circuits generated by jsnark) . \n");
		exit(-1);
	}

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	LinearCombinationPtr<Fp> l;
	find(inWireId, l, true);

	wireLinearCombinations[outputWireId] = l;
	*(wireLinearCombinations[outputWireId]) *= readFieldElementFromHex<Fp>(
			constStr);
	*(wireLinearCombinations[outputWireId]) *= Fp(-1); //TODO: make shared Fp constants
}
