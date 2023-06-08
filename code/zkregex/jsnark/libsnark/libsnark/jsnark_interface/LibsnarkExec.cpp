/* Modified from 
 * run_ppzksnark.cpp
 * Added processing time bench mark and only process one case
 * Author: CorrAuthor
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

#define BUFSIZE 8192 
#define CIRC_DIR "dependency/jsnark/JsnarkCircuitBuilder/circuits"

int main(int argc, char **argv) {
	//1. get the arguments
	if(argc!=4){
		printf("USAGE: ./LibsnarlExec Driver_Name Circ_Name Case_ID\n");
		exit(1);
	}
	char *circ_name = argv[2];
	char *case_id = argv[3];
	char arith_file [BUFSIZE];
	char in_file [BUFSIZE];
	snprintf(arith_file, BUFSIZE, "%s/%s.arith.LIBSNARK", CIRC_DIR, circ_name);
	snprintf(in_file, BUFSIZE, "%s/%s.in.LIBSNARK", CIRC_DIR, circ_name);

	//2. prepare the circuits
	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	// Read the circuit, evaluate, and translate constraints
	//CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	CircuitReader reader(arith_file, in_file, pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}
	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	const bool test_serialization = false;

	//3. build and run
	bool successBit = libsnark::run_r1cs_ppzksnark_profile<libff::default_ec_pp>(example, test_serialization, case_id);

	return 0;
}

