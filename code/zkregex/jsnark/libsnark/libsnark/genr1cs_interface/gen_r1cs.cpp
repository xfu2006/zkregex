/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */
//-------------------------------------------
//Mods by CorrAuthor
//Idea: modify gadgetlib2 so that it's templated by the prime field
//-------------------------------------------

#include "CircuitReader.hpp"

// The call of bn128_init is needed; otherwise the
// bn128 prime group will not work (depending on global variable).
// but this is only applied to bn128 prime field. Others are not affected.
void system_init(){
	libff::bn128_modulus_r = bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617");
}

// the "extra" suffix (filedname) is appended to r1cs_filename
// NOTE: the function is templated by the prime field type
template<class Fp>
void genr1cs(char *arithfile, char *infile, char *r1cs_filename, char *fieldname){
	//1. initilization for the Fp class
	Fp::quick_init_for_gen_r1cs();

	//2. processing and write to r1cs_filename + extra_suffix
	libff::start_profiling();

	new_gadgetlib2::GadgetLibAdapter<Fp>::resetVariableIndex();
	ProtoboardPtr<Fp> pb = new_gadgetlib2::Protoboard<Fp>::create(new_gadgetlib2::R1P);

	// Read the circuit, evaluate, and translate constraints
	CircuitReader<Fp> reader(arithfile, infile, pb);

	r1cs_constraint_system<Fp> cs = get_constraint_system_from_new_gadgetlib2<Fp>(
			*pb);
	const r1cs_variable_assignment<Fp> full_assignment =
			get_variable_assignment_from_new_gadgetlib2<Fp>(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<Fp> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<Fp> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());

	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;

		exit(100);
	}

	printf("DEBUG USE 102: call dump()\n");
	FILE *dumpfile = fopen(r1cs_filename, "w");
	cs.save_to(dumpfile, primary_input, auxiliary_input, reader.num_segments, reader.seg_size);
	fflush(dumpfile);
	fclose(dumpfile);

}

/** 
 Expecting: arithfile, infile, r1csfilepath, primefieldname
 Supported prime filed names:
 (1) LIBSNARK (bn128 size)
 (2) SPARTAN (curve25519)
*/

int main(int argc, char **argv) {

	//1. parameter checking
	system_init();
	if(argc != 5){
		printf("Usage: genr1cs arithfilepath infilepath ricsfilepath primefieldname\n");
		exit(1);
	} 	
	char *arithfile = argv[1];
	char *infile = argv[2];
	char *r1cs_filename = argv[3];
	char *pname = argv[4];

	//2. Depending on platform name call the corresponding functions
	if(strcmp(pname, "LIBSNARK")==0){
		genr1cs<FieldT_Default>(arithfile, infile, r1cs_filename, pname);
	}else if(strcmp(pname, "SPARTAN")==0){
		genr1cs<FieldT_Spartan>(arithfile, infile, r1cs_filename, pname);
	}else if(strcmp(pname, "AURORA")==0){
		genr1cs<FieldT_Aurora>(arithfile, infile, r1cs_filename, pname);
	}else if(strcmp(pname, "Bls381")==0){
		genr1cs<FieldT_Bls381>(arithfile, infile, r1cs_filename, pname);
	}else{
		printf("Libsnark: Unsupported prime field name: %s\n", pname);
		exit(200);
	}
	return 0;
}

