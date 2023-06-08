/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS ppzkSNARK for
 a given R1CS example.

 See run_r1cs_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_PPZKSNARK_TCC_
#define RUN_R1CS_PPZKSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <sys/time.h>

namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS ppzkSNARK Affine Verifier");
    const bool answer = r1cs_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::UNUSED(vk, primary_input, proof, expected_answer);
    libff::print_header("R1CS ppzkSNARK Affine Verifier");
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_ppzksnark");

    libff::print_header("R1CS ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS ppzkSNARK Prover");
    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS ppzkSNARK Verifier");
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_ppzksnark");

    return ans;
}

//----------------------------------------------------------------
// --- The following Added by CorrAuthor to profile performance ---
//----------------------------------------------------------------
// get the data usage of the current process
long int mem_usage(){
  unsigned long size;
  unsigned long dummy;
  std::string s_ignore;
  std::ifstream ifs("/proc/self/stat", std::ios_base::in);
  for(int i=0; i<22; i++){ifs>>s_ignore;} //ignore first 22 words
  ifs>>size;
  return size;
}

class PerfData{
	public:
		PerfData(){};
		//start time ticking and memory measurement
		void start(){	
			gettimeofday(&this->start_time, NULL);
			this->mem1 = mem_usage();
		}

		//end time ticking and memory measurement
		void stop(){
				gettimeofday(&this->stop_time, NULL);
				this->time_ms = (stop_time.tv_sec - start_time.tv_sec) * 1000 + (stop_time.tv_usec - start_time.tv_usec)/1000; //in milliseconds
				this->mem2 = mem_usage();
				this->space = mem1<mem2? mem2-mem1: 0;
		}
		string to_json(){
			string s1 = string("{\"time_ms\": ") + to_string((long long int)time_ms) + ", \"space\": " +  to_string((long long int)space) + "}";
			return s1;
		}
	
	protected:
		

	public:
		long int time_ms; //running time in milli-second
		long int space; //memory consumption of process (measured by OS)

	private:
		struct timeval stop_time, start_time;
		long int mem1, mem2; //mem usage
};

class CircuitPerfData{
	public:
		CircuitPerfData(PerfData *setup_data, PerfData *proof_gen_data, PerfData *verify_data, long int crs_size, long int proof_size, long int num_r1cs, bool b_success, string s_err){
			this->setup_data = setup_data;
			this->proof_gen_data = proof_gen_data;
			this->verify_data = verify_data;
			this->crs_size = crs_size;
			this->proof_size = proof_size;
			this->num_r1cs = num_r1cs;
			this->b_success = b_success;
			this->s_error = s_err;
			this->count = 1;
		}
		~CircuitPerfData(){
			delete setup_data;
			delete proof_gen_data;
			delete verify_data;
		}
		string to_json(){
			string bSuccess = b_success? "true": "false";
			string s1 = string("{\"setup_data\":") + setup_data->to_json() + \
				string(", \"proof_gen_data\": ") + proof_gen_data->to_json() + \
				string(", \"verify_data\": ") + verify_data->to_json() + \
				string(", \"crs_size\": ") + to_string((long long int) crs_size) +\
				string(", \"proof_size\": ") + to_string((long long int) proof_size) +\
				string(", \"num_r1cs\": ") + to_string((long long int) num_r1cs) +\
				string(", \"b_success\": ") + bSuccess + \
				string(", \"s_error\": \"") + s_error + string("\"") +\
				string(", \"count\": ") + to_string(count)  +\
				string("}");
			return s1;
		}
		// write the jason to a file in ../../jsondata 
		void write_json_to(char *caseid){
			char path[2048];
			snprintf(path, 2048, "jsondata/file_%s.txt", caseid);	
			string json = this->to_json();
			std::ofstream out(path);
		    out << json;
		    out.close();
		}
	
	protected:
		PerfData *setup_data;
		PerfData *proof_gen_data;
		PerfData *verify_data;
		long int crs_size; //default 0, used for common reference string size
		long int proof_size; //size of proof
		long int num_r1cs; //number of constraints
		bool b_success;
		string s_error; //cause of exception
		int count = 1; //by default always = 1
};

template<typename ppT>
bool run_r1cs_ppzksnark_profile(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization, char *case_id)
{
	int num_constraints = example.constraint_system.num_constraints();
	PerfData* pd_setup = new PerfData();
	pd_setup->start();
    libff::enter_block("Call to run_r1cs_ppzksnark");
    libff::print_header("R1CS ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
	int crs_size = keypair.pk.size_in_bits()/8;

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }
	pd_setup->stop();

    libff::print_header("R1CS ppzkSNARK Prover");
	PerfData* pd_proof = new PerfData();
	pd_proof->start();
    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
	int proof_size = proof.size_in_bits()/8; 
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }
	pd_proof->stop();

    libff::print_header("R1CS ppzkSNARK Verifier");
	PerfData *pd_verify= new PerfData();
	pd_verify->start();
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_ppzksnark");
	pd_verify->stop();
	CircuitPerfData *c1 = new CircuitPerfData(pd_setup, pd_proof, pd_verify, 
		crs_size, proof_size, num_constraints, true, "");
	c1->write_json_to(case_id);

    return ans;
}
//---- The above added by CorrAuthor to profile performance ---

} // libsnark

#endif // RUN_R1CS_PPZKSNARK_TCC_
