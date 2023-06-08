/** Efficient Zero Knowledge Project
	Wrapper of the Standard DIZK Prover and Verifier.
	We hide the details of CRS/prover/verifier key inside the object.
	Author: Dr. CorrAuthor
	Created: 06/10/2022
*/ 

package cs.Employer.dizk_driver.standard;

import cs.Employer.ac.AC;
import java.util.HashSet;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Arrays;
import cs.Employer.dizk_driver.*;
import cs.Employer.zkregex.Tools;
import cs.Employer.acc_driver.AccDriver;

import algebra.curves.barreto_naehrig.BNFields.*;
import algebra.curves.barreto_naehrig.*;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNG1Parameters;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNG2Parameters;
import algebra.curves.barreto_naehrig.abstract_bn_parameters.AbstractBNGTParameters;
import algebra.curves.barreto_naehrig.bn254a.BN254aFields.BN254aFr;
import algebra.curves.barreto_naehrig.bn254a.BN254aG1;
import algebra.curves.barreto_naehrig.bn254a.BN254aG2;
import algebra.curves.barreto_naehrig.bn254a.BN254aPairing;
import algebra.curves.barreto_naehrig.bn254a.bn254a_parameters.BN254aG1Parameters;
import algebra.curves.barreto_naehrig.bn254a.bn254a_parameters.BN254aG2Parameters;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.storage.StorageLevel;
import profiler.generation.R1CSConstruction;
import relations.objects.Assignment;
import relations.r1cs.R1CSRelationRDD;
import configuration.Configuration;
import scala.Tuple3;
import zk_proof_systems.zkSNARK.objects.CRS;
import zk_proof_systems.zkSNARK.objects.Proof;
import zk_proof_systems.zkSNARK.DistributedSetup;
import zk_proof_systems.zkSNARK.DistributedProver;
import zk_proof_systems.zkSNARK.Verifier;

import za_interface.za.circs.zkreg.ZaTraceVerifier;
import za_interface.za.circs.basicops.*;
import za_interface.za.Utils;
import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.PrimeFieldInfo;
import za_interface.za.ZaGenerator;
import java.util.ArrayList;
import java.util.Random;
import circuit.structure.CircuitGenerator;


/** standard DIZK prover and verifier wrapper
*/
public class StandardDizkDriver 
			<BNFrT extends BNFr<BNFrT>,
            BNFqT extends BNFq<BNFqT>,
            BNFq2T extends BNFq2<BNFqT, BNFq2T>,
            BNFq6T extends BNFq6<BNFqT, BNFq2T, BNFq6T>,
            BNFq12T extends BNFq12<BNFqT, BNFq2T, BNFq6T, BNFq12T>,
            BNG1T extends BNG1<BNFrT, BNFqT, BNG1T, BNG1ParametersT>,
            BNG2T extends BNG2<BNFrT, BNFqT, BNFq2T, BNG2T, BNG2ParametersT>,
            BNGTT extends BNGT<BNFqT, BNFq2T, BNFq6T, BNFq12T, BNGTT, BNGTParametersT>,
            BNG1ParametersT extends AbstractBNG1Parameters<BNFrT, BNFqT, BNG1T, BNG1ParametersT>,
            BNG2ParametersT extends AbstractBNG2Parameters<BNFrT, BNFqT, BNFq2T, BNG2T, BNG2ParametersT>,
            BNGTParametersT extends AbstractBNGTParameters<BNFqT, BNFq2T, BNFq6T, BNFq12T, BNGTT, BNGTParametersT>,
            BNPublicParametersT extends BNPublicParameters<BNFqT, BNFq2T, BNFq6T, BNFq12T>,
            BNPairingT extends BNPairing<BNFrT, BNFqT, BNFq2T, BNFq6T, BNFq12T, BNG1T, BNG2T, BNGTT, BNG1ParametersT, BNG2ParametersT, BNGTParametersT, BNPublicParametersT>>
implements DizkDriverInterface{
	// ---------------------------------------
	// *** DATA MEMBERS ***
	// ---------------------------------------
	protected BNFrT fieldFactory;
	protected BNG1T g1Factory;
	protected BNG2T g2Factory;
	protected BNPairingT pairing;
	protected Configuration config;

	// common reference string. Will be set up in prove for verify use	
	protected CRS<BNFrT, BNG1T, BNG2T, BNGTT> crs  = null;
	// r1cs relation
    protected R1CSRelationRDD<BNFrT> r1cs = null;
	// assignment of PRIMARY (public input/output)
    protected Assignment<BNFrT> primary = null;
	// assignment of ALL variables
    protected JavaPairRDD<Long, BNFrT> fullAssignment = null;

	/** set of states and transitions */
	protected BigInteger [] arr_st; 
	// ---------------------------------------
	// *** OPERATIONS ***
	// ---------------------------------------
	/** Constructor. Feed group/field factory elements.
	The config is for controlliing system setup of DIZK
	 */
	public StandardDizkDriver(BNFrT fieldFactory, BNG1T g1Factory, BNG2T g2Factory, BNPairing paring, Configuration config){
		this.fieldFactory = fieldFactory;
		this.g1Factory = g1Factory;
		this.g2Factory = g2Factory;
		this.pairing = pairing;
		this.config = config;
		// STRANGELY has to to do this. FIGURE IT OUT LATER
		// there must be some template inferring error in Java
		// pairing input is always NULL.
		this.pairing = (BNPairingT) new BN254aPairing(); 
	}

	/** return the set of states and transitions */
	public BigInteger [] get_st(){
		return arr_st;
	}
	/** prove the given regex statement. The list of transitions is
		given in arrTrans */
	public DizkProofInterface prove(AC ac, ArrayList<AC.Transition> arrTrans, 
		BigInteger r1, BigInteger r2){
		Tuple3<R1CSRelationRDD<BNFrT>, Assignment<BNFrT>, JavaPairRDD<Long,BNFrT>> construction = this.genR1CS(ac, arrTrans, r1, r2);

        this.r1cs = construction._1();
        this.primary = construction._2();
        this.fullAssignment = construction._3();
	
		System.out.println("=======**** \n DEBUG USE 112: before calling DistributedSetup.generate pairing is: " + pairing + " =========*****\n");	
		this.crs = DistributedSetup.generate(r1cs, fieldFactory, g1Factory, g2Factory, pairing, config);

		//4. prover R1CS
		Proof proof = DistributedProver.prove(
			crs.provingKeyRDD(), primary, fullAssignment, fieldFactory, config);
		StandardDizkProof prf_ret = new StandardDizkProof(proof);
		return prf_ret;
	}

	/** verify the zkSnark proof */
	public boolean verify(DizkProofInterface prf){
		Proof proof = ((StandardDizkProof) prf).proof;
        boolean isValid = Verifier.verify(
			crs.verificationKey(), primary, proof, pairing, config);
		return isValid;
	}

	/** Given the input arrTrans, generate the input for ZaTraceVerifier.
	the extra element is a single dimension aray containing the value
	of n (*** the number of input chars ***). Note specifically that
	n is NOT the arrTrans.length (it might be smaller if there
	are failing edges.
		r1 and r2 are set values
		Return [arrPubInput, arrWitness, {n}, arrStates, arrTransNum}
	 */
	public BigInteger [][] gen_input_for_circ(
		AC ac, ArrayList<AC.Transition> arrTrans, BigInteger r1, BigInteger r2){
		//1. read the params
		int state_bits = ac.getStateBits(); 
		int term_symbol = ac.TERM_CHAR;	
		int trans_len = arrTrans.size();
		int n_fail_edge= 0;
		for(int i=0; i<trans_len; i++){
			if(arrTrans.get(i).bFail) n_fail_edge++;
		}
		int n = trans_len - n_fail_edge;
		BigInteger [] arrBFail = new BigInteger [2*n];
		BigInteger [] arrStates = new BigInteger [2*n+1];
		BigInteger [] arrInput= new BigInteger [2*n];
		BigInteger [] arrAlignedInput = new BigInteger [n];
		//because when arrStates translate to to polynomial
		//its degree is 2*n + 1 (but including const coeff at degree 0)
		//it needs an array of capacity 2*n + 2
		int N = 2*n + 2; 

		//2. process all transitions
		int char_idx = 0;
		arrStates[0] = BigInteger.valueOf(arrTrans.get(0).src);
		for(int i=0; i<trans_len; i++){
			AC.Transition trans = arrTrans.get(i);
			arrStates[i+1] = BigInteger.valueOf(trans.dest);
			arrInput[i] = BigInteger.valueOf(trans.c);
			int iBFail = trans.bFail? 1: 0;
			arrBFail[i] = BigInteger.valueOf(iBFail);
			if(!trans.bFail){
				arrAlignedInput[char_idx] = BigInteger.valueOf(trans.c);
				char_idx += 1;
			}
		}
		if(char_idx!=n) {Tools.panic("arrAlignedInput does not have length n! char_idx: " + char_idx + ", n: " + n);}

		//3. patch with self-loop transitions
		int last_state = arrTrans.get(trans_len-1).dest;
		for(int i=trans_len; i<2*n; i++){
			arrInput[i] = BigInteger.valueOf(term_symbol);
			arrStates[i+1] = BigInteger.valueOf(last_state);
			arrBFail[i] = BigInteger.valueOf(1);
		}

		//4. get the vectors needed for subset proofs
		ZaConfig za_config = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
			ZaConfig.EnumHashAlg.Poseidon);
		ZaTraceVerifier circ= new ZaTraceVerifier(za_config, null, 
			n, ac.getStateBits());
		BigInteger [] arrTransNum = 
			circ.logical_build_trans(arrStates, arrInput, arrBFail);
		
		AccDriver ad = new AccDriver();
		ArrayList<ArrayList<BigInteger>> ar_ev = ad.gen_poly_evidence(
			arrStates, arrTransNum);

		//Tools.dump_arr("arrAlignedInput", arrAlignedInput);
		//Tools.dump_arr("arrInput", arrInput);
		//Tools.dump_arr("arrStates", arrStates);

		//4. assemble
		ArrayList<BigInteger> allWit = new ArrayList<BigInteger>();
		allWit.addAll(Arrays.asList(arrStates)); 	
		allWit.addAll(Arrays.asList(arrInput)); 	
		allWit.addAll(Arrays.asList(arrBFail)); 	
		allWit.addAll(Arrays.asList(arrAlignedInput)); 	 
		//add five randomness r, r1, r2, r3, r4
		for(int k=0; k<1; k++){ 
			allWit.add(Utils.randbi(250));
		}
		allWit.add(r1);
		allWit.add(r2);
		for(int k=0; k<2; k++){ 
			allWit.add(Utils.randbi(250));
		}
		if(ar_ev.size()!=14) {Tools.panic("ar_ev.size!=14" + ar_ev.size());}
		for(int i=0; i<ar_ev.size(); i++){
			ArrayList<BigInteger> ar = ar_ev.get(i);
			if(ar.size()!=N){Tools.panic("ar.size!=N. size: " + ar.size()
				+ ", N: " + N);}
			allWit.addAll(ar);
		}
		BigInteger [] arrW = Utils.toArray(allWit);

		//5. process and set up the set of states and transitions
		HashSet<BigInteger> set_st = new HashSet<>(Arrays.asList(arrStates));
		HashSet<BigInteger> set_t = new HashSet<>(Arrays.asList(arrTransNum));
		set_st.addAll(set_t);
		this.arr_st = new BigInteger [set_st.size()];
		set_st.toArray(arr_st);

				
		return new BigInteger [][] {
			new BigInteger [] {},
			arrW,
			new BigInteger [] {BigInteger.valueOf(n)},
			arrStates,
			arrTransNum	
		};
	}

	/** generate the input for all nodes for zaModularVerifier .Note that
	for each node its input is BigInteger [][]. r is the randon nonce for
	evaluating polynoamisl*/
	public BigInteger [][][] gen_input_for_modular_circ(
		String sinp, AC ac, ArrayList<AC.Transition> arrTrans, int num_modules, 
		String randcase_id, BigInteger r, BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key, String curve_type) {
		return gen_input_for_modular_circ_worker(sinp, 
			ac, arrTrans, num_modules,
			0, false, randcase_id, r, r_inv, z, r1, r2, key, curve_type);
	}

	/** generate the input for all nodes for zaModularVerifier .Note that
	for each node its input is BigInteger [][]. If bOnlyOneNode
	is true, just return the data in the node_id's entry (all others
	are empty). We assume that arrTrans is already produced by
	run_by_chunks. r is the randon nonce for evaluating polynomials.
	Each element is a witness for one node. */
	public BigInteger [][][] gen_input_for_modular_circ_worker(
		String s, AC ac, ArrayList<AC.Transition> arrTrans, int num_modules, 
		int node_id, boolean bOnlyOneNode, String randcase_id, BigInteger r,
		BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key, String curve_type){
		//1. submit data request to Acc Driver (should ONLY called on one node)
		submit_data_for_modular_circ_worker(s, ac, arrTrans, num_modules,
			node_id, bOnlyOneNode, randcase_id, r, r_inv, z, r1, r2, key, curve_type);
	
		System.out.println("DEBUG USE 701: step 1: gen_input_for_modular_circ_worker");	
		//2. assembly data
		BigInteger [][][] res = new BigInteger [num_modules][][];
		int n = s.length();
		AccDriver ad = new AccDriver();
		for(int i=0; i<num_modules; i++){
			if(!bOnlyOneNode || i==node_id){
				BigInteger [] wit = ad.collect_modular_verifier_witness_for_node(i, randcase_id, num_modules, n);
				//no public input for all modules, r and r_inv
				//will be disclosed in the output lines of the last module
				res[i] = new BigInteger [][] { 
						{}, 
						wit
				};
			}
		}

		//3. clear data
		ad.clear_data(randcase_id);
		return res;
	}

	/** Preprocess data so that a request (with randcase_id) is submitted
	to AccDriver to generate polynomial evidence (e.g., Bizout's coefs).
	The results will be generated and placed in a folder based on
	randcase_id. Later the data of each node can be called from
	AccDriver. Note: if a node is located on a physical computer
	different from the main node, its data ONLY exists on that physical
	computer.

	NOTE: this function can be later called from RUST side.
	NOTE2: this functino should ONLY be called on the MAIN NODE.
	Don't call it multiple times, it's going to waste CPU time.
	r is the randon nonce for evaluating polynomials */
	public void submit_data_for_modular_circ_worker(
		String s, AC ac, ArrayList<AC.Transition> arrTrans, int num_modules, 
		int node_id, boolean bOnlyOneNode, String randcase_id, BigInteger r,
		BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key, String curve_type){
		//1. read the params
		int n = s.length();
		if(arrTrans.size()!=2*n) {Tools.panic("ERROR: call run_by_chunk()!");}
		int chunk_size = n/num_modules;
		int state_bits = ac.getStateBits(); 
		int term_symbol = ac.TERM_CHAR;	
		int trans_len = arrTrans.size();

		BigInteger [] arrBFail = new BigInteger [2*n];
		BigInteger [] arrStates = new BigInteger [2*n+1];
		BigInteger [] arrInput= new BigInteger [2*n];
		BigInteger [] arrAlignedInput = new BigInteger [n];

		//2. process all transitions
		int char_idx = 0;
		arrStates[0] = BigInteger.valueOf(arrTrans.get(0).src);
		for(int i=0; i<trans_len; i++){
			AC.Transition trans = arrTrans.get(i);
			arrStates[i+1] = BigInteger.valueOf(trans.dest);
			arrInput[i] = BigInteger.valueOf(trans.c);
			int iBFail = trans.bFail? 1: 0;
			arrBFail[i] = BigInteger.valueOf(iBFail);
			if(!trans.bFail){
				arrAlignedInput[char_idx] = BigInteger.valueOf(trans.c);
				char_idx += 1;
			}
		}
		if(char_idx!=n) {Tools.panic("arrAlignedInput does not have length n! char_idx: " + char_idx + ", n: " + n);}

		//3. generate the polynomial evidence
		ZaConfig za_config = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
			ZaConfig.EnumHashAlg.Poseidon);
		ZaTraceVerifier circ= new ZaTraceVerifier(za_config, null, 
			n, ac.getStateBits());
		BigInteger [] arrTransNum = 
			circ.logical_build_trans(arrStates, arrInput, arrBFail);
		
		AccDriver ad = new AccDriver();
		//later call the collect function
		ad.gen_poly_evidence_for_modular_verifier(arrStates, arrInput, arrBFail, arrAlignedInput, arrTransNum, randcase_id, num_modules, r, r_inv, z, r1, r2, key, curve_type);
	
	}
	
	/** generate the R1CS instance. by invoking jsnark circuit,
		r1 and r2 are set random nonces for generating
		for poly(r_1) * r2 [output]
		NOTE: it also SETS UP BigInteger [] arr_st (set of states and transitions)		for future use!!!
	 */ 
	protected Tuple3<R1CSRelationRDD<BNFrT>, Assignment<BNFrT>, JavaPairRDD<Long,BNFrT>> genR1CS(AC ac, ArrayList<AC.Transition> arrTrans, 
		BigInteger r1, BigInteger r2){
		//1. prepare the INPUT for the circuit (mainly from transition list)
		String dirpath = "./circuits";
		Tools.new_dir(dirpath);
		BigInteger [][] ai = gen_input_for_circ(ac, arrTrans, r1, r2);
		int n = ai[2][0].intValue();
		ZaConfig za_config = new ZaConfig(PrimeFieldInfo.LIBSNARK, 
			ZaConfig.EnumHashAlg.Poseidon);
		ZaTraceVerifier circ= new ZaTraceVerifier(za_config, null, 
			n, ac.getStateBits());
		ZaGenerator zg = circ.getGenerator();
		zg.setPresetInputs(ai[0], ai[1]);
		CircuitGenerator.setActiveCircuitGenerator(zg);
		circ.getConfig().apply_config();
		PrimeFieldInfo info = circ.getConfig().field_info;

		//2. generate and save the circuit and generate R1CS as files in
		// directory: ./circuits (TraceVerifier.r1cs.LIBSNARK)
		zg.generateCircuit();
		zg.evalCircuit();
		zg.prepFiles(dirpath, info.name);
		zg.genR1cs(info);

		//3. TODO: serial generation of R1CS instance
		ZkrgxR1CSRelation zr = new ZkrgxR1CSRelation(this.fieldFactory, this.fieldFactory.element().FpParameters, this.config);
		Tuple3<R1CSRelationRDD<BNFrT>, Assignment<BNFrT>, JavaPairRDD<Long,BNFrT>>  res = zr.genR1CSRDD("./circuits/TraceVerifier_LIBSNARK_Poseidon.r1cs.LIBSNARK");
		return res;
	}

	
}
