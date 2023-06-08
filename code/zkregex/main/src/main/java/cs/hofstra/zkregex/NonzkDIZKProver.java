/** Efficient Zero Knowledge Project
	NonzkDIZKProver (prove a file satisfies AC-DFA)
	Author: Dr. CorrAuthor
	Created: 06/10/2022
*/ 

package cs.Employer.zkregex;
import za_interface.za.Utils;
import configuration.Configuration;
import cs.Employer.dizk_driver.*;
import cs.Employer.sigma_driver.*;
import cs.Employer.ac.AC;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Arrays;

/**
	NonzkDIZKProver: it provides non-zk proof combining the
DIZK prover and sigma protocol.
	Note: this is a prototype impelmentation before the
parallel Rust version, just for comparion. It does
not check the equality of parameters between the claims
of the dizk and Sigma proofs.
	NOTE2: this protocol should be only used as a comparion
of performance (Spark vs Rust parallel Groth16 system).

Its workerflow: (1) load the DFA (assuming DFA.dat) is located
in the given folder; (2) generate the states/input pair given the
executable file to prove; (3) call JSnark to generate the circuit;
(4) call DIZK to generate the proof 
(5) call the rust/acc module to generate the Sigma proof.
(6) save the proof in the given file.
*/
public class NonzkDIZKProver implements ProverInterface{
	// *** DATA MEMBERS ***
	protected DizkDriverInterface dizk_driver; //used for snark proof
	protected SigmaDriverInterface sigma_driver; //used for sigma_proof
	protected Configuration config;
	
	// *** OPERATIONS ***
	public NonzkDIZKProver(DizkDriverInterface dd, SigmaDriverInterface sdd, 
		Configuration config){
		this.dizk_driver = dd;
		this.sigma_driver = sdd;
		this.config = config;
	}

	/** Assume the DFA.datis located in acDir. Read it and process
	the given binFile and save the proof into prfPrfDir - all proofs
	and related intermediate files will be saved there
	*/
	public void process(String acDir, String sBinFileToProve, 
		String sPrfDir, Configuration config){
		Tools.set_log_level(Tools.LOG1);
		Tools.log(Tools.LOG1, "\n========== NonzkDIZKProver ========\n"+
			"AC_DFA Folder: " + acDir+ 
			"\nBin File to Prove: " + sBinFileToProve+ 
			"\nSave Proof to Dir: " + sPrfDir + 
			"\n==================================");

		//0. Timers
		NanoTimer tLoadAC = new NanoTimer();
		NanoTimer tLoadExec = new NanoTimer();
		NanoTimer tSnark = new NanoTimer();
		NanoTimer tSigma = new NanoTimer();
		NanoTimer tVerify = new NanoTimer();
		NanoTimer tVerifySigma = new NanoTimer();

		//1. load AC-DFA
		config.beginLog("Step 1: load AC-DFA");
		tLoadAC.start();
		AC ac = AC.deserialize(acDir + "/DFA.dat");
		tLoadAC.end();
		config.endLog("Step 1: load AC-DFA");
		//ac.dump_summary();

		//2. read the given executable file
		//NOTE: this includes ONE-TIME circuit generation and key setup
		//When counting timing, should not included.
		// *** (1) the input is padded with 0 to power of 2
		config.beginLog("Step 2: read executable and generate DFA path");
		tLoadExec.start();
		byte [] nibbles = cs.Employer.ac.Tools.
			read_nibbles_from(sBinFileToProve);
		String sinput= cs.Employer.ac.Tools.bytearr_to_str(nibbles);
		ArrayList<AC.Transition> arrTrans = ac.run(sinput);
		tLoadExec.end();
		config.endLog("Step 2: read executable and generate DFA path");

		//3. generate Zksnark proof (using Dizk)
		config.beginLog("Step 3: set up DIZK and prove DIZK");
		tSnark.start();
		BigInteger r1 = Utils.randbi(250);
		BigInteger r2 = Utils.itobi(0); //thus just producing p(r) itself
		DizkProofInterface dizk_proof = dizk_driver.
			prove(ac, arrTrans, r1, r2);
		tSnark.end();
		tVerify.start();
		if(!dizk_driver.verify(dizk_proof)){
			Tools.panic("Snark Proof invalid!");
		}
		tVerify.end();
		config.endLog("Step 3: set up DIZK and prove DIZK");

		//5. generate the Sigma proof
		BigInteger [] arr_st = dizk_driver.get_st();
		config.beginLog("Step 4: prove Sigma part");
		tSigma.start();
		SigmaProofInterface sigma_proof = this.sigma_driver.prove_nonzk(acDir,
			arr_st, r1, sPrfDir);
		tSigma.end();
		tVerifySigma.start();
		if(!sigma_driver.verify(sigma_proof)){
			Tools.panic("Sigma Proof invalid!");
		}
		tVerifySigma.end();
		config.endLog("Step 4: prove Sigma part");

		//6. construct the two parts proof (this step is actually skipped)
		Proof prf = new Proof(dizk_proof, sigma_proof);
		byte [] bytes_prf = prf.to_bytes();
		Tools.write_bytes_to_file(bytes_prf, sPrfDir + "/combined.prf"); 

		System.out.println("============= Summary ===============");
		System.out.println("Size: " + arrTrans.size() + " nibbles");	
		System.out.println("load AC: "+tLoadAC.getDuration()/1000000 + " ms");	
		System.out.println("load Exec: "+tLoadExec.getDuration()/1000000 + " ms");	
		System.out.println("SnarkProve: "+tSnark.getDuration()/1000000 + " ms");	
		System.out.println("SigmaProve: "+tSigma.getDuration()/1000000 + " ms");	
		System.out.println("VerifySnark: "+tVerify.getDuration()/1000000 + " ms");	
		System.out.println("VerifySigma: "+tVerifySigma.getDuration()/1000000 + " ms");	
		System.out.println("============= END ===============");
	}

}
