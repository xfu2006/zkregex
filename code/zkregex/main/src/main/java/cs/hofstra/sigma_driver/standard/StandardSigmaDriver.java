/** Efficient Zero Knowledge Project
	Wrapper of the Standard Sigma Protocol Prover and Verifier.
	Author: Dr. CorrAuthor
	Created: 06/13/2022
	Implemented: 07/11/2022
*/ 

package cs.Employer.sigma_driver.standard;
import cs.Employer.sigma_driver.*;
import cs.Employer.acc_driver.*;
import cs.Employer.ac.AC;
import cs.Employer.zkregex.Tools;

import java.util.ArrayList;
import java.util.Arrays;
import java.math.BigInteger;

/** This class is simply like acc_driver which runs executable
of acc to generate the proof. It is a part of StandardNonzkProver
which is not for official (but for performance comparison) -
it lacks the check of equality of elements between zkSnark 
and sigma protocol claims, and it does not have a modified Groth16
system for connection commited i/o.
*/

public class StandardSigmaDriver implements SigmaDriverInterface{
	class StandardSigmaProof implements SigmaProofInterface{
		public String dir; //its location
		public int get_size(){
			System.out.println("WARNING: StandardSigmaProof returns FAKE data 392");
			return 128; //CHECK REAL IMPLEMENTATION LATER.
		}
		public StandardSigmaProof(String dir){
			this.dir = dir;
		}
	}



	/** generate the sets of states and transitions and
		write the data into a temporarily folder. 
		Then run the acc command to process it
		The proof returned is ACTUALLY FAKE (because we do
	not seralize the rust proof into the form readable by java)!
		Save all files to sPrfDir
	*/
	public SigmaProofInterface prove_nonzk(String acDir,
		BigInteger [] set_st,
		BigInteger r, String sPrfDir){

		//1. create a new temp_dir
		String dir= sPrfDir;
		Tools.new_dir(dir);

		//2. write the data into folder
		BigInteger [] arr_r = new BigInteger [] {r};
		String [] fnames = {"st.dat", "r.dat"};
		ArrayList<ArrayList<BigInteger>> arrD = new ArrayList<>();
		arrD.add(new ArrayList<BigInteger>(Arrays.asList(set_st)));
		arrD.add(new ArrayList<BigInteger>(Arrays.asList(arr_r)));
		for(int i=0; i<fnames.length; i++){
			Tools.write_arr_to_file(arrD.get(i), dir + "/" + fnames[i]);
		}

		//4. call the driver
		MPIConfig mcfg = new MPIConfig(); //setting in config/MPI_CONFIG.txt
		String [] args = mcfg.gen_mpirun_params("gen_nonzk_sigma_proof " + acDir + " " + dir);
		String res = Tools.run(args);
		System.out.println(res);

		//5. remove the folder
		//REMOVE LATER ----
		//RECOVER LATER ---------
		//Tools.del_dir(dir);
		//RECOVER LATER --------- ABOVE
		return new StandardSigmaProof(dir);
	}
	public boolean verify(SigmaProofInterface proof){
		StandardSigmaProof prf = (StandardSigmaProof) proof;
		MPIConfig mcfg = new MPIConfig(); //setting in config/MPI_CONFIG.txt
		String [] args = mcfg.gen_mpirun_params("verify_sigma_proof " + prf.dir);
		String res = Tools.run(args);
		System.out.println(res);
		
		return true; //blindly
	}
}

