/** Efficient Zero Knowledge Project
	Main Controller File
	Author: Dr. CorrAuthor
	Created: 04/09/2022
	Modified: 05/23/2022
	Modified: 08/24/2022: Added params: depthStep, maxDepth, curve_type
	Revised: 01/01/2023: adapted gen-dfa() to be consistent with the
		params used in nfa/ac/.../App.java "scan"
	Revised: 01/09/2023. exclued step-wise and upper limit.
		use RunConfig.subset_list
*/ 

package cs.Employer.zkregex;
import cs.Employer.ac.AC;
import cs.Employer.acc_driver.*;
import cs.Employer.ac.App;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Arrays;
import java.math.BigInteger;
import za_interface.za.Utils;

/**
 Publihser workflow: (1) generate the AC-DFA from the given source
folder; (2) dump the states, transition, final states as simple
text file; (3) run RUST openmpi implementation to generate the
KZG commitment for the union of states and transitions. (4) generate
subset data (for 2-phase proof scheme) and the corresponding KZG proofs.
*/
public class Publisher 
{
	/** generate the DFA. Assumptions: sigs.dat (words) in srcDir.
		It also samples num_samples of binary executable files
		in the sample_dir and generate frequency set.
		Create the destDir and store the following files:
		(1) DFA.dat (serialization of DFA)
		(2) st.dat (list of transitions and states, digitalized)
		(3) info.txt (information about number of stats and final states). 
			Contains:
			[1] number of lines
			[2] number of final states.
			[3] number of states
		(4) freq_keywords.dat (the freqently visited keywords set)
	*/
	public static void gen_dfa(String srcDir, String destDir, String listfile){
			srcDir = Tools.getAbsolutePath(srcDir);
			destDir= Tools.getAbsolutePath(destDir);

			//1. build AC-DFA
			AC ac = AC.load_clamav_fixed(srcDir+ "/sigs.dat");
			//ac.serialize_to(destDir+"/DFA.dat");

			//2. write states + transitions
			String fpath = destDir + "/st.dat";
			Tools.write_num_to_arr(Utils.itobi(0), fpath); //just a place token
			long mem1= Runtime.getRuntime().totalMemory();
			int num_states = ac.write_states_as_num(fpath);
			int num_trans = ac.write_trans_as_num(fpath);
			int num_st = num_states + num_trans;
			long mem2= Runtime.getRuntime().totalMemory();
			Tools.overwrite_file_begin(fpath, Tools.num2str9(num_st));
			Tools.log(Tools.LOG1, "DFA states: " + num_states + ", transitions: " + num_trans);
			

			//3. write the info
			ArrayList<BigInteger> arInfo = new ArrayList<>();
			arInfo.add(Utils.itobi(ac.get_num_final_states()));
			arInfo.add(Utils.itobi(ac.get_num_states()));
			Tools.write_arr_to_file(arInfo, destDir + "/info.txt");

			//4. write the freq word set 
			// search for freq words appears >= 2 times with depth>=15
			/** 
			ArrayList<String> files = Tools.read_file_lines(listfile);
			int num_samples = files.size()/10;
			//NOTE! check nfa/acc/App.java "scan" func for the SAME PARAMS!
			int min_occ = 2;
			int min_depth = 15;
			Tools.log(Tools.LOG1, "Generating freq-word_set. ELF list " + 
listfile + " num_samples: " + num_samples + ". min_occ: " + min_occ + ", min_depth: " + min_depth+ ". NOTE: check nfa/acc/App.java for CONSISTANT params"); 
			*/
			int idx = listfile.lastIndexOf("/"); 
			String base_dir = listfile.substring(0, idx);
			String freq_file = base_dir + "/../freq_keywords.dat";
			Tools.log(Tools.LOG1, "READ freq-word from: " + freq_file);
			ArrayList<BigInteger> arr_freq_in = 
				Tools.read_arr_bi_from_file(freq_file);
			HashSet<Integer> freq_set = new HashSet<>();
			for(BigInteger x : arr_freq_in) {freq_set.add(x.intValue());}
			/*
			HashSet<Integer> freq_set = App.new_collect_freq_word_set(
				ac,files,num_samples,min_occ,min_depth);
			*/
			ArrayList<BigInteger> ar_freq = new ArrayList<>();
			for(Integer i: freq_set){ 
				ar_freq.add(BigInteger.valueOf(i.intValue())); 
			}
			Tools.write_arr_to_file(ar_freq, destDir + "/freq_keywords.dat");

			//5. produce the subset info, looks like
			// st_subset_10.dat, st_subset_20.dat etc.
			int sub_setids [] = new int [] {10, 15, 20, 30, 40, 50, 300};
			Tools.log(Tools.LOG1, "subset_ids: " + Arrays.toString(sub_setids)+ ". CHECK acc/RUN_CONFI.for consistency!");
			for(int i: sub_setids){
				String subset_fpath = destDir + "/st_subset_"+i+".dat"; 
				Tools.write_num_to_arr(Utils.itobi(0), subset_fpath); 
				int num_s = ac.write_states_as_num_worker(
					i, freq_set, subset_fpath);
				int num_t = ac.write_trans_as_num_worker(
					i, freq_set, subset_fpath);
				int num_sub_st = num_s + num_t;
				Tools.overwrite_file_begin(subset_fpath, 
					Tools.num2str9(num_sub_st));
				//Tools.log(Tools.WARN, "Subset " + i + ": states: " + num_s + ", transitions: " + num_t);
			}
	}

	/** Generate the KZG of the bilinear polynomial representing
		the given multi-sets, generte the (standard) KZG'10 commitment.
		fname: the name of the data file, it must be located in
		srcDir in the MAIN node.
		destDir: the destination folder to place the result. in MPI distribution
	mode, each node needs to create destDir and place the results (partition data) there.
	*/
	public static void gen_kzg(String srcDir, String destDir, String fname,
		String curve_type ){
			String [] supported = {"BN254", "Bls381"};
			boolean bFound = false;
			for(String s: supported){ if(s.equals(curve_type)) bFound = true;}
			if(!bFound) {Tools.panic("Curve: " + curve_type + " not supported!");} 
			
			srcDir= Tools.getAbsolutePath(srcDir);
			destDir = Tools.getAbsolutePath(destDir);
			MPIConfig mcfg = new MPIConfig(); //setting in config/MPI_CONFIG.txt

			String [] args = mcfg.gen_mpirun_params("gen_kzg " + srcDir + 
			" " + destDir + " " + fname +  " " + curve_type + " " + mcfg.NODELIST);
			Tools.run_in_background(args, "/tmp/publish.dump.txt");
	}

	/** process the pattern data in srcDir and save the data to destDir.
		curve_type: allowing BN254 and BLS12_381
		listfile: file which contains the list of ELF executables to scan
	 */
	public static void process(String srcDir, String destDir, String curve_type, String listfile){
		Tools.set_log_level(Tools.LOG1);
		NanoTimer t1 = new NanoTimer();
		NanoTimer t2= new NanoTimer();
		NanoTimer t3 = new NanoTimer();
		Tools.log(Tools.LOG1, "\n========== Publisher framework ========\n"+
			"src: " + srcDir + 
			"\ndest: " + destDir + "\n==================================");

		Tools.new_dir(destDir);
		Tools.log(Tools.LOG1, "Step 1: Generating AC-Automata");
		t1.start();
		gen_dfa(srcDir, destDir, listfile);
		t1.end();
		Tools.log(Tools.LOG1, "Step 1: GEN_DFA Time: " + t1.getDuration()/1000000  + "ms");

		Tools.log(Tools.LOG1, "Step 2: Build KZG of Transitions+States");
		t2.start();
		gen_kzg(destDir, destDir, "st", curve_type); //the union of trans and states
		t2.end();
	}
}
