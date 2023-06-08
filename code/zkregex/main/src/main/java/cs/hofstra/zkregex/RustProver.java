/** Efficient Zero Knowledge Project
	Wrapper (Driver of Rust Prover)
	Author: Author1, Dr. CorrAuthor (doc and spec)
	Created: 09/05/2022
	Revised: 11/11/2022 Minor Revision on process().
	Revised: 12/29/2022 (padding for occasionally failed run_by_chunks)
	Revised: 01/10/2023 (providing support for partitioned large file)
	Revised: 02/08/2023 (adding distributed processing for batch_preprocess, now files will be distributed on each server)
	Revised: 03/26/2023 (adding batch_padding, batch_encrypt, batch_hash
		for verification of claims/statements)
	Revised: 04/04/2023 change the allocation of jobs to servers so that
		node 0 always get the largets share
*/ 

package cs.Employer.zkregex;
import java.time.Instant;
import za_interface.za.Utils;
import cs.Employer.ac.AC;
import cs.Employer.ac.App;
import java.util.ArrayList;
import java.util.HashSet;
import java.math.BigInteger;
import java.util.Arrays;
import java.nio.file.Path;
import java.nio.file.Paths;
import cs.Employer.acc_driver.MPIConfig;
import za_interface.za.ZaConfig;
import za_interface.PrimeFieldInfo;
import za_interface.za.circs.zkreg.ZaTraceVerifier;
import cs.Employer.acc_driver.AccDriver;
import java.io.BufferedWriter;
import java.io.FileWriter;

/** RustProver is mainly a command driver of the prover in rust acc/.
	Its main job is to read the input (automata, file to prove),
 	generate the trace data and write the data into the specified
	folder, and then call the RUST acc prover.
	*** NOTE: all "logical" implementation are contained in ZaModularVerifier's
		rand_inst() function! Tracing its implementation gives
		a list of functions that can be re-used or re-implemented 
	***
	Usage: see scripts/prover.sh
	java ... class_dependency cs.Employer.zkregex.App
		rust_prover ac_dfa_dir  file_path_to_prove prof_storage_dir
			curve_name(BN254|Bls381)   case_id   max_nodes
		
*/
public class RustProver{
	// *** DATA MEMBERS ***	
	protected BigInteger modulus;

	// *** OPERATIONS ***
	public RustProver(){ }

	/** generate r, r_inv, z, r1, r2 (within 252 bits */
	public BigInteger [] genRandNonce(ZaConfig za_config){
		//REMOVE LATER ----------
		BigInteger r = Utils.itobi(12342342);
		BigInteger modulus = za_config.getFieldOrder();
		BigInteger r_inv = r.modInverse(modulus); // how to get modulus?
		BigInteger z = Utils.itobi(65123123);
		BigInteger r1 = Utils.itobi(27123);
		BigInteger r2 = Utils.itobi(923423423);
		BigInteger key = Utils.itobi(12345678);
		//REMOVE LATER ---------- ABOVE

		//RECOVER LATER
		/**
		BigInteger r = Utils.randbi(250);
		BigInteger modulus = za_config.getFieldOrder();
		BigInteger r_inv = r.modInverse(modulus); // how to get modulus?
		BigInteger z = Utils.randbi(250);
		BigInteger r1 = Utils.randbi(250);
		BigInteger r2 = Utils.randbi(250);
		BigInteger key = Utils.randbi(250);
		*/
		//RECOVER LATER ABOVE

		BigInteger [] res = {r, r_inv, z, r1, r2, key};
		return res;
		
	}

	/** submit the data to generate polynomial evidence  */
	public void gen_poly_evidence_for_modular_circ(
		String s, AC ac, ArrayList<AC.Transition> arrTrans, int num_modules, 
		String randcase_id, BigInteger r, BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key, String curve_type){
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

	/** assume all BigInteger in range. convert ArrayList to
		a hashSet */
	private HashSet<Integer> to_set(ArrayList<BigInteger> arr){
		HashSet<Integer> hs = new HashSet<>();
		for(int i=0; i<arr.size(); i++){
			BigInteger bi = arr.get(i);
			Integer item = bi.intValue();
			hs.add(item);
		}
		return hs;	
	}

	/** read and padd the given give, so that the
		size of the string is a multiple of 
			252bits * 2 = 126 nibbles (4-bit) 
		Based on the number of processors, pad it also to the smallest
		acceptable size: 252bits*2 * np = 126*np nibbles
		DEPARECATED
	*/ 	
	protected String read_and_pad(String sBinFileToProve, int np){
		System.out.println("DEPRECATED: read_and_pad!!!");
		byte[] nibbles = cs.Employer.ac.Tools.read_nibbles_from(sBinFileToProve);
		String nibblesStr = new String(nibbles);
		int cur_len = nibblesStr.length(); //in nibbles
		System.out.println("DEBUG USE 006: input length: " + cur_len + " nibbles");
		//Each node needs at least 126 nibbles = 504 bits 
		int unit = 126;
		int cur_len_per_node = cur_len/np;
		int target_len_per_node = cur_len_per_node%unit==0?
				cur_len_per_node: (cur_len_per_node/unit+1)*unit;
		System.out.println("DEBUG USE 007: cur_len_per_node: " +
				cur_len_per_node + ", target_len_per_node: " +
				target_len_per_node);
		//last node can have ONLY 1 unit 
		int target_len = target_len_per_node*np;
		int min_len = unit * np;
		if (target_len<min_len){
				target_len = min_len;
				Tools.log(Tools.LOG1, "Number of processors min-size: " + min_len + ", padding executable to min-size");
		}
		Tools.log(Tools.LOG1, "Read: " + sBinFileToProve +
				", cur_len: " +  cur_len + " nibbles ==> (padded) " +
				target_len + " nibbles");
		int diff_len = target_len - cur_len;
		byte [] padd_bytes = new byte [diff_len]; 
		for(int i=0; i<padd_bytes.length; i++){
			padd_bytes[i] = 10; //0xA
		}
		String padded = new String(padd_bytes);
		String res = nibblesStr + padded;
		return res;
	}

	/** Input: acDir: contains AC-DFA serialization data.
		sBinFileToProve: need to read it as nibbles
		sPrfDir: the estination folder that rust acc prover will 
			use to generate data
		curve_name: one of "BN254" or "Bls381"
		caseID: a case ID for tracing subsequent data
		nodes: number of nodes to use in parallel processing (prove
			and generation) 
			IMPROVE LATER: sometimes the file length restricts the
			the number nodes change.
	*/
	public void process(String acDir, String sBinFileToProve, 
		String sPrfDir, String curve_name, String case_id, int max_nodes){
		acDir = Tools.getAbsolutePath(acDir) + "/";
		sPrfDir = Tools.getAbsolutePath(sPrfDir) + "/";
		Tools.set_log_level(Tools.LOG1);
		Tools.log(Tools.LOG1, "\n========== RustProver v1 ========\n"+
			"AC_DFA Folder: " + acDir+ 
			"\nBin File to Prove: " + sBinFileToProve+ 
			"\nSave Proof to Dir: " + sPrfDir + 
			"\nCurve: " + curve_name + 
			"\nMaxNodes: " + max_nodes + 
			"\n==================================");
		//1. load the AC-DFA
		NanoTimer t1 = new NanoTimer();
		t1.start();
		AC ac = AC.deserialize(acDir + "DFA.dat");			
		t1.end();
		Tools.log_perf("PERF_USE_LoadDFA", t1);

		//2. run the chunked transitions (generate transitions)
		//see ZaModularVerifier rand_inst()
		MPIConfig mcfg = new MPIConfig(max_nodes);
		int np = mcfg.numNodes;
		String nibblesStr = read_and_pad(sBinFileToProve, np);
		ArrayList<AC.Transition> alTrans= ac.run_by_chunks(nibblesStr, np); 
		//String sinp = ac.collect_inputs(alTrans);
		int n = nibblesStr.length(); 
		ZaConfig za_config = ZaConfig.new_config_by_curve(curve_name);
		BigInteger [] bi = genRandNonce(za_config);
		BigInteger r = bi[0];
		BigInteger r_inv = bi[1];
		BigInteger z = bi[2];
		BigInteger r1 = bi[3];
		BigInteger r2 = bi[4]; 
		BigInteger key = bi[5]; 
		//RECOVER LATER --------
		//String randcase_id = "poly_" + Utils.randbi(64).to_string();
		//RECOVER LATER -------- ABOVE
		gen_poly_evidence_for_modular_circ(
			nibblesStr, ac, alTrans, np,
			case_id, r, r_inv, z, r1, r2, key,
			curve_name);
		Tools.log_perf("PERF_USE_GenPoly", t1);

		//3. collect number of final states and subset_id
		int max_final_states = ac.get_num_final_states();
		ArrayList<BigInteger> ar_req = Tools.read_arr_bi_from_file(acDir + "/freq_keywords.dat");
		HashSet<Integer> freq_set = to_set(ar_req);
		int max_depth = ac.get_max_depth_by_run(nibblesStr, freq_set);
		int unit_subset = 20;
		int subset_id = (max_depth/unit_subset+1)*unit_subset;
		//System.out.println("DEBUG USE 105: max_final_states: " + max_final_states + ", mdepth: " + max_depth +", subset_id: " + subset_id);
		Tools.log_perf("PERF_USE_Locate_Subset_ID", t1);

		//4. invoke option *** rust_prove *** of acc
		Tools.new_dir(sPrfDir);
		String polyDir = Tools.getAbsolutePath("../DATA/"+case_id);
		String subset_id_str = String.valueOf(subset_id);
		String tmpnode_list = "/tmp/tmp_nodelist.txt";
		String[] args = mcfg.gen_mpirun_params("rust_prove " + acDir + " " + polyDir + " " + sPrfDir + " " + curve_name + " " + subset_id_str + " " + tmpnode_list + " " + max_final_states); 

		Tools.run_in_background(args, sPrfDir + "/dump.txt");
	}

	// ---------------------------------------------------
	// The folllowing are for BatchProcessing Related Functions
	// ---------------------------------------------------

	class PreprocessThread extends Thread{
		protected int id; //0 to num_th -1
		protected int num_th; //total number of worker threads
		protected FileInfo [] job_list; //list of files to process (for all)
										//we take job_list[x] s.t. x%num_th =id
		protected AC ac; //must be UNIQUE for each thread to avoid asynch issue
		int file_size; //target_file size
		String work_dir; //the work_dir to create dumped info
		int np; //number of MPI processors
		String curve_type; //BN254 or BLS12-381
		protected BufferedWriter writer; //for logging purpose

		/** constructor */
		public PreprocessThread(int id, int num_th, FileInfo [] job_list, AC ac,
			int file_size, String work_dir, int np, String curve_type){
			this.id = id;
			this.num_th = num_th;
			this.job_list = job_list;
			this.ac = ac;
			this.file_size = file_size;
			this.work_dir = work_dir;
			this.np = np;
			this.curve_type = curve_type;
			try{
				this.writer = new BufferedWriter(new FileWriter("/tmp/report_batchproc_thread_" + id + ".txt")); 
			}catch(Exception exc){
				Tools.panic(exc.toString());
			}
		}

		public void run(){
			String marker = "==============";
			Tools.flog(Tools.LOG1, marker + "Worker Thread " + id + " starts at: " + Instant.now() + marker, writer);
			for(int i=id; i<job_list.length; i+=num_th){
				FileInfo file = job_list[i];
				preprocess_file(file, file_size, work_dir, ac, np, curve_type);	
			}
			Tools.flog(Tools.LOG1, marker + "Worker Thread " + id + " stops at: " + Instant.now() + marker, writer);
			try{ writer.close();}catch(Exception exc){Tools.panic(exc.toString());}
		}


		// return the "substring" of it
		protected byte [] get_part(byte [] nibbles, int start_idx, int length){
			byte [] res = new byte [length];
			for(int i=0; i<length; i++){
				res[i] = nibbles[i + start_idx];
			}
			return res;
		}
		/** preprocess the file and store all info in work_dir/fname.
		each file will be expanded to file_size (nibbles)
		 */
		protected void preprocess_file(FileInfo fi, int file_size, String work_dir, AC ac, int np, String curve_type){
		 try{
			//1. expand and read nibbles and generate transitions
			//String fname = get_file_name(fpath);
			boolean b_perf = true;

			String fpath = fi.file_path;
			int idx = fpath.indexOf("_partx71");
			String real_fpath = idx<0? fpath: fpath.substring(0, idx);
			String fname = fpath.replace("/", "_");
			NanoTimer t1 = new NanoTimer();
			t1.start();
	
			String curve_name=curve_type.equals("BLS12-381")?  "Bls381":curve_type;
			ZaConfig za_config = ZaConfig.new_config_by_curve(curve_name);
			//NOTE: run_by_chunks may fail (rarely). We need to PAD
			//with TERM CHARS carefully to make sure run_by_chunks ok
			byte [] nibbles = cs.Employer.ac.Tools.read_nibbles_from(real_fpath);
			nibbles = get_part(nibbles, fi.offset*2, fi.size*2); //*2 for nibbles
			if(nibbles==null){Tools.panic("FILE NOT EXIST: " + fpath);}
			boolean b_failed = true;
			ArrayList<AC.Transition> arrTrans= new ArrayList<AC.Transition>();
			String nibblesStr = App.padd_nibbles(ac, nibbles, file_size, fi.start_state, np, fpath); 
			if(nibblesStr==null){
				Tools.myassert(false, "ERROR 501: failed to padd nibbles. len: " + nibbles.length + ", file_size: " + file_size);
			}
			int [] res = ac.adv_run_by_chunks(nibblesStr, fi.start_state, np, arrTrans, false); 
			Tools.myassert(res==null, "ERROR 501, run_by_chunks return error!");
			int real_last_state = arrTrans.get(arrTrans.size()-1).dest; 
			int exp_last_state = fi.end_state;
			Tools.myassert(real_last_state==exp_last_state, "real_last_state: " + real_last_state + " != exp_last_state: " + exp_last_state);

			if (b_perf) {Tools.flog_perf("-- PERF_USE_Read and Pad: " + fname, t1, writer);}
	
			//String sinp = ac.collect_inputs(arrTrans);
			int n = nibblesStr.length();
			if(arrTrans.size()!=2*n) {Tools.panic("ERROR: call run_by_chunk()!");}
	
			int chunk_size = n/np;
			int state_bits = ac.getStateBits(); 
			int term_symbol = ac.TERM_CHAR;	
			int trans_len = arrTrans.size();
			BigInteger [] arrBFail = new BigInteger [2*n];
			BigInteger [] arrStates = new BigInteger [2*n+1];
			BigInteger [] arrInput= new BigInteger [2*n];
			BigInteger [] arrAlignedInput = new BigInteger [n];
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
			if(b_perf) {Tools.flog_perf("-- PERF_USE_CreateAligned: " + fname, t1, writer);}
			if(char_idx!=n) {Tools.panic("arrAlignedInput does not have length n! char_idx: " + char_idx + ", n: " + n);}
			ZaTraceVerifier circ= new ZaTraceVerifier(za_config, null, 
				n, ac.getStateBits());
			BigInteger [] arrTransNum = 
				circ.logical_build_trans(arrStates, arrInput, arrBFail);
			if (b_perf) {Tools.flog_perf("-- PERF_USE_DigitizeTransitions: " + fname, t1, writer);}
	
	
			//2.  generate randon nonces
			BigInteger [] bi = genRandNonce(za_config);
			BigInteger r = bi[0];
			BigInteger r_inv = bi[1];
			BigInteger z = bi[2];
			BigInteger r1 = bi[3];
			BigInteger r2 = bi[4]; 
			BigInteger key = bi[5]; 
	
			//3. write into directory
			String dirpath = work_dir + "/" + fname;
			Tools.new_dir(dirpath);
			if(arrStates.length!=arrTransNum.length+1){
				Tools.panic("state.len!=trans.len+1");
			}
			String [] paths = {"states.dat", "trans.dat", "arr_input.dat", "arr_bfail.dat", "arr_aligned.dat", "hash_in.dat", "encrypt_in.dat", "r.dat"};
			AccDriver ad = new AccDriver();
			arrStates = ad.massage_states(arrStates, np);
			BigInteger [][] arr2d= ad.compute_hash_in_worker(arrAlignedInput, key, np, true, curve_name); //thus size will be np+1 with the last as the ENTIRE output.
			int an = arr2d[0].length;
			if (b_perf) {
				Tools.flog_perf("-- PERF_USE_ComputeHash: " + fname + ", file size: " + fi.size + " bytes , padded to " + file_size + " nibbles: ", t1, writer);
			}
	
			BigInteger [] arrHashIn = arr2d[1];
			BigInteger [] arrEncryptIn = arr2d[0];
			BigInteger [] arrR = new BigInteger [] {r, r_inv, z, r1, r2, key, r, r_inv};
			BigInteger [][] data = {arrStates, arrTransNum, arrInput, arrBFail, arrAlignedInput, arrHashIn, arrEncryptIn, arrR};
			for(int i=0; i<paths.length; i++){
				Tools.write_arr_to_file(new ArrayList(Arrays.asList(data[i])),
					dirpath + "/" + paths[i]);
			}
	
			if (b_perf) {Tools.flog_perf("-- PERF_USE_WriteFiles: " + fname, t1, writer);}
			Tools.flog(Tools.LOG1, "-- SUCCESS_Preprocess: " + fpath, writer);
		  }catch(Exception exc){
			exc.printStackTrace();
			Tools.warn("ERROR 501: " + fi.file_path + ": " + exc.toString());
			//but go on
		  }
		}

		/* read the nibbles and pad to the target_len */
/*
		protected String read_and_pad_to(String sBinFileToProve, int target_len, AC ac){
			byte[] nibbles = cs.Employer.ac.Tools.read_nibbles_from(sBinFileToProve);
			if(nibbles==null) {Tools.log(Tools.WARN, "unable to open file: " + sBinFileToProve + ", generating a dummy strin gof 0's ...");}
			nibbles = nibbles==null? new byte [target_len]: nibbles;
			String nibblesStr = new String(nibbles);
			int cur_len = nibblesStr.length(); //in nibbles
			Tools.log(Tools.LOG1, "Read: " + sBinFileToProve +
					", cur_len: " +  cur_len + " nibbles ==> (padded) " +
					target_len + " nibbles");
			int diff_len = target_len - cur_len;
			if(diff_len<0) Tools.panic("diff_len<0! diff_len: " + diff_len);
			byte [] padd_bytes = new byte [diff_len]; 
			for(int i=0; i<padd_bytes.length; i++){
				padd_bytes[i] = (byte) ac.TERM_CHAR;
			}
			String padded = new String(padd_bytes);
			String res = nibblesStr + padded;
			return res;
		}
	*/

	}

	class WorkerThread extends Thread{
		protected int id; //0 to num_th -1
		protected int num_th; //total number of worker threads
		protected FileInfo [] job_list; //list of files to process (for all)
										//we take job_list[x] s.t. x%num_th =id
		protected AC ac; //must be UNIQUE for each thread to avoid asynch issue
		int file_size; //target_file size
		String curve_type; //BN254 or BLS12-381
		protected BufferedWriter writer; //for logging purpose
		protected String op;
		protected BigInteger key;
		protected int np; //number of processing nodes of MPI, need for pad

		/** constructor */
		public WorkerThread(int id, int num_th, FileInfo [] job_list, AC ac,
			int file_size, String curve_type, String op, BigInteger key,
			int np){
			this.id = id;
			this.num_th = num_th;
			this.job_list = job_list;
			this.ac = ac;
			this.file_size = file_size;
			this.curve_type = curve_type.equals("BLS12-381")?  
				"Bls381":curve_type;
			this.op = op;
			this.key = key;
			this.np = np;
			try{
				this.writer = new BufferedWriter(new FileWriter(
					"/tmp/report_multhworker_" + id + ".txt")); 
			}catch(Exception exc){
				Tools.panic(exc.toString());
			}
		}

		public void run(){
			String marker = "==============";
			Tools.flog(Tools.LOG1, marker + "Worker Thread " + id + " starts at: " + Instant.now() + ", Op: " + this.op +  marker , writer);
			for(int i=id; i<job_list.length; i+=num_th){
				FileInfo file = job_list[i];
				if(op.equals("batch_pad")){
					padfile(file, file_size, ac, curve_type, np);
				}else if(op.equals("encrypt")){
					encrypt_hash_file(file, file_size, false);
				}else if(op.equals("hash")){
					encrypt_hash_file(file, file_size, true);
				}else{
					throw new RuntimeException("CANNOT handle op: " + op);
				}
			}
			Tools.flog(Tools.LOG1, marker + "Worker Thread " + id + " stops at: " + Instant.now() + marker, writer);
			try{ writer.close();}catch(Exception exc){Tools.panic(exc.toString());}
		}

		public void encrypt_hash_file(FileInfo fi, int files_size, boolean
			b_hash){
			//1. build the arrAlignedInput
			String encrypt_fpath = fi.file_path + ".encrypted";
			String hash_fpath = fi.file_path + ".hash";
			BigInteger [] arr_input = null;
			if(!b_hash){//encrypt
				String target_pad_fpath = fi.file_path + ".padded";	
				String padStr = Tools.read_bin_file(target_pad_fpath);
				Tools.myassert(padStr.length()==file_size, 
					"file_size: " + file_size
					+ "!= padStr.length: " + padStr.length() + ", for: "
					+ target_pad_fpath);
				arr_input = new BigInteger [file_size];
				for(int i=0; i<file_size; i++) arr_input[i] 
					= BigInteger.valueOf(padStr.charAt(i)); 
			}else{//hash
				byte [] bytes = Tools.read_bytes_from_file(encrypt_fpath);
				arr_input = Tools.from_bytes(bytes);
			}


			//3. encrypt or hash
			AccDriver ad = new AccDriver();
			if(op.equals("encrypt")){
				BigInteger [] res = ad.compute_encryption(arr_input, key, curve_type, np);
				byte [] arr = Tools.to_bytes(res);
				Tools.write_bytes_to_file(arr, encrypt_fpath);
			}else if(op.equals("hash")){
				BigInteger res = ad.compute_hash(arr_input, key, curve_type, np);
				ArrayList<BigInteger> arr = new ArrayList<>();
				arr.add(res);
				Tools.write_arr_to_file(arr, hash_fpath);
			}else{
				throw new RuntimeException("op not supported: " + op);
			}
		
		}


		// return the "substring" of it
		protected byte [] get_part(byte [] nibbles, int start_idx, int length){
			byte [] res = new byte [length];
			for(int i=0; i<length; i++){
				res[i] = nibbles[i + start_idx];
			}
			return res;
		}
		/** preprocess the file and store all info in work_dir/fname.
		each file will be expanded to file_size (nibbles)
		 */
		protected void padfile(FileInfo fi, int file_size, AC ac, 
String curve_type, int np){
		 try{
			//1. expand and read nibbles and generate transitions
			//String fname = get_file_name(fpath);
			boolean b_perf = true;

			String fpath = fi.file_path;
			int idx = fpath.indexOf("_partx71");
			String real_fpath = idx<0? fpath: fpath.substring(0, idx);
			String par_dir = Tools.get_parent_dir(fpath);
			String target_pad_fpath = fi.file_path + ".padded";	
			String fname = fpath.replace("/", "_");
			NanoTimer t1 = new NanoTimer();
			t1.start();
	
			String curve_name=curve_type.equals("BLS12-381")?  "Bls381":curve_type;
			ZaConfig za_config = ZaConfig.new_config_by_curve(curve_name);
			//NOTE: run_by_chunks may fail (rarely). We need to PAD
			//with TERM CHARS carefully to make sure run_by_chunks ok
			byte [] nibbles = cs.Employer.ac.Tools.read_nibbles_from(real_fpath);
			nibbles = get_part(nibbles, fi.offset*2, fi.size*2); //*2 for nibbles
			if(nibbles==null){Tools.panic("FILE NOT EXIST: " + fpath);}
			boolean b_failed = true;
			ArrayList<AC.Transition> arrTrans= new ArrayList<AC.Transition>();
			String nibblesStr = App.padd_nibbles(ac, nibbles, file_size, fi.start_state, np, fpath); 
			if(nibblesStr==null){
				Tools.myassert(false, "ERROR 501: failed to padd nibbles. len: " + nibbles.length + ", file_size: " + file_size);
			}
			int [] res = ac.adv_run_by_chunks(nibblesStr, fi.start_state, np, arrTrans, false); 
			Tools.myassert(res==null, "ERROR 501, run_by_chunks return error!");
			int real_last_state = arrTrans.get(arrTrans.size()-1).dest; 
			int exp_last_state = fi.end_state;
			Tools.myassert(real_last_state==exp_last_state, "real_last_state: " + real_last_state + " != exp_last_state: " + exp_last_state);

			if (b_perf) {Tools.flog_perf("-- PERF_USE_Read and Pad: " + fname, t1, writer);}
			Tools.write_lines_to_file(new String [] {nibblesStr}, 
				target_pad_fpath);
			String str2 = Tools.read_bin_file(target_pad_fpath);
			Tools.myassert(str2.equals(nibblesStr), 
				"contents not match after writing");
			if (b_perf) {Tools.flog_perf("-- PERF_USE_Read Write: " + 
				target_pad_fpath, t1, writer);}
			
		  }catch(Exception exc){
			exc.printStackTrace();
			Tools.warn("ERROR 501: " + fi.file_path + ": " + exc.toString());
			//but go on
		  }
		}

		protected void encrypt(FileInfo fi, int file_size, AC ac, 
String curve_type, int np){
		  try{
		  }catch(Exception exc){
			exc.printStackTrace();
			Tools.warn("ERROR 503: in encrypt: " + fi.file_path + ": " + exc.toString());
		  }
		}
	}


	/** For each executable in the job_file, create a sub-directory
		for in in the work_dir, and dump all the info such as
		trace and states array, needed for generating polynomial evidence
		@param curve_name: either BN254 or BLS12-381
		@param job_file: file path of the job list
		@param work_dir: where to save data to
		@param ac_dir: where the AC-DFA is located
		@param np: number of MPI nodes
		@param num_worker: worker thread (NOTE: different from MPI nodes)
			This needs to be determined at run time by the size of the
			DFA and total RAM available at the main node.
		@param server_id: this server's ID
		@param n_servers: how many servers together. So based on server_id and n_servers we can decide the chunk size to process.
		This function should ONLY be called at main node
	*/
	public void batch_preprocess(String curve_name, String job_file, 
		String ac_dir, String work_dir, int np, int num_worker,
		int server_id, int n_servers, String dfa_file){
		boolean b_perf = true;
		BufferedWriter writer = null;
		try{
			writer = new BufferedWriter(
				new FileWriter("/tmp/report_batchproc.txt"));
		}
		catch(Exception exc){ Tools.panic(exc.toString()); }

		Tools.set_log_level(Tools.LOG1);
		Tools.flog(Tools.LOG1, "\n========== Batch Preproess: job_file: " 
			+ job_file + "\n save data to: " + work_dir + "\n num_worker: " + num_worker + ", server_id: " + server_id + ", n_servers: " + n_servers + "\n StartTimer: " + Instant.now() + "\n============", writer);

		//1. load the AC-DFA
		NanoTimer t1 = new NanoTimer();
		t1.start();
		ac_dir = Tools.getAbsolutePath(ac_dir) + "/";
		AC [] arr_ac = new AC [num_worker];
		System.out.println("DEBUG USE 101: load dfa_file: " + dfa_file);
		//if(dfa_file==null){//load serialized
		//	if (b_perf) {Tools.flog(Tools.LOG1,"load DFA.dat ...",writer);}
		//	arr_ac[0] = AC.deserialize(ac_dir+ "DFA.dat");			
		//}else{
			arr_ac[0] = AC.load_clamav_fixed(dfa_file); 
			if (b_perf) {Tools.flog_perf("build DFA ...states: " + arr_ac[0].get_num_states(), t1, writer);}
		//}
		AC ac = arr_ac[0];
		for(int i=1; i<num_worker; i++){
			try{
				arr_ac[i] = (AC) arr_ac[0].clone();
			}catch(Exception exc){
				Tools.panic(exc.toString());
			}
		}
		if (b_perf) {Tools.flog_perf("replicate DFA", t1, writer);}

		//2. get the files
		int [] details = get_job_details(job_file);
		int group_id = details[0];
		int subset_id = details[1];
		FileInfo [] files_to_process_all = get_files(job_file);
		int total = files_to_process_all.length;

		//distribute the work evenly but node 0 getes most
		int [] load = new int [n_servers];
		int avg= total/n_servers;
		for(int i=0; i<n_servers; i++){
			load[i] = avg;
		}
		int left = total - avg * n_servers;
		if(left>=n_servers) throw new RuntimeException("ERROR left: " + left
			+ " >=n_servers: " + n_servers);
		for(int i=0; i<left; i++){ load[i] += 1;}
	
		int begin_idx = 0;
		for(int i=0; i<server_id; i++){ begin_idx += load[i];}
		int end_idx = begin_idx + load[server_id];

		FileInfo [] files_to_process = new FileInfo [end_idx - begin_idx];
		for(int i=0; i<end_idx-begin_idx; i++){
			files_to_process[i] = files_to_process_all[begin_idx+i];
		} 
		int group_size_nibbles = App.get_group_size_in_nibbles(group_id, np);
		if (b_perf) {Tools.flog(Tools.LOG1, "Job Details: server_id: " + server_id + ", n_servers: " + n_servers + ", begin_idx: " + begin_idx + ", end_idx: " + end_idx + ", files_to_process.len: " + files_to_process.length + ", all files: " + files_to_process_all.length+ "\n group_size_nibbles: " + group_size_nibbles, writer) ;}
		if (b_perf) {Tools.flog_perf("PERF_USE_GetFileList", t1, writer);}

		//3. process each file
		Tools.new_dir(work_dir);
		PreprocessThread [] arr_th = new PreprocessThread [num_worker];	
		for(int i=0; i<num_worker; i++){
			arr_th[i] = new PreprocessThread(i, num_worker, files_to_process,
				arr_ac[i], group_size_nibbles, work_dir, np, curve_name);
			arr_th[i].start();
		}
		for(int i=0; i<num_worker;i++){
			try{
				arr_th[i].join();
				if (b_perf) {Tools.flog(Tools.LOG1, "Thread " + i + " completed at: " + Instant.now(), writer);}
			}catch(Exception exc){
				Tools.panic(exc.toString());
			}
		}
		if (b_perf) {Tools.flog_perf("PERF_USE_ProcessAllFiles", t1, writer);}
		try{writer.close();}catch(Exception exc){Tools.panic(exc.toString());}
		
	}

	/** process of all files listed in job file
		Assuming all OPS (threads) done on ONE SERVER! (unlike batch_preprocess)
		np: is the planned number of processes. It does affect padding
		somehow (to be improved later - maybe set an upper limit of np)
		The op: supports "batch_pad", "encrypt" and "hash"
		key is only used for the hash operation
	*/
	public void multh_op(String curve_name, String job_file, String ac_dir,
		int num_worker, String dfa_sigs_path, int np, String op, BigInteger key){
		if(!op.equals("batch_pad") && !op.equals("encrypt") &&
			!op.equals("hash")){
			throw new RuntimeException("multh_op does not support: " + op);
		}
		BufferedWriter writer = null;
		try{
			writer = new BufferedWriter(
				new FileWriter("/tmp/report_multh.txt"));
		}
		catch(Exception exc){ Tools.panic(exc.toString()); }
		Tools.set_log_level(Tools.LOG1);

		//1. build the DFA
		boolean b_perf = true;
		System.out.println("batch_pad ...");
		NanoTimer t1 = new NanoTimer();
		t1.start();
		ac_dir = Tools.getAbsolutePath(ac_dir) + "/";
		AC [] arr_ac = new AC [num_worker];
		if(op.equals("batch_pad")){
			arr_ac[0] = AC.load_clamav_fixed(dfa_sigs_path);
			if (b_perf) {Tools.flog_perf("Multh_OP: " + op + 
				" Step1: build DFA .... DFA-States: " +
				arr_ac[0].get_num_states(), t1, writer);}
			for(int i=1; i<num_worker; i++){
				try{ arr_ac[i] = (AC) arr_ac[0].clone();
				}catch(Exception exc){ Tools.panic(exc.toString()); }
			}
			if (b_perf) {Tools.flog_perf("Multh_Op: Step 2: dup DFA: num: " + 
			arr_ac.length, t1, writer);}
		}else{
			if (b_perf) {Tools.flog_perf("Multh_Op: Step 1-2: skip loading DFA",
			 t1, writer);}
		}

		//2. retrieve the file list
		int [] details = get_job_details(job_file); //MISUSE IT group_id
		//is treated as file_size
		int file_size= details[0];
		int subset_id = details[1];
		FileInfo [] files_to_process= get_files(job_file);
		//System.out.println("file_size: " + file_size);

		//3. starts process thread and wait for them
		WorkerThread [] arr_th = new WorkerThread [num_worker];	
		for(int i=0; i<num_worker; i++){
			arr_th[i] = new WorkerThread(i, num_worker, files_to_process,
				arr_ac[i], file_size, curve_name, op, key, np);
			arr_th[i].start();
		}
		for(int i=0; i<num_worker;i++){
			try{
				arr_th[i].join();
				if (b_perf) {Tools.flog(Tools.LOG1, "Thread " + i + " completed at: " + Instant.now(), writer);}
			}catch(Exception exc){ Tools.panic(exc.toString()); }
		}
		if (b_perf) {Tools.flog_perf("PERF_USE_ProcessAllFiles", t1, writer);}
		try{writer.close();}catch(Exception exc){Tools.panic(exc.toString());}
	}
	class FileInfo{
		public String file_path; 
		public int offset;
		public int size;
		public int group_id;
		public int start_state;
		public int end_state;
		public int depth;

		@Override
		public String toString(){
			return "fpath: " + file_path + ", offset: " + offset
				+ ", size: " + size + ", start_state: " + start_state
				+ ", end_state: " + end_state
				+ ", depth: " + depth;
		}
	}


	/** extract a list of file paths to process */
	protected FileInfo [] get_files(String jobfiles){
		String [] lines = Tools.readLines(jobfiles);
		ArrayList<FileInfo> arr = new ArrayList<>();
		for(String line: lines){
			if (line.indexOf("#")==0) continue;
			String [] arrWords = line.split(" ");
			FileInfo fi = new FileInfo();
			String fpath = arrWords[0];
			int idx = fpath.indexOf("_partx71");
			//if(idx>0) {fpath = fpath.substring(0, idx);}
			fi.file_path = fpath;
			fi.size = Integer.parseInt(arrWords[1]);
			fi.group_id = Integer.parseInt(arrWords[2]);
			fi.offset = Integer.parseInt(arrWords[3]);
			fi.depth = Integer.parseInt(arrWords[4]);
			fi.start_state = Integer.parseInt(arrWords[5]);
			fi.end_state = Integer.parseInt(arrWords[6]);
			arr.add(fi);
		}
		FileInfo [] arr_res = new FileInfo [arr.size()];
		arr_res = arr.toArray(arr_res);
		return arr_res;	
	}

	/** return the file name of it */
	protected String get_file_name(String filepath){
		Path path = Paths.get(filepath);
		String fname = path.getFileName().toString();
		return fname;
	}

	/** get the [subgruop_id, subset_id] */
	protected int [] get_job_details(String job_file){
		String job_file_name = get_file_name(job_file);
		job_file_name = job_file_name.substring(0, job_file_name.length()-4);
		String [] arr = job_file_name.split("_");
		if(!arr[0].equals("job")){ Tools.panic("job_file: " + job_file + " does not start with 'job'");}
		String s_group = arr[1];
		String s_subsetid = arr[2];
		int groupid = Integer.parseInt(s_group);
		int subsetid = Integer.parseInt(s_subsetid);
		return new int [] {groupid, subsetid};
	}

}
