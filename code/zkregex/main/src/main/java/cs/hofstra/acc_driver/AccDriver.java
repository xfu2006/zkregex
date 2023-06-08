/** Efficient Zero Knowledge Project
	Driver of the RUST implementation of the Polynomial and Accumulator
	package. Run it as external Linux command and exchange info using files.
	Author: Dr. CorrAuthor
	Created: 06/27/2022
*/ 

package cs.Employer.acc_driver;
import cs.Employer.zkregex.Tools;
import cs.Employer.zkregex.NanoTimer;
import za_interface.za.Utils;
import za_interface.za.circs.zkreg.*;
import za_interface.za.*;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Arrays;

public class AccDriver{
	/** Treat multi-set A = {a_i} as a polynomial, with length n.
		Build the following polynomial of all degree n (size coefs 
		vector size: n+1).
		(1) P = \prod (x-a_i) [the polynomial]
		 -- PD = derivitative_of_P (pad zero on degree n)
			this is derived directly in the circuit, no need to provide
			as a witness
		(2) GCD = gcd(P, P') 
		(3) P_GCD = P-GCD [this is the set support!]
		(4) PD_GCD = PD-GCD
		(5,6) S and T: s.t. S*P_GCD + T*PD_GCD = 1 (co-prime proof)
		Note: P_GCD is the set-support (standard set extracted from multi-set)
	We have two multi-sets: states and transitions, Each has (6) entries
	shown above: Note the polys for states have actually 1 more degree,
    to make it even for both; pad zero on the higher degree for transitions.
		[0] S_P: polynomial for states where "S" stands for states
		[1] S_GCD: GCD of states 
		[2] S_P_GCD: P-GCD for states
		[3] S_PD_GCD: Derivative of P - GCD
		[4] S_S: S,T Bizou coefs		
		[5] S_T
		[6] T_P: polynomial for transitions with "T" stands for transitions
		[7] T_GCD: GCD for transitions' poly and derivative
		[8] T_P_GCD: P-GCD for transitions
		[9] T_PD_GCD: PD-GCD for transitions
		[10] T_S: Bizout's coefs S,T
		[11] T_T
		---
		[12] S_ST
		[13] T_ST s.t. S_ST * S_P_GCD + T_ST * T_P_GCD = 1 (to show 
			set supports of states and transitions are disjoint)
	*/
	public ArrayList<ArrayList<BigInteger>> 
		gen_poly_evidence(BigInteger [] states, BigInteger [] trans){
		//1. validity check of input
		if(states.length!=trans.length+1){
			Tools.panic("state.len!=trans.len+1");
		}
		int n = states.length + 1;

		//2. write the data to temp
		String abspath = Tools.getAbsolutePath("../DATA");
		String dirname = Tools.randStr("polyevid");
		//REMOVE LATER -----------
		dirname = "polyevid_001";
		//REMOVE LATER ----------- ABOVE
		String dirpath = abspath + "/" + dirname;
		String state_fpath = dirpath + "/states.dat";
		String trans_fpath = dirpath + "/trans.dat";
		String witdir = dirpath + "/witness";
		Tools.new_dir(dirpath);
		Tools.new_dir(witdir);
		
		Tools.write_arr_to_file( new ArrayList(Arrays.asList(states)), 
			state_fpath);
		Tools.write_arr_to_file( new ArrayList(Arrays.asList(trans)), 
			trans_fpath);
			

		//3. call the MPI run command
		MPIConfig mcfg = new MPIConfig(); //setting in config/MPI_CONFIG.txt
		String [] args = mcfg.gen_mpirun_params("gen_circ_witness_serial " + dirpath + " " + n);
		String res = Tools.run(args);
		System.out.println(res);

		//4. collect the data from files
		String [] raw_fnames = new String [] {//see class doc
			"S_P", "S_GCD", "S_P_GCD", "S_PD_GCD", "S_S", "S_T", 
			"T_P", "T_GCD", "T_P_GCD", "T_PD_GCD", "T_S", "T_T", 
			"S_ST", "T_ST"	
		};
		ArrayList<ArrayList<BigInteger>> all_list = new ArrayList<>();
		for(int i=0; i<raw_fnames.length; i++){
			String fpath = witdir+ "/" + raw_fnames[i];
			ArrayList<BigInteger> ai = Tools.read_arr_from_file(fpath, n);
			//System.out.println(raw_fnames[i] + " size: " 
			//+ ai.size() + ", [0]:" + ai.get(0) + ", [1]: " +ai.get(1));
			all_list.add(ai);
		}
		return all_list;
	}

	/** return the file path for random case ID */
	public String get_case_path(String randcase_id){
		String abspath = Tools.getAbsolutePath("../DATA/" + randcase_id);
		return abspath;		
	}

	/** remove the folder ../DATA/rand_caseid */
	public void clear_data(String randcase_id){
		String pathname = get_case_path(randcase_id);
		//REMOVE LATER -----------
		//Tools.del_dir(pathname);
		//REMOVE LATER ----------- RECOVER LATER ABOVE
	}

	/** duplicate the states of each subsequent segment as the ending
		state of each chunk. That is, the beginning state of
		each segment is actually ''doubly'' counted twice, one as
		the beginning state and the other as the ending state of
		the previous chunk. Merge all back. */
	public BigInteger [] massage_states(BigInteger [] states, int np){
		int n = states.length; 
		int unit_size = n/np;
		BigInteger [] res = new BigInteger [n + np -1];
		int idx = 0;
		for(int i=0; i<np; i++){
			int my_unit_size= i<np-1? unit_size: n%np + unit_size;
			for(int j=0; j<my_unit_size; j++){
				res[idx++] = states[i*unit_size + j];
			}
			if(i<np-1){//just except last one
				res[idx++] = states[(i+1)*unit_size];
			}
		}
		if(idx!=res.length){
			Tools.panic("idx: " + idx + "!=res.length: " +res.length);
		}
		return res;
	}	

	/** test if chunked hash is working */
	private void test_hash(BigInteger [] arrAlignedInput, int np){
		BigInteger key = Utils.itobi(1233);
		BigInteger [] arr2 = compute_hash_in_worker(arrAlignedInput, key, np, true, "BN254")[1];
		BigInteger exp = hash(arrAlignedInput, key, "BN254");
		BigInteger act = arr2[arr2.length-1];
		for(int i=0; i<arr2.length; i++){
			System.out.println("DEBUG USE 100: i: " + i + ": " + 
				arr2[i]);
		}
		if(!exp.equals(act)){
			Tools.panic("ERROR in hash: act: " + act + ", exp: " + exp);
		}else{
			System.out.println("PASSING in hash: act: " + act + ", exp: " + exp);
		}
	}

	/** Generate the following data for each NODE in the given folder.
	np: number of moudles.
	r - the randon nonce for poly eval */
	public void gen_poly_evidence_for_modular_verifier(BigInteger [] arrStates, BigInteger [] arrInput, BigInteger [] arrBFail, BigInteger [] arrAlignedInput, BigInteger [] arrTransNum, String caseid, int np, BigInteger r, BigInteger r_inv, BigInteger z, BigInteger r1, BigInteger r2, BigInteger key, String curve_type){
		//1. validity check of input
		if(arrStates.length!=arrTransNum.length+1){
			Tools.panic("state.len!=trans.len+1");
		}
		int n = arrAlignedInput.length;

		//2. write the data to temp
		String dirpath = get_case_path(caseid);
		Tools.new_dir(dirpath);
		String witdir = dirpath + "/witness";
		Tools.new_dir(witdir);
		String [] paths = {"states.dat", "trans.dat", "arr_input.dat", "arr_bfail.dat", "arr_aligned.dat", "hash_in.dat", "encrypt_in.dat", "r.dat"};
		arrStates = massage_states(arrStates, np);
		BigInteger [][] arr2d= compute_hash_in_worker(arrAlignedInput, key, np, true, curve_type); //thus size will be np+1 with the last as the ENTIRE output.
		BigInteger [] arrHashIn = arr2d[1];
		BigInteger [] arrEncryptIn = arr2d[0];
		BigInteger [] arrR = new BigInteger [] {r, r_inv, z, r1, r2, key, r, r_inv};


		BigInteger [][] data = {arrStates, arrTransNum, arrInput, arrBFail, arrAlignedInput, arrHashIn, arrEncryptIn, arrR};
		for(int i=0; i<paths.length; i++){
			Tools.write_arr_to_file(new ArrayList(Arrays.asList(data[i])),
				dirpath + "/" + paths[i]);
		}
		

		//3. call the MPI run command
		MPIConfig mcfg = new MPIConfig(np); //setting in config/MPI_CONFIG.txt
		String tmpnode_list = "/tmp/tmp_nodelist.txt";
		String [] args = mcfg.gen_mpirun_params("gen_poly_for_modular_verifier " + dirpath + " " + n + " " + np + " " + curve_type + " " + tmpnode_list);
		String res = Tools.run(args);
		System.out.println(res);

	}

	/** computed the hash_in and encrypt in for each chunk.
		The 1st is the encrypt_in [], and the second is
		the hash_in [] */
	public BigInteger [][] compute_hash_in(BigInteger [] arrAlignedInput, BigInteger key, int np, String curve_type){
		//last param: false: don't genereate extra
		return compute_hash_in_worker(arrAlignedInput, key, np, false, curve_type); 
	} 

	/** produce the final hash */
	public BigInteger hash(BigInteger [] arrAlignedInput, BigInteger key, String curve_type){
		ZaConfig cfg = ZaConfig.new_config_by_curve(curve_type);
		ZaModularVerifier za = ZaModularVerifier.new_ZaModularVerifier(cfg, 1, 0, 4);
		BigInteger [] enc= za.logical_build_encrypt(arrAlignedInput, Utils.itobi(0), key);
		BigInteger res =za.logical_build_hash(enc, Utils.itobi(0));
		return res;
	}

	/** use bLast to indicate whether to generate the last.
		Return two BigInteger arrays, the first is encrypt_in []
		the second is hash_in [] */
	public BigInteger [][] compute_hash_in_worker(BigInteger [] arrAlignedInput, BigInteger key, int np, boolean bGenLast, String curve_type){
		int total = bGenLast? np+1: np;
		BigInteger [] res_hash = new BigInteger [total];
		BigInteger [] res_encrypt = new BigInteger [total];
		int n = arrAlignedInput.length;
		res_hash[0] = Utils.itobi(0); //initial IV vector
		res_encrypt[0] = Utils.itobi(0); //IV vector
		ZaConfig cfg = ZaConfig.new_config_by_curve(curve_type);
		ZaModularVerifier za = ZaModularVerifier.new_ZaModularVerifier(cfg, 1, 0, 4);

		
		for(int i=0; i<total-1; i++){
			int unit = i<np-1?n/np: n/np + n%np; 
			BigInteger [] chunk = new BigInteger[unit];
			for(int j=0; j<unit; j++){
				chunk[j] = arrAlignedInput[i*(n/np)+ j];
			}

			BigInteger [] enc= za.logical_build_encrypt(chunk,res_encrypt[i], key);
			res_encrypt[i+1]= enc[enc.length-1];
			res_hash[i+1]= za.logical_build_hash(enc, res_hash[i]);
		}
		return new BigInteger [][] {res_encrypt, res_hash};
	} 

	/** treat it like a single thread-mode no still needs the np, 
		as for chunks, only half info is used somehow
		different from all-in-one array encryption. will improve
		later*/
	public BigInteger [] compute_encryption(BigInteger [] arrAlignedInput, BigInteger key, String curve_type, int np){
		int n = arrAlignedInput.length;
		BigInteger encrypt_in = Utils.itobi(0); //IV vector
		ZaConfig cfg = ZaConfig.new_config_by_curve(curve_type);

		int total = np + 1;
		BigInteger [] res_encrypt = new BigInteger [total];
		BigInteger [] ret = new BigInteger [n/32*2];
		res_encrypt[0] = Utils.itobi(0); //IV vector
		ZaModularVerifier za = ZaModularVerifier.
			new_ZaModularVerifier(cfg, 1, 0, 4);
	
		int idx = 0;	
		for(int i=0; i<total-1; i++){
			int unit = i<np-1?n/np: n/np + n%np; 
			BigInteger [] chunk = new BigInteger[unit];
			for(int j=0; j<unit; j++){
				chunk[j] = arrAlignedInput[i*(n/np)+ j];
			}

			BigInteger [] enc= za.logical_build_encrypt(chunk,res_encrypt[i], key);
			for(int j=0; j<enc.length; j++){
				ret[idx++] = enc[j];
			}
			res_encrypt[i+1]= enc[enc.length-1];
		}

		BigInteger [] real_ret = new BigInteger [idx];
		for(int i=0; i<idx; i++) real_ret[i] = ret[i];
		
		return real_ret;
	} 

	/** treat it like a single thread-mode  */
	public BigInteger compute_hash(BigInteger [] arrAlignedInput, BigInteger key, String curve_type, int np){
		int n = arrAlignedInput.length;
		BigInteger encrypt_in = Utils.itobi(0); //IV vector
		ZaConfig cfg = ZaConfig.new_config_by_curve(curve_type);

		int total = np + 1;
		BigInteger [] res_hash = new BigInteger [total];
		BigInteger [] ret = new BigInteger [n];
		res_hash[0] = Utils.itobi(0); //IV vector
		ZaModularVerifier za = ZaModularVerifier.
			new_ZaModularVerifier(cfg, 1, 0, 4);
	
		for(int i=0; i<total-1; i++){
			int unit = i<np-1?n/np: n/np + n%np; 
			BigInteger [] chunk = new BigInteger[unit];
			for(int j=0; j<unit; j++){
				chunk[j] = arrAlignedInput[i*(n/np)+ j];
			}
			res_hash[i+1]= za.logical_build_hash(chunk,res_hash[i]);
		}
		return res_hash[res_hash.length-1];
	} 


	/** Return the witness array for node i. for modular verifier
		Layout as follows: where n is the input chars of the chunk.
		arrStates (2n+1),  
		arrInput (2n), 
		arrBFail (2n), 
		arrAlignedInput(n), 
		Then the following 12 arrays are each of 2n+2 elements
		S_P, S_GCD, S_P_GCD, S_PD_GCD, S_S, S_T
		T_P, T_GCD, T_P_GCD, T_PD_GCD, T_S, T_T,

		chunk_inputs wihch has the following: (42 elements)
		z, r1, r2, key
        hash_in, p_acc_states_in, p_acc_trans_in, 
        v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, vs_s, v_s_t_in,
        v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, vs_s_in, v_t_t_in, encrypt_in 
        hash_out, p_acc_states, p_acc_trans
        v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, vs_s, v_s_t,
        v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, vs_s, v_t_t,
		encrypt_out
		
	
	*/
	public BigInteger [] collect_modular_verifier_witness_for_node(int id, String caseid, int np, int total_len){
		int n = id<np-1? total_len/np: total_len%np + total_len/np;
		String dirpath = get_case_path(caseid);
		String witdir = dirpath + "/witness";
		String [] raw_fnames = new String [] {//see class doc
			"states.dat", "arr_input.dat", "arr_bfail.dat", "arr_aligned.dat",
			"S_P", "S_GCD", "S_P_GCD", "S_PD_GCD", "S_S", "S_T", 
			"T_P", "T_GCD", "T_P_GCD", "T_PD_GCD", "T_S", "T_T", 
			"chunk_inputs.dat",
		};
		int total_s_size = 2*total_len + np + 1;
		int total_t_size = 2*total_len + 1;
		int s_size = id<np-1? total_s_size/np: total_s_size/np + total_s_size%np;
		int t_size = id<np-1? total_t_size/np: total_t_size/np + total_t_size%np;
		int [] arr_size = {
			2*n+1, 2*n, 2*n, n,
			s_size, s_size, s_size, s_size, s_size, s_size,
			t_size, t_size, t_size, t_size, t_size, t_size,
			42	
		};
		ArrayList<BigInteger> all_list = new ArrayList<>();
		for(int i=0; i<raw_fnames.length; i++){
			String fpath = witdir+ "/" + raw_fnames[i] + ".node_" + id;
			int size = arr_size[i];
			ArrayList<BigInteger> ai = Tools.read_arr_from_file(fpath, size);
			if(ai.size()!=arr_size[i]){
				Tools.panic("ERROR in processing " + fpath + ". expected size: " + size + ", actual: " + ai.size());
			}
			all_list.addAll(ai);
		}
		BigInteger [] arrW = all_list.toArray(new BigInteger [all_list.size()]);
		return arrW;
	}
	
}

