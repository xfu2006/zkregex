/*******************************************************************************
	Copyright Dr. CorrAuthor
	All Rights Reserved.
	Author: Dr. CorrAuthor
 	Created: 11/10/2022
	Refined: 12/28/2022: added genvars
 *******************************************************************************/

/*************************************************************
	This class takes a polynomial evidence directory,
	and generates the R1CS for ZaModularVerifierV3
	and dump the r1cs into the specified directory.
	Expected arguments:
		chunks_252bit: number of chunks per 252-bit (file length
			required to be multiple of 252 - IMPROVE LATER:
			this wastes a bit for bls12-381)A
		idx: the index of the circuilt in the "np" circuits in parallel
		np: number of parallel circuits
		poly_dir: the directory that contains the polynomial evidence
		case_id: the unique random number for case
		max_final_states: the MAX final states (used for constructor)
		
* *************************************************************/
package za_interface;

import za_interface.za.Utils;
import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import java.util.ArrayList;
import java.util.Random;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileReader;
import java.io.BufferedReader;
import circuit.structure.CircuitGenerator;
import java.math.BigInteger;
import za_interface.za.circs.zkreg.*;

public class ZaRegexCircRunner{

	// ----------------- Utility Functions ---------------------
	/**  remove directory completely.  */
	public static void del_dir_worker(File todel){
		if(!todel.exists()) {return;}
		File[] allContents = todel.listFiles();
    	if (allContents != null) {
        	for (File file : allContents) {
            	del_dir_worker(file);
        	}
		}
		todel.delete();
    }

	/** security check: no space bars, and must contain DATA */
	public static void validate_path(String dirpath){
		if(dirpath.indexOf(" ")>=0 || dirpath.indexOf("DATA")<0){
			panic("newdir does not allow dirpath: " + dirpath);
		}
	}

	/** remove a directory */
	public static void del_dir(String dirpath){
		validate_path(dirpath);
		del_dir_worker(new File(dirpath));
	}

	/** if the dir exists, remove all; and then create */
	public static void new_dir(String dirpath){
		del_dir_worker(new File(dirpath));
		new File(dirpath).mkdirs();
	}

	public static void panic(String msg){
		System.err.println("PANIC: " + msg);
		System.exit(1);
	}

	/** read as a byte array and for every 8 bytes (64-bits)
		convert it to a BigInteger. n is the expected number of elements.
	*/
	public static ArrayList<BigInteger> read_arr_from_file(String fpath, int n){
		ArrayList<BigInteger> arr = new ArrayList<>();
		try{
			Path path = Paths.get(fpath);
			byte [] barr = Files.readAllBytes(path);
			int total_len = barr.length;
			if(total_len%n!=0){
				throw new RuntimeException("ERROR ZaRegexRunner: read_arr_from_file: " + fpath +". total_len%n !=0. Total_len: " + 
					total_len + ", n: " + n);
			}
	
			int unit_len = total_len/n;
			byte [] unit = new byte [unit_len];
			for(int i=0; i<n; i++){
				//1. copy over the bytes
				for(int j=0; j<unit_len; j++){
					unit[unit_len-1-j] = barr[i*unit_len + j];
				}
	
				//2. construct BigInteger
				BigInteger bi = new BigInteger(unit);
				if(bi.signum()<0){ panic("Get a negative field element!"); }
				arr.add(bi);
			}
			return arr; 
		}catch(Exception exc){
			//exc.printStackTrace(System.out);
			panic(exc.toString());
			return null;
		}
	}

	 public static BigInteger [] read_arr_fe(String fpath){
        BufferedReader reader;
        try{
            reader = new BufferedReader(new FileReader(fpath));
            String line = reader.readLine();
			int num = Integer.valueOf(line);
			line = reader.readLine();
			BigInteger [] arr = new BigInteger [num];
			int idx = 0;
            while(line!=null){
				BigInteger v = new BigInteger(line);
                line = reader.readLine();
				arr[idx] = v;
				idx++;
            }
        	return arr;
        } catch(Exception exc){
                panic(exc.toString());
				return null;
        }
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

		chunk_inputs wihch has the following: (37 elements)
		z, r1, r2
        hash_in, p_acc_states_in, p_acc_trans_in, 
        v_s_p_in, v_s_pd_in, v_s_gcd_in, v_s_p_gcd_in, v_s_pd_gcd_in, vs_s, v_s_t_in,
        v_t_p_in, v_t_pd_in, v_t_gcd_in, v_t_p_gcd_in, v_t_pd_gcd_in, vs_s_in, v_t_t_in,
        hash_out, p_acc_states, p_acc_trans
        v_s_p, v_s_pd, v_s_gcd, v_s_p_gcd, v_s_pd_gcd, vs_s, v_s_t,
        v_t_p, v_t_pd, v_t_gcd, v_t_p_gcd, v_t_pd_gcd, vs_s, v_t_t,
	
	*/
	public static BigInteger [] collect_modular_verifier_witness_for_node(String dirpath, int id, int np, int total_len){
		int n = id<np-1? total_len/np: total_len%np + total_len/np;
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
			43	
		};
		int my_total_len = 0;
		for(int i=0; i<arr_size.length; i++){my_total_len+=arr_size[i];}
		ArrayList<BigInteger> all_list = new ArrayList<>();
		for(int i=0; i<raw_fnames.length; i++){
			String fpath = witdir+ "/" + raw_fnames[i] + ".node_" + id;
			int size = arr_size[i];
			ArrayList<BigInteger> ai = read_arr_from_file(fpath, size);
			if(ai.size()!=arr_size[i]){
				throw new RuntimeException("ERROR in processing " + fpath + ". expected size: " + size + ", actual: " + ai.size());
			}
			all_list.addAll(ai);
		}
		BigInteger [] arrW = all_list.toArray(new BigInteger [all_list.size()]);
		return arrW;
	}
	/** Generates the r1cs for the given ZaCirc.
		Save the circuit to circuits/case_id/id
		The polynomial_evidence are in poly_dir
	*/
	public static void genr1cs(ZaCirc circ, String case_id, int id, int np, String poly_dir, int total_len){
		//1. set up params
		long time_now = System.currentTimeMillis();
		ZaGenerator zg = circ.getGenerator();
		CircuitGenerator.setActiveCircuitGenerator(zg);
		circ.getConfig().apply_config();
		String dirpath = "circuits/" + case_id + "/" + id + "/";
		String prefix = "  ";
		Utils.log(Utils.LOG1, prefix + "Write Circ: " + circ.getName() + ", Config: " + circ.getConfig().toString());

		//2. generate the input
		BigInteger [] arrWit= collect_modular_verifier_witness_for_node(poly_dir, id, np, total_len);
		BigInteger [] ar = read_arr_fe(poly_dir+"/r.dat");
		BigInteger [] arrPub= {};//r and r_inv moved witness, will be disclosed
								//in the public output in the last mdule

		//3. generate the circuit file 
		PrimeFieldInfo info = circ.getConfig().field_info;
		zg.setPresetInputs(arrPub, arrWit);
		zg.generateCircuit();
		new_dir(dirpath);
		long time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "JsnarkStep 2: Create and Write Circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		zg.evalCircuit();
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "JsnarkStep 3: Eval Circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		zg.prepFiles(dirpath, info.name);
		zg.genR1cs(info, dirpath, true);
		zg.genConnVars(info, dirpath, circ.get_connector_wire_ids());

		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "JsnarkStep 4: Call LibSnark to generate R1CS: " + (time_now2-time_now) + " ms");
		time_now = time_now2;


	}

	/** Generates the variable VALUES only! The values will
	be consistent with distributed vars part of genr1cs (...r1cs assignments
	part). and the file name is: new_var_assign.txt.
	*/
	public static void genvars(ZaCirc circ, String case_id, int id, int np, String poly_dir, int total_len){
		genvars_slow(circ, case_id, id, np, poly_dir, total_len);
	}

	/** Generates the variable VALUES only! The values will
	be consistent with distributed vars part of genr1cs (...r1cs assignments
	part). and the file name is: new_var_assign.txt.
	*/
	public static void genvars_slow(ZaCirc circ, String case_id, int id, int np, String poly_dir, int total_len){
		//1. set up params
		long time_now = System.currentTimeMillis();
		long time_start = time_now;
		ZaGenerator zg = circ.getGenerator();
		CircuitGenerator.setActiveCircuitGenerator(zg);
		circ.getConfig().apply_config();
		String dirpath = "circuits/" + case_id + "/" + id + "/";
		BigInteger [] arrWit= collect_modular_verifier_witness_for_node(
			poly_dir, id, np, total_len);
		BigInteger [] ar = read_arr_fe(poly_dir+"/r.dat");
		BigInteger [] arrPub= {};//r and r_inv moved witness, will be disclosed
								//in the public output in the last mdule

		//ArrayList<BigInteger> arrw = new ArrayList<>();
		//for(int i=0; i<arrWit.length; i++) arrw.add(arrWit[i]);
		//Utils.write_arr_to_file(arrw, dirpath + "arr_wit1.dat");

		long time_now2 = System.currentTimeMillis();
		String prefix = "      ";
		Utils.log(Utils.LOG1, prefix + "GenVars Step1: Read Witness: " + (time_now2-time_now) + "ms");
		time_now = time_now2;

		//3. generate the circuit file 
		PrimeFieldInfo info = circ.getConfig().field_info;
		zg.setPresetInputs(arrPub, arrWit);
		zg.generateCircuit();
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step2: Create Circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		zg.evalCircuit();
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step3: Eval Circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		//4. Call Zg to genrate vars
		//zg.prepFiles(dirpath, info.name);
		zg.genVars(info, dirpath, circ.get_connector_wire_ids());
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step4: GenVars: " + (time_now2-time_now) + " ms");
		time_now = time_now2;
		Utils.log(Utils.LOG1, prefix + "GenVars Total: "+ (time_now2-time_start) + " ms");
	}

	/** FAST version by loading the circ from serialization, assuming it's ALREADY generated in the genr1cs */
	public static void genvars_not_used(ZaCirc circ, String case_id, int id, int np, String poly_dir, int total_len){
		//1. set up params
		long time_now = System.currentTimeMillis();
		long time_start = time_now;
		ZaGenerator zg = circ.getGenerator();
		CircuitGenerator.setActiveCircuitGenerator(zg);
		circ.getConfig().apply_config();
		String dirpath = "circuits/" + case_id + "/" + id + "/";
		BigInteger [] arrWit= collect_modular_verifier_witness_for_node(
			poly_dir, id, np, total_len);
		BigInteger [] ar = read_arr_fe(poly_dir+"/r.dat");
		BigInteger [] arrPub= {};//r and r_inv moved witness, will be disclosed
								//in the public output in the last mdule
		String prefix = "      ";


		long time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step1: Read Witness: " + (time_now2-time_now) + "ms");
		time_now = time_now2;

		time_now2 = System.currentTimeMillis();
		String circ_file = dirpath + "zg_circ.dump"; 
		ZaGenerator zg2 = (ZaGenerator) Utils.deserialize_from(circ_file);
		//zg.force_onetimeSetCirc(circ);
		//circ.force_setGenerator(zg);
		time_now = time_now2;
		Utils.log(Utils.LOG1, prefix + "GenVars Step2: DESERIALIZE circ: " + (time_now2-time_now) + "ms");
		time_now = time_now2;


		//3. generate the circuit file 
		PrimeFieldInfo info = circ.getConfig().field_info;
		zg.setPresetInputs(arrPub, arrWit);
		zg.generateCircuit(); //DO NOT load 
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step2.5: Create Circuit BUT SKIP build_circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		zg.evalCircuit();
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step3: Eval Circuit: " + (time_now2-time_now) + " ms");
		time_now = time_now2;

		//4. Call Zg to genrate vars
		//zg.prepFiles(dirpath, info.name);
		zg.genVars(info, dirpath, circ.get_connector_wire_ids());
		time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, prefix + "GenVars Step4: GenVars: " + (time_now2-time_now) + " ms");
		time_now = time_now2;
		Utils.log(Utils.LOG1, prefix + "GenVars Total: "+ (time_now2-time_start) + " ms");
	}

	//-----------------------------------------------------
	// ------------ MAIN PROGRAM --------------------------
	//-----------------------------------------------------
	/** use run.sh to run it */	
	public static void main(String [] args){

		//1. processing arguments
		if(args.length!=8){
			System.out.println("Expect args: genr1cs|genvar chunks_252bit idx np poly_dir case_id curve_type max_states");
			System.exit(1);
		}
		Utils.setLogLevel(Utils.LOG2);
		String usage = args[0];
		int chunks_252bit = Integer.valueOf(args[1]);
		int total_len = chunks_252bit * (252/4);
		int idx = Integer.valueOf(args[2]);
		int np = Integer.valueOf(args[3]);
		String poly_dir = args[4];
		String case_id = args[5];
		String curve_type = args[6].trim();
		if(curve_type.equals("BLS12-381") || curve_type.indexOf("381")>=0){
			curve_type = "Bls381";
		}
		int max_final_states = Integer.valueOf(args[7].trim());
		Utils.log(Utils.LOG1, "********************************");	
		Utils.log(Utils.LOG1, "     Generating Circuit Files   ");
		Utils.log(Utils.LOG1, "chunk_252_bits: " + chunks_252bit + ", idx: " + idx + ", np: " + np + ", poly_dir: " + poly_dir + ", case_id: " + case_id + ", curve_type: " + curve_type + ", total_len: " + total_len + ", max_final_states: " + max_final_states);
		Utils.log(Utils.LOG1, "********************************");	

		//2. create the circuit
		long time_now = System.currentTimeMillis();
		ZaConfig config = ZaConfig.new_config_by_curve(curve_type);
		int state_bits = 4;
		
		ZaCirc circ = new ZaModularVerifier(config, null, 
			total_len, state_bits, idx, np, max_final_states);
		long time_now2 = System.currentTimeMillis();
		Utils.log(Utils.LOG1, "JsnarkStep 1: Creating Circ Object in Java: " + (time_now2-time_now) + " ms");

		//3. generate R1CS
		if(usage.equals("genr1cs")){
			genr1cs(circ, case_id, idx, np, poly_dir, total_len);
		}else if(usage.equals("genvars")){
			genvars(circ, case_id, idx, np, poly_dir, total_len);
		}else{
			throw new RuntimeException("UNKNOWN operation: " + usage);
		}
	}


}
