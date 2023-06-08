/** Efficient Zero Knowledge Project
	Paper Data Collection
	Author: Dr. CorrAuthor
	Created: 04/09/2022
*/ 
package cs.Employer.zkregex;
import cs.Employer.acc_driver.*;
import java.util.ArrayList;
import java.io.*;
import java.util.Map;

public class PaperData{
	// ---- DATA MEMBERS -----
	public int get_log_nodes(String server){
		int log_nodes = 2; //2 for 2d, 4 for 32d, 8 for 256-nodes
		if(server.equals("bd32")){
			log_nodes = 5;
		}else if(server.equals("hpc")){
			log_nodes = 8;
		}
		return log_nodes;
	}
	public void quick_test(String server){
		int log_nodes = get_log_nodes(server);
		collect_poly_data("fft", 24, 24, 1,   log_nodes, log_nodes, 1, Tools.getAbsolutePath(".//quick_test.dump"), 1, 200, true);	
		Tools.run(new String [] {"cat", "quick_test.dump"});
		System.out.println("Expected: Local host: 5.3 sec, 2d: 10 sec, 32-d server: 2.3 sec, 256-node: 500 ms");
	}

	public void collect_samples(String server){
		int timeout = 500; //500 secods
		int attempts = 1;
		int log_nodes = get_log_nodes(server);
		collect_poly_data("fft", 16, 32, 1,   2, log_nodes, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/fft_good.dump"), attempts , timeout, true);	 //1 rayon thread
		collect_poly_data("mul", 16, 32, 1,   2, log_nodes, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/mul_good.dump"), attempts , timeout, true);	 //1 rayon thread
		collect_poly_data("div", 16, 32, 1,   2, log_nodes, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/div_good.dump"), attempts , timeout, true);	 //1 rayon thread
		collect_poly_data("serial_gcd", 10, 32, 1,   1, 1, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/serial_gcd_good.dump"), attempts , timeout, true);	 //1 rayon thread
		collect_poly_data("gcd", 10, 32, 1,   1, 1, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/serial_gcd_good.dump"), attempts , timeout, true);	 //1 rayon thread
		collect_poly_data("groth16prove", 16, 30, 1,   2, log_nodes, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/groth_good.dump"), attempts , timeout, true);	 //1 rayon thread
	}
	public void collect_all_data(){
		String server = "hpc";
		quick_test(server);
		//collect_samples(server);
		// -------------------------------------
		//collect_poly_data("fft", 16, 26, 1,   1, 3, 1, Tools.getAbsolutePath(".//data/dump/" + server + "/fft_good.dump"), 1, 100, true);	 //1 rayon thread
		//collect_poly_data("mul", 20, 32, 1,   2, 8, 1, Tools.getAbsolutePath("./data/dump/hpc/mul_hpc256.dump"), 3, 30);	
		//collect_poly_data("div",22 , 23, 1,   2, 3, 1, Tools.getAbsolutePath("data/dump/local/div_quick_test.dump"), 1, 100);	
		//-------------------------------------
		//collect_poly_data("div", 16, 30, 1,   2, 8, 1, Tools.getAbsolutePath("data/dump/hpc/div_02_23_23.dump"), 1, 225);	
		//collect_poly_data("gcd", 20, 22, 1,   4, 4, 1, Tools.getAbsolutePath("data/dump/bigdata/gcd_quick_test.dump"), 1, 500);	
		//collect_poly_data("gcd", 20, 20, 1,   2, 8, 3, Tools.getAbsolutePath("data/dump/hpc/gcd_4_32_256.dump"), 1, 1000);	
		//collect_poly_data("gcd_new", 17, 17, 1,   7, 8, 1, Tools.getAbsolutePath("data/dump/local/new_gcd17_quick_test.dump"), 1, 200);	
/*
		int start_log_size = 12;
		int steps = 5;
		for(int log_size = start_log_size, cpus=1; log_size<start_log_size + steps; log_size++, cpus++){
			collect_poly_data("groth16prove", log_size, log_size, 1,   cpus, cpus, 1, Tools.getAbsolutePath("data/dump/local/scale_" + cpus+".dump"), 1, 500);	
		}
*/
//		collect_poly_data("groth16prove", 16, 16, 1,   2, 2, 1, Tools.getAbsolutePath("data/dump/local/groth16_20_4.dump"), 1, 2000);	
		//collect_poly_data("groth16prove", 30, 30, 1,   8, 8, 1, Tools.getAbsolutePath("data/dump/hpc/groth16_30_256.dump"), 1, 2000);	
		//collect_poly_data("groth16prove", 27, 27, 1,   8, 8, 1, Tools.getAbsolutePath("data/dump/hpc/groth16_27_256.dump"), 1, 2000);	
		//collect_poly_data("groth16prove", 29, 29, 1,   8, 8, 1, Tools.getAbsolutePath("data/dump/hpc/groth16_29_256.dump"), 1, 2000);	
		//collect_poly_data("groth16prove", 20, 30, 1,   2, 8, 1, Tools.getAbsolutePath("data/dump/hpc/groth16_full.dump"), 1, 2000);	
		//collect_poly_data("groth16prove", 20, 30, 1,   2, 8, 1, Tools.getAbsolutePath("data/dump/hpc/groth16_full_singlethread.dump"), 1, 2000);	
	}


	/** called by others */	
	public void collect_poly_data(String s_op, int log_min_size, int log_max_size, int log_step_wise, int log_min_node, int log_max_node, int log_node_step_wise, String dumpfile, int trials, int timeout_sec, boolean b_rayon_single_thread){
  try{
		long min_size = Tools.pow2(log_min_size);
		long max_size = Tools.pow2(log_max_size); 
		long size_step = Tools.pow2(log_step_wise);
		long min_node = Tools.pow2(log_min_node);
		long max_node = Tools.pow2(log_max_node);
		long node_step = Tools.pow2(log_node_step_wise);
		long estimated_timeout = 2* timeout_sec * ((log_max_size-log_min_size)/log_step_wise +1) * ((log_max_node-log_min_node)/log_node_step_wise + 1) * trials;
		System.out.println("===== DEBUG USE 888888: estimated_timeout: " + estimated_timeout + ", unit timeout: " + timeout_sec + " seconds");
		Tools.del_file(dumpfile);

		ArrayList<String> lines = new ArrayList<>();	
		for(long node = min_node; node<=max_node; node *= node_step){
				MPIConfig mcfg = new MPIConfig((int)node); 
				System.out.println("====== Cycle for Nodes: "+node+"=======");
				String [] args = mcfg.gen_mpirun_params("collect_poly_data "  + s_op + " " + log_min_size + " " + log_max_size + " " + log_step_wise +  " " + trials + " " + timeout_sec);
				Tools.run_worker3(args, (int) estimated_timeout,dumpfile,true, b_rayon_single_thread);
				try{
					Thread.sleep(1000*5);
				}catch(Exception exc) {}
		}
	  }catch(Exception exc){
		exc.printStackTrace();
		Tools.panic(exc.toString());
	  }
   		System.out.println("===================================");
        System.out.println("DATA COLLECTION COMPLETED!");
        System.out.println("===================================");

	} 

}


