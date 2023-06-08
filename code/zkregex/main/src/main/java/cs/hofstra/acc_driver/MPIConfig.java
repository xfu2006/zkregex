/** Efficient Zero Knowledge Project
	Configuration for running MPI (acc in Rust)
	Author: Dr. CorrAuthor
	Created: 06/27/2022
*/ 

package cs.Employer.acc_driver;
import cs.Employer.zkregex.Tools;
import java.util.HashMap;
import java.io.File;

/**
	MPIConfig is read from proj_root/config/CONFIG.txt
*/
public class MPIConfig{
	/** mode */
	public boolean bLocal;
	/** number of nodes, to be passed as mpi -nXXX*/
	public int numNodes;
	/** host list file. This is the TOTAL LIST file.
	based on the numExecutors we'll generate a temporary 
	node list taking numServers of nodes from the list */
	public String all_nodes_file;
	/**  number of phisical servers*/
	public int numServers;
	/** soft upper capacity of each node but can be exceeded,	
		used to determine ratio
	*/
	public int [] node_capacity;
	/** total capacity of all nodes (soft) */
	public int total_capacity;
	/** the extra parameters, e.g., disabling certain network adaptors */
	public String extra_params;
	public static String NODELIST = "/tmp/tmp_nodelist.txt";

	/** when allocating nodes, allocate among all existing servers */
	public static int AVERAGE_MODE = 1;
	/** when allocating nodes, saturate the servers first */
	public static int GREEDY_MODE = 2;

	// ------------------ PUBLIC OPERATIONS ----------------------
	/** It reads from the config file in proj_root/config/MPI_CONFIG.txt 
		if num_nodes<0, read from the spec file
	*/
	public MPIConfig(int num_nodes){
		HashMap<String,String> map = Tools.readConfigFile("config/MPI_CONFIG.txt");
		this.bLocal = map.get("mode").equals("local");	
		this.numNodes = num_nodes<0? Tools.str2i(map.get("nodes")): num_nodes;
		this.numServers = Tools.str2i(map.get("servers"));
		this.all_nodes_file= "config/" + map.get("cluster");
		this.extra_params = read_extra_params();
		this.set_nodes_capacity();
		build_tmp_nodelist();
	}

	public MPIConfig(){
		this(-1); //read the numbers from spec
	}

	/** assuming only one effective line in config/mpi_params.txt */
	protected String read_extra_params(){
		String [] arr = Tools.readLines("config/mpi_params.txt");
		for(int i=0; i<arr.length; i++){
			if(arr[i].indexOf("#")==-1){
				return arr[i];
			}
		} 
		return null; //error
	}

	/** by default greedy */
	protected void build_tmp_nodelist(){
		build_tmp_nodelist(AVERAGE_MODE);
	}

	protected void build_tmp_nodelist(int mode){
		if(mode==GREEDY_MODE){
			build_tmp_nodelist_greedy();
		}else if(mode==AVERAGE_MODE){
			build_tmp_nodelist_average();
		}else{
			throw new RuntimeException("mode: " + mode + " not defined yet");
		}
	}

	//processing each line
	protected void set_nodes_capacity(){
		String [] nodes_line = Tools.readLines(all_nodes_file);
		int idx = 0;
		int [] capacity = new int [numServers];
		for(int i=0; i<nodes_line.length; i++){
			String line = nodes_line[i];
			if(line.indexOf("#")==-1){
				int loc = line.indexOf("slots=");
				String rest = line.substring(loc+6);
				capacity[idx] = Integer.parseInt(rest);
				idx++;
			}
		}
		if (idx<numServers) throw new RuntimeException("found less than numServers! Details: " + nodes_line);
		this.node_capacity = capacity;
		this.total_capacity = getSum(capacity);
		for(int i=0; i<numServers; i++){
			System.out.println("DEBUG USE 101: node: " + i + " capacity: " + node_capacity[i]);
		}
		System.out.println("DEBUG USE 102: total capacity: " + total_capacity);
	}

	protected int getSum(int [] arr){
		int sum = 0;
		for(int i=0; i<arr.length; i++) sum+= arr[i];
		return sum;
	}
	/** write to "/tmp/tmp_nodelist.txt. DEPRECATED */ 
	protected void build_tmp_nodelist_greedy(){
		String [] nodes = Tools.readLines(all_nodes_file);
		if(nodes.length<this.numServers){
			Tools.panic("There are no " + numServers + " servers in " + all_nodes_file);
		}
		String [] nodes_in_use = new String [numServers];
		int idx = 0;
		for(int i=0; idx<numServers && i<nodes.length; i++){
			if(nodes[i].indexOf("#")==-1){
				nodes_in_use[idx++] = nodes[i];
			}
		}
		Tools.write_lines_to_file(nodes_in_use, NODELIST);
	}

	private String update_capacity(String line, int capacity){
		int idx = line.indexOf("=");
		//System.out.println("DEBUG USE 300: idx: " + idx);
		String newline = line.substring(0,idx+1) + String.valueOf(capacity);
		//System.out.println("DEBUG USE 301: " + newline);
		return newline;
	}

	/** write to "/tmp/tmp_nodelist.txt.  SPLIT the total
	nodes among servers, take the info of the server
	by reading the input file
	*/
	protected void build_tmp_nodelist_average(){
		System.out.println("Generating server list using AVG/RATIO mode");
		String [] nodes = Tools.readLines(all_nodes_file);
		if(nodes.length<this.numServers){
			Tools.panic("There are no " + numServers + " servers in " + all_nodes_file);
		}
		String [] nodes_in_use = new String [numServers];
		
		int [] joblist = new int [numServers];
		int idx = 0;
		int total_allocated = 0;
		int jobs = this.numNodes;
		for(int i=0; idx<numServers; i++){
			if(nodes[i].indexOf("#")==-1){
				int share = node_capacity[idx] * jobs/total_capacity; 
				if(share==0 && total_allocated<jobs){
					share = 1;
				}
				joblist[idx]= share;
				total_allocated += share;
				idx++;
			}
		}
		if(total_allocated>jobs){
			throw new RuntimeException("WRONG: total_allocated: " + total_allocated + "> jobs: " + jobs);
		}
		if(total_allocated<jobs){
			int diff = jobs-total_allocated;
			for(int i=0; i<numServers-1 && diff>0; i++){
				int extra = diff/(numServers-1);
				extra = extra<1? 1: extra;
				joblist[i] += extra;	 
				diff -= extra;
				System.out.println("DEBUG USE 105: node " + i + " got extra jobs: " + extra);
			}
		}
		
		idx = 0;
		for(int i=0; idx<numServers; i++){
			if(nodes[i].indexOf("#")==-1){
				String newline = update_capacity(nodes[i], joblist[idx]);
				System.out.println("DEBUG USE 106: server" + idx + "'s nodes: " + joblist[idx]); 
				nodes_in_use[idx++] = newline;
			}
		}
		Tools.write_lines_to_file(nodes_in_use, NODELIST);
	}

	/** filter out the empty string */
	private String [] filter_emptyStr(String [] arr){
		int count = 0;
		for(int i=0; i<arr.length; i++){
			if(arr[i].trim().length()>0){
				count++;
			}
		}	
		String [] res = new String [count];
		int idx = 0;
		for(int i=0; i<arr.length; i++){
			if(arr[i].trim().length()>0){
				res[idx++] = arr[i];
			}
		}	
		return res;
	}

	/** sometimes it is called in jsnark, and needs one more level
		of .. */
	private String get_acc_path(){
		String rel_path = "../acc/target/release/acc";
		File f1 = new File(rel_path);
		if(!f1.exists()){
			rel_path = "../../acc/target/release/acc";
		}
		f1 = new File(rel_path);
		if(!f1.exists()){
			Tools.panic("Can't locate release/acc!");
		}
		return rel_path;
	}	
	/** generate the runner strings, arg is the arguments for the
	command */
	public String [] gen_mpirun_params(String arg){
		String rel_path = get_acc_path();
		String acc_path = Tools.getAbsolutePath(rel_path);
		String params = "mpirun " + this.extra_params 
			+ "  --hostfile " + this.NODELIST+ " -np " + this.numNodes
			+ " " + acc_path + " " + arg;
		String [] arr = params.split(" ");
		arr = filter_emptyStr(arr);
		return arr;
	}	
}

