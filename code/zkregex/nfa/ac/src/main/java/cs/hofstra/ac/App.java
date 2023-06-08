/**
	Aho-Corasick DFA and Virus Scanner
	Ref: Jack Vilo Text Algorithms
	https://courses.cs.ut.ee/2008/text/uploads/Main/TA%20Lecture%203_2%206up%20v2.pdf
	Author: Dr. CorrAuthor, Author2, Author1, Author3
	Created: 03/29/2022
	Revised: 08/04/2022 (Added variety of scan virus related functions).
	Revised: 08/06/2022 (Added depth info to states)
	Revised: 08/21/2022 (Added further analysis of depth info)
	Revised: 01/09/2023 (handle too-large file size scanning - chopped inot
pieces)
	Revised: 01/29/2023 (further improve padding)
*/
package cs.Employer.ac;
import java.nio.file.Files;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Random;
import java.lang.Integer;

/** Supports the following usages:
(1) java -cp target/..../.jar App build_dfa  src_dir dest_dir
	Note: expecting a file sigs.dat in src_dir
	Will output: DFA.dat into dest_dir
		assuming dest_dir already exists.
*/
public class App 
{
    public static void main( String[] args )
    {
		Tools.set_log_level(Tools.INFO2);
		if(args[0].equals("build_dfa")){
			String src_dir = args[1];
			String dst_dir = args[2];
			AC ac = AC.load_clamav_fixed(src_dir+ "/sigs.dat");
			ac.serialize_to(dst_dir+"/DFA.dat");
		}else if(args[0].equals("sample1")){
			sample_use1();
		}else if(args[0].equals("sample2")){
			sample_use2();
		}else if (args[0].equals("scan")){
			String src_dir = args[1];
			String dir = args[2];
			int file_size_limit = Integer.parseInt(args[3]);
			String list_file = args[4];
			int np = Integer.parseInt(args[5]);
			System.out.println("PARTITION_SIZE: " + file_size_limit);

			AC ac = AC.load_clamav_fixed(src_dir+ "/sigs.dat");
			Tools.log(Tools.INFO, "Step 1. start collecting freq word. All ELF list in " + list_file); 
			ArrayList<String> files = Tools.read_file_lines(list_file);
			int num_samples = files.size()/10;
			HashSet<Integer> freq_set = 
				new_collect_freq_word_set(ac,files,num_samples,2,10);
			Tools.log(Tools.INFO, "Step 2. Processing ... File Size > " + file_size_limit + " will be split.");
			ArrayList<BigInteger> ar_freq = new ArrayList<>();
			for(Integer i: freq_set){ 
				ar_freq.add(BigInteger.valueOf(i.intValue())); 
			}
			Tools.write_arr_to_file(ar_freq, "./freq_keywords.dat");
			Tools.log(Tools.INFO, "Step 3. Write freq_set:  " + ar_freq.size());
			new_listVirusWithDetails(ac, files, freq_set, file_size_limit, np);
		}else if(args[0].equals("listexec")){
			String [] files = Tools.getFiles("/", 10, 500000, 1024*1024*512);
			for(int i=0; i<files.length; i++){
				System.out.println("file " + i + ": " + files[i]);
			}
		}else{
			Tools.panic("ERROR: unknown argument: " + args[0]);
		}
    }

	/** sample use of an ASCII AC-DFA */
	public static void sample_use1(){
		AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "hers","she" }); 
		ac.dump();
	}

	public static void sample_use2(){
		AC ac = new AC(AC.CLAMAV_BIT_SIZE, new String [] {"\u0001\u0000", "\u0001\u0002\u0005"}); 
		ac.dump();
	}

	/** collect samples from src_dir with specified max_depth and
		max_num_files. Analyze all trace files and generate
		the frequently appeared words (their index), which appears
		at least min_times, and reaching depth greater than min_depth */
	public static HashSet<Integer>collect_freq_word_set(AC ac, String src_dir, int max_depth, int max_num_files, int min_times, int min_depth){
		HashSet<Integer> res = new HashSet<Integer>();
		HashMap<Integer, Integer> counters= new HashMap<>();

		//1. collect and process all files
		System.out.println("DEBUG USE 1001: collect files ...");
		String [] files = Tools.getFiles(src_dir, max_depth, max_num_files, 1024*1024*4); //collect 4MB files below, good enough
		System.out.println("DEBUG USE 1002: process files: " + files.length); 
		for (int i = 0; i < files.length; i++) {
			try {
				String cur_file = files[i];
				byte[] nibbles = Tools.read_nibbles_from(cur_file);
				String nibbles_str = new String(nibbles);
				ArrayList<AC.Transition> arr_trans = ac.run(nibbles_str);
				AC.Transition last_trans = arr_trans.get(arr_trans.size()-1);
				ArrayList<HashSet<Integer>> arr = ac.get_depth_stats(arr_trans);
				HashSet<Integer> set = new HashSet<>();
				for(int depth=min_depth; depth<arr.size(); depth++){
					set.addAll(arr.get(depth));	
				}
				for(Integer ele: set){
					if(counters.containsKey(ele)){
						counters.put(ele, counters.get(ele)+1);
					}else{
						counters.put(ele, 1);
					}
				}
			} catch(Exception e) {
				System.out.print(e);
			}
		}

		//2. construct res
		for(Map.Entry<Integer,Integer> e: counters.entrySet()){
			if(e.getValue()>min_times){
				res.add(e.getKey());
			}
		}
		return res;
	}

	public static void listVirusWithDetails(AC ac, String destName, int max_depth, int max_num_files, HashSet setExclude, long filesize_limit) {
		System.out.println("DEBUG USE 200: collect files ...");
		String [] files = Tools.getFiles(destName, max_depth, max_num_files, filesize_limit);
		System.out.println("DEBUG USE 201: startng scanning ... num_files: " + files.length);
		int count = 0;
		double totalFileSize = 0.0;
		double allTimeTotal = 0.0;
		//ac.serialize_to("/tmp/dfa.dat");
		//AC ac = AC.deserialize("/tmp/dfa.dat");
		int all_max_depth = 0;
		int [] counter_depth = new int [30];
		int [] counter_depth2 = new int [30];
		for (int i = 0; i < files.length; i++) {
			try {
				String cur_file = files[i];
				//System.out.println("DEBUG USE 301 processing file " 
				//	+ i + " of " + 
				//	files.length + ": " + cur_file);
				long start = System.currentTimeMillis();
				byte[] nibbles = Tools.read_nibbles_from(cur_file);
				String nibbles_str = new String(nibbles);
				//ArrayList<AC.Transition> arr_trans = ac.run(nibbles_str);
				//AC.Transition last_trans = arr_trans.get(arr_trans.size()-1);
				//boolean bAccepted = ac.isFinal(last_trans.dest);
				boolean bVirus= ac.isVirus(cur_file);
				if(bVirus){
					System.err.println("DUBUG USE 999: found virus: " + cur_file + "," + i + " of " + files.length );
				}
				int mdepth = ac.get_max_depth_by_run(nibbles_str, new HashSet<Integer>());
				int mdepth2 = ac.get_max_depth_by_run(nibbles_str, setExclude);
				String resultScan = bVirus? "VIRUS": "good";
				long end = System.currentTimeMillis();
				long timeTotal = end - start;
				long fileSize = Files.size(Paths.get(cur_file)) / 1024;
				//System.out.format("%s, Size: %d kb, Virus? (%s), Time: %d ms, MaxDepth: %d, NewMaxDepth: %d\n", cur_file, fileSize, resultScan, timeTotal, mdepth, mdepth2);
				all_max_depth = all_max_depth<mdepth? mdepth: all_max_depth;
				int cidx = mdepth/10>=29? 29: mdepth/10;
				counter_depth[cidx] += 1;
				int cidx2 = mdepth2/10>=29? 29: mdepth2/10;
				counter_depth2[cidx2] += 1;
				count++;
				totalFileSize += fileSize;
				allTimeTotal += timeTotal;
			} catch(Exception e) {
				System.out.print(e);
			}

		}
		System.out.println("...");
		ac.dump_summary();
		ac.dump_depth();
		System.out.println("Total: " + count + " files, " + totalFileSize + "kb, Time: " + allTimeTotal + " ms" + ", DEEPEST depth: " + all_max_depth);
		ac.dump_excludeset_stats(setExclude);
		System.out.println("=========== Depth Distribution 0 - " + counter_depth.length*10 + " ====");
		int total = 0;
		int total2 = 0;
		int num_files = files.length;
		for(int i=0; i<counter_depth.length; i++){
			total += counter_depth[i];
			total2 += counter_depth2[i];
			System.out.format("Depth <= %d: %2.2f: percent, Depth2: %2.2f percent\n", (i+1)*10,  total*100.0/num_files, total2*100.0/num_files);
		}
	}

	/** NEW VERSION: collect samples RANDOMLy
		with occuring least min_times, and 
		reaching depth greater than min_depth 
	*/
	public static HashSet<Integer>new_collect_freq_word_set(AC ac, ArrayList<String> all_files, int max_num_files, int min_times, int min_depth){
		HashSet<Integer> res = new HashSet<Integer>();
		HashMap<Integer, Integer> counters= new HashMap<>();

		//1. collect and process all files
		ArrayList<String> files = new ArrayList<String>();
		long seed = 123123791;
		Random rand = new Random(seed);
		while(files.size()<max_num_files){
			int idx = rand.nextInt();
			idx = idx<0? -idx: idx;
			idx = idx % all_files.size();	
			String file = all_files.get(idx);
			if(!files.contains(file)){
				files.add(file);
			}
		}
		Tools.log(Tools.INFO, "Collected files: " + files.size());

		for (int i = 0; i < files.size(); i++) {
			try {
				String cur_file = files.get(i);
				byte[] nibbles = Tools.read_nibbles_from(cur_file);
				String nibbles_str = new String(nibbles);
				ArrayList<AC.Transition> arr_trans = ac.run(nibbles_str);
				ArrayList<HashSet<Integer>> arr = ac.get_depth_stats(arr_trans);
				HashSet<Integer> set = new HashSet<>();
				for(int depth=min_depth; depth<arr.size(); depth++){
					set.addAll(arr.get(depth));	
				}
				for(Integer ele: set){
					if(counters.containsKey(ele)){
						counters.put(ele, counters.get(ele)+1);
					}else{
						counters.put(ele, 1);
					}
				}
			} catch(Exception e) {
				System.out.print(e);
			}
		}

		//2. construct res
		for(Map.Entry<Integer,Integer> e: counters.entrySet()){
			if(e.getValue()>=min_times){
				res.add(e.getKey());
			}
		}
		Tools.log(Tools.INFO, "Freq-set Size: " + res.size());
		StringBuilder sb = new StringBuilder();
		for(Integer i: res){
			sb.append(i + " ");
		}
		Tools.log(Tools.INFO2, "Freq-Set: " + sb.toString());
		return res;
	}
	/** Get the max depth of the input string by run it. exclude the
	setExclude. Take the given input state as the initial state (the
	reason: sometimes we have to handle file fragements
		return [max_depth, final_state, default_max_depth if setExclude 0]
	*/
	public static int [] get_max_depth_by_run(AC ac, String inputstr, int num_chunks, HashSet<Integer> setExclude, int init_state){
		//1. run by chunks
		ArrayList<AC.Transition> arrTrans = new ArrayList<>();
		int [] res = ac.adv_run_by_chunks(inputstr, init_state, num_chunks, arrTrans, false);
		if(res!=null) {throw new RuntimeException("adv_run_by_chunks failed! Pad the str first!");}
		
		//2. analyze the transitions
		int max_depth = 0;
		int max_depth_default = 0;
		for(int i=0; i<arrTrans.size(); i++){
			int curr_state = arrTrans.get(i).src;
			int depth = ac.tbl_depth.get(curr_state);
			int word_idx = ac.tbl_src_keyword_idx.get(curr_state);
			if(!setExclude.contains(word_idx)){
				max_depth = max_depth<depth? depth : max_depth;
			}
			max_depth_default = max_depth_default<depth? 
				depth : max_depth_default;
		}
		AC.Transition last_trans = arrTrans.get(arrTrans.size()-1);
		return new int [] {max_depth, last_trans.dest, max_depth_default};
	}


	/* return the number of chunks, chunk_size is in nibbles */
	protected static int get_num_parts(byte [] nibbles, int chunk_size){
		int total_len = nibbles.length;
		int chunks = total_len/chunk_size;
		chunks = total_len/chunk_size;
		chunks = total_len%chunk_size==0? chunks: chunks+1;
		return chunks;
	}
	/** return the i'th chunk */
	protected static byte [] get_part(byte [] nibbles, int chunk_size, int i){
		int chunks = get_num_parts(nibbles, chunk_size);
		if(i<0 || i>=chunks) throw new RuntimeException("chunk id not right");
		int begin_idx = i*chunk_size;
		int end_idx = (i+1) * chunk_size; //not included
		end_idx = end_idx>nibbles.length? nibbles.length: end_idx; 
		byte [] res = new byte [end_idx-begin_idx];
		for(int j=0; j<res.length; j++){
			res[j] = nibbles[j + begin_idx];
		}
		return res;
	}


	/** use AC to scan each of the file, setExclude is the freq_set 
		when tabulating the subset_id.
		For file has size greater than file_size_limit, split them
	into partitions by file_size_limit, and the PRINTED RECORD
	contains the (subset_id, last state)  
	for each parition (as additional string
	in the same line)
		file_size_limit in bytes.
	*/
	public static void new_listVirusWithDetails(AC ac, ArrayList<String> files, HashSet setExclude, int file_size_limit, int np ) {
		file_size_limit = file_size_limit * 2; //now in nibbles
		int count = 0;
		double totalFileSize = 0.0;
		double allTimeTotal = 0.0;
		//ac.serialize_to("/tmp/dfa.dat");
		//AC ac = AC.deserialize("/tmp/dfa.dat");
		int all_max_depth = 0;
		int [] counter_depth = new int [30];
		int [] counter_depth2 = new int [30];
		int mdepth = -1;
		int mdepth2 = -1;
		int all_last_state = -1;
		int all_group_id = -1;
		double compression_rate = -1.0;
		for (int i = 0; i < files.size(); i++) {
			try {
				String cur_file = files.get(i);
				long start = System.currentTimeMillis();
				byte[] nibbles = Tools.read_nibbles_from(cur_file);
				StringBuilder sb = new StringBuilder();
				sb.append(", partitions_info: ");
				String part_info = "";
				if(nibbles.length<=file_size_limit){
					all_group_id=get_group_id_in_nibbles(nibbles.length, 
						np);
					int all_group_size=get_group_size_in_nibbles(all_group_id, 
						np);
					String nibbles_str=padd_nibbles(ac, nibbles, 
						all_group_size, 0, np, cur_file);
					//try 3 times
					for(int j=0; j<3 && nibbles_str==null; j++){
						System.out.println("WARNING 504: bump group ID up for file: " + cur_file + " to all_group_id: " + (all_group_id +1));
						all_group_id += 1;
						all_group_size = get_group_size_in_nibbles(all_group_id, np);
						nibbles_str = padd_nibbles(ac, nibbles, all_group_size, 0, np, cur_file);

					}
					if(nibbles_str==null){
						Tools.panic("padding failed for: " + cur_file);
					}
					compression_rate = ac.get_compression_rate(nibbles_str);
					int [] res = get_max_depth_by_run(ac, nibbles_str, np, setExclude, 0);
					mdepth = res[2];
					mdepth2 = res[0];
					all_last_state = res[1];
				}else{
					int parts = get_num_parts(nibbles, file_size_limit);
					int last_state = 0;
					for(int j=0; j<parts; j++){
						byte [] part = get_part(nibbles, file_size_limit, j);
						int group_id = get_group_id_in_nibbles(part.length, np);
						int group_size = get_group_size_in_nibbles(group_id, np);
						String part_str = padd_nibbles(ac, part, group_size, last_state, np, cur_file);
						for(int u=0; u<3 && part_str==null; u++){
							System.out.println("WARNING 504.1: bump group ID up for file: " + cur_file + " PARTITION: " + j + "  to group_id: " + (group_id +1));
							group_id += 1;
							group_size = get_group_size_in_nibbles(group_id, np);
							part_str = padd_nibbles(ac, part, group_size, 0, np, cur_file);

						}
						double rate = ac.get_compression_rate(part_str);
						compression_rate = compression_rate>rate? compression_rate: rate;
						all_group_id = all_group_id>group_id? all_group_id:
							group_id;
						if(part_str==null){
							Tools.panic("padding failed for: " + cur_file + "PART " + j);
						}
						int [] maxres = get_max_depth_by_run(ac, part_str,np, setExclude, last_state);
						int my_last_state = maxres[1];
						int max_depth = maxres[0];
						mdepth = mdepth>maxres[2]? mdepth: maxres[2];
						mdepth2 = mdepth>maxres[0]? mdepth2: maxres[0];
						//dump the depth, init_state, last_state, group_id
						sb.append(max_depth + " " + last_state + " " + my_last_state + " " + group_id + " ");
						last_state = my_last_state;
						all_last_state = last_state;
					}	
					part_info = sb.toString();
				}
				boolean bVirus = !ac.isFinal(all_last_state);
				if(bVirus){
					System.err.println("DUBUG USE 999: found virus: " + cur_file + "," + i + " of " + files.size());
				}
				String resultScan = bVirus? "VIRUS": "good";
				long end = System.currentTimeMillis();
				long timeTotal = end - start;
				long fileSize = Files.size(Paths.get(cur_file));
				System.out.format("FILEDUMP: %s, Size: %d, Group: %d, Virus: (%s), Time: %d ms, MaxDepth: %d, NewMaxDepth: %d, Compression: %2.2f perc, init_state: %d, last_state: %d" + part_info + "\n", cur_file, fileSize, all_group_id, resultScan, timeTotal, mdepth, mdepth2, compression_rate*100, 0, all_last_state);


				all_max_depth = all_max_depth<mdepth? mdepth: all_max_depth;
				int cidx = mdepth/10>=29? 29: mdepth/10;
				counter_depth[cidx] += 1;
				int cidx2 = mdepth2/10>=29? 29: mdepth2/10;
				counter_depth2[cidx2] += 1;
				count++;
				totalFileSize += fileSize;
				allTimeTotal += timeTotal;

			} catch(Exception e) {
				e.printStackTrace();
				System.out.print(e);
				System.exit(1);
			}

		}
		System.out.println("...");
		ac.dump_summary();
		ac_dump_depth_new(ac, setExclude);
		System.out.println("Total: " + count + " files, " + totalFileSize + "kb, Time: " + allTimeTotal + " ms" + ", DEEPEST depth: " + all_max_depth);
		ac.dump_excludeset_stats(setExclude);
		System.out.println("=========== Depth Distribution 0 - " + counter_depth.length*10 + " ====");
		int total = 0;
		int total2 = 0;
		int num_files = files.size();
		for(int i=0; i<counter_depth.length; i++){
			total += counter_depth[i];
			total2 += counter_depth2[i];
			System.out.format("Depth <= %d: %2.2f: percent, Depth2: %2.2f percent\n", (i+1)*10,  total*100.0/num_files, total2*100.0/num_files);
		}
	}
	/** dump the depth information, but counting the setExclude */
	public static void ac_dump_depth_new(AC ac, HashSet<Integer> freq_set){
		//1. get the max depth and total counts
		int max_depth = 0;
		for(int i=0; i<ac.tbl_depth.size(); i++){
			int depth = ac.tbl_depth.get(i);
			max_depth = depth>max_depth? depth: max_depth;
		}
		System.out.println("MAX_DEPTH: " + max_depth);
		//2. collect the counters
		int max_collect = 300;
		Integer [] counters = new Integer [max_depth+1];
		//accumulated: counters_acc[i] includes all depth <= i
		//AND also the setExclude (freq_set)
		Integer [] counters_acc= new Integer [max_depth+1]; 
		for(int i=0; i<counters.length; i++){
			 counters[i] = 0;	
			 counters_acc[i] = 0;
		}
		//process each state i
		for(int i=0; i<ac.tbl_depth.size(); i++){
			int depth = ac.tbl_depth.get(i);
			counters[depth] = counters[depth]+1;

			Integer word_idx = ac.tbl_src_keyword_idx.get(i);
			if(freq_set.contains(word_idx)){
				for(int j=0; j<=max_depth && j<=max_collect; j++){//coz it will be included in each depth set
					counters_acc[j] = counters_acc[j]+1;
				}
			}else{
				for(int j=depth; j<=max_depth && j<=max_collect; j++){
					counters_acc[j] = counters_acc[j]+1;
				}
			}
		}
		//3. print out the stats
		int total_states = ac.tbl_depth.size();
		int sum = 0;
		int sum2 = 0;
		for(int i=0; i<counters.length && i<max_collect; i++){
			sum += counters[i];
			sum2 = counters_acc[i]; //as it's accumulated
			double val = sum*100.0/total_states;
			double val2 = sum2*100.0/total_states;
			String str = String.format("%2.2f  freq_set counted: %2.2f, states: " + counters[i]+ " " + counters_acc[i], val, val2);
			System.out.println("Depth " + i + ": " + str);
		}
	}

	/** default padding approach, at the end */
	protected static String pad_nibbles_1(byte [] nibbles, int target_size, byte ch){
		if(nibbles.length>target_size){Tools.panic("nibble.len>target");}
		byte [] new_arr = new byte [target_size];
		for(int i=0; i<target_size; i++){
			new_arr[i] = i<nibbles.length? nibbles[i]: ch;
		}
		String res = new String(new_arr);
		return res;
	}

	/** 2nd preferred padding approach, at the beginngin*/
	protected static String pad_nibbles_2(byte [] nibbles, int target_size, byte ch){
		if(nibbles.length>target_size){Tools.panic("nibble.len>target");}
		byte [] new_arr = new byte [target_size];
		int diff = target_size - nibbles.length;
		for(int i=0; i<target_size; i++){
			new_arr[i] = i<diff? ch: nibbles[i-diff];
		}
		String res = new String(new_arr);
		return res;
	}


	/**  Fill the transitions into the input transitions. It will be clear
	at the beginning. If ERROR. return an int [] which
		contains information of:
	[idx_of_chunk_with_err, the_last_value_of_num_remain, OFFSET of the max backdepth INSIDE the chunk]
	return NULL if ok
	*/
	public static int [] adv2_run_by_chunks(AC ac, String inputstr, int init_state, int num_chunks){
		//1. input sanity check
		int total_len = inputstr.length();
		int chunk_size = total_len/num_chunks; 

		//2. build up the transitions
		int curr_state = init_state;
		int next_state = 0;
		int trans_size = 0;
		int max_back_start = 0;
		for(int j = 0; j < num_chunks; j++) {
			int cur_size = trans_size;
			int my_size = j<num_chunks-1? chunk_size: total_len%num_chunks + chunk_size;
			int max_back_depth = 0;
			for(int i=0; i<my_size; i++){
				char c = inputstr.charAt(i+j*chunk_size);
				//special handling for TERM_CHAR (as padding chars)
				if(c==ac.TERM_CHAR){
					trans_size++;
					continue;
				}

				// handle fail edges:
				int cur_back_depth = 0;
				while((ac.next_state(curr_state, c) == -1) 
					&& (ac.tbl_fail.get(curr_state) != curr_state)) {	
					int curr_state2 = ac.tbl_fail.get(curr_state);
					trans_size++;
					curr_state = curr_state2;
					cur_back_depth ++;
				}
				if(cur_back_depth>max_back_depth) {
					max_back_depth=cur_back_depth;
					max_back_start = i;
				}
				next_state = ac.next_state(curr_state, c);
				trans_size++;
				curr_state = next_state;
			}
			int added = trans_size-cur_size;
			int num_remain = 2*my_size - added;
			if(num_remain<0){//ERROR!
				return new int [] {j, num_remain, max_back_depth, max_back_start};
			}
			for(int i=0; i<num_remain; i++){
				//NOTE: if there are SPECIFICALLY padded TERM_CHAR by
				//read_and_pad iteration  in RustProver, they ARE
				//regarded as valid paraters (non-fail edges!)
				trans_size++;
			}
		}
		if(trans_size!=2*total_len){
			Tools.panic("generated transition length: " + trans_size
				+ "!= 2*total_len: " + 2*total_len);
		}

		return null;
	}

	//for debugging purpose
	protected static byte [] filter_padding(byte [] nibbles, byte ch){
		int n = 0;
		for(int i=0; i<nibbles.length; i++){
			if (nibbles[i]!=ch) n++;
		}
		byte [] res = new byte [n];
		int idx = 0;
		for(int i=0; i<nibbles.length; i++){
			if (nibbles[i]!=ch){
				res[idx] = nibbles[i];
				idx++;
			} 
		}
		return res;
	}
	/** insert num of padding char at the position, interleaved, returning a larger array */
	protected static byte [] insert_padding(byte [] nibbles, int position, int num, byte ch){
		byte [] res = new byte [nibbles.length+num];
		boolean b_debug = false;

		int total_len = res.length;
		for(int i=0; i<total_len; i++){
			if(i<position){
				res[i] = nibbles[i];
			}else if(i<position+num){	
				res[i] = ch;
			}else{
				res[i] = nibbles[i-num];
			}
		}

		if(b_debug){
			byte [] new_inp = filter_padding(res, ch);
			byte [] res2= filter_padding(nibbles, ch); //why? coz nibbles
			//can contain padded chars too!
			if(new_inp.length!=res2.length){
				throw new RuntimeException("ERROR! padding does not insert right! new_inp.length" + new_inp.length + " !=nibbles.length: " + nibbles.length);
			}
			boolean b_ok = true;
			for(int i=0; i<new_inp.length; i++){
				if(new_inp[i]!=res2[i]){
					System.out.println("PADDING failed at: " + i + ", new_inp[i]: " + new_inp[i] + ", nibbles[i]: " + res2[i]);
					b_ok = false;
				}
			}
			if(!b_ok){
				throw new RuntimeException("ERROR! padding incorrect");
			}
			System.out.println("DEBUG USE 100: padding ok");
		}
		return res;
	}
	
	/** Try to run default padd1, and padd2 (at end or beginning) .
		Under very rare cases where the accept run greater 2 * input length
		(this only happens for very small input size and very
			small ACDFA),
		find the error chunk and insert some padding chars.
		Most likely just need nibbles, target_size to work.
		the others params are for special case and log info.

		If successful return the padded string, OTHERWISE return null (because the target_size too small)
	*/
	public static String padd_nibbles(AC ac, byte [] nibbles, int target_size, int start_state, int np, String fpath){
		boolean b_failed = true;
		byte ch = (byte) ac.TERM_CHAR;
		//ArrayList<AC.Transition> arrTrans= new ArrayList<AC.Transition>();
		int iteration = 0;
		int file_size = target_size;
		String nibblesStr = null;
		while(true){
			boolean b_debug = false;
			//attempt 1
			nibblesStr= pad_nibbles_1(nibbles, target_size, ch);
			int [] res = adv2_run_by_chunks(ac, nibblesStr, start_state, np);
			if(res==null) break; //found it
			//attempt 2
			nibblesStr= pad_nibbles_2(nibbles, target_size, ch);
			int [] res2 = adv2_run_by_chunks(ac, nibblesStr, start_state, np);
			if(res==null) break; //found it
	
			//attempt 3 had to patch nibbles	(heurstics)			
			//THIS SECTION SHOULD BE VERY RARELLY CALLED AS IT DEPENDS
			//ON THE RUNNING ACCEPTANCE PATH
			int failed_chunk_id = res[0];
			int num_remain = res[1]; //negative
			int max_back_depth = res[2];
			int max_back_start= res[3];
			int space_left = target_size - nibbles.length;
			int position = target_size/np * failed_chunk_id + max_back_start;
			int chunk_size = target_size/np;
			if(chunk_size<max_back_depth){
				System.out.println("WARNING 503.1: chunk_size too small. chunk_size: " + chunk_size + ", max_back_depth: " + max_back_depth);
				return null;
			}


			//heuristics: to estimate a good padding strategy
			int num = -1;
			if(max_back_depth<chunk_size/8){//small to handle
				num = -num_remain*4 + 2;
				position = target_size/np * failed_chunk_id;
			}else{
				int chunk_left = chunk_size - max_back_start - 2;
				if(max_back_depth<chunk_left){//just push forward in same chunk
					num = max_back_depth;
				}else{
					num = chunk_left+2; //push to next chunk
				}
				position = target_size/np * failed_chunk_id + max_back_start;
			}
			if(num>=space_left){
				System.out.println("WARNING 503.2. Failed Heurstics. Details: failed_chunk_id: " + failed_chunk_id + ", num_remain: " + num_remain + ", max_back_depth: " + max_back_depth + ", space_left: " + space_left + ", position: " + position + ", num: " + num);
				return null;
			}
			// there is a signature with 48 1's + some magic string.
			// 1 is likely to produce less backedges
			nibbles = insert_padding(nibbles, position, num, ch);
			System.out.println("WARNING 502 Details: failed_chunk_id: " + failed_chunk_id + ", num_remain: " + num_remain + ", max_back_depth: " + max_back_depth + ", space_left: " + space_left + ", position: " + position + ", num: " + num);
			iteration++;

			if(iteration>np+1){
				System.out.println("ERROR 503.3: padding failed after iteration: np");
				return null;
			}
		}
		return nibblesStr;
	}

	/** get the size limit of group_id in nibbles*/
	public static int get_group_size_in_nibbles(int group_id, int np){
		//int cur_len = (1<<group_id) * 2; //in nibbles
		int unit = 126;
		int cur_len = (1<<group_id) *2  - np * unit; //in nibbles
		int cur_len_per_node = cur_len/np;
		int target_len_per_node = cur_len_per_node%unit==0?
			cur_len_per_node: (cur_len_per_node/unit+1) * unit;
		int target_len = target_len_per_node*np;
		int min_len = unit * np;
		target_len = target_len<min_len? min_len: target_len;
		return target_len;
	}

	/** given the size in nibbles get the subgroup ID 
		group id actually corresponds to log2(size_in_bytes)
		e.g., group id 10 cooresponds to roughly 1024 bytes or 2048 nibbles,
		numbers may vary depending on the np nodes.
	*/ 
	public static int get_group_id_in_nibbles(int size, int np){
 		int unit = 126;
		int min_len = unit * np;
		if(size<min_len){
			//make it slightly larger to avoid frequent failing padding
			return Tools.ceil_log2(min_len); 
		}

		int x = 1;
		while(true){
			if(get_group_size_in_nibbles(x, np)>size){
				return x;
			}
			x += 1;
		}
	}
}
