/**
	Aho-Corasick DFA
	Ref: Jack Vilo Text Algorithms
	https://courses.cs.ut.ee/2008/text/uploads/Main/TA%20Lecture%203_2%206up%20v2.pdf
	Author: Dr. CorrAuthor, Author2, Author1, Author3
	Created: 03/29/2022
	Revised: 08/04/2022 (Added variety of scan virus related functions).
	Revised: 08/06/2022 (Added depth info to states)
	Revised: 08/21/2022 (Added further analysis of depth info)
	Revised: 12/25/2022 (to avoid future changes on the class, make
		all attributes public - to avoid seirlaization issue in the future
	--FINALIZED).
	Revised: 01/09/2023 (fixed a bug in write_trans_as_num)
	Revised: 01/10/2023 (modify adv_run_by_chunks to allow changing init state)
	Revised: 01/11/2023 (moved padding function here)
	Revised: 01/12/2023 (moved back to TERM_CHAR for padding)
	Revised: 01/13/2023 (move padding function to App)
*/
package cs.Employer.ac;
import java.util.Random;
import java.util.Collections;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
import java.util.HashSet;
import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.io.InputStream;
import java.math.BigInteger;
import static java.lang.Math.ceil;
import static java.lang.Math.pow;
import static java.lang.Math.log10;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.nio.file.*;

/** Aho-Corasic Automata */
public class AC implements Serializable,Cloneable{
	public Object clone() throws CloneNotSupportedException {
    	 AC obj = (AC)super.clone();
		 return obj;
	}

	public class Transition{
		/** source state */
		public int src;
		/** the char on the transition */
		public char c;
		/** destination state */
		public int dest;
		/** whether this is fail edge */
		public boolean bFail;
		/** constructor */
		public Transition(int src, char c, int dest, boolean bFail){
			this.set(src, c, dest, bFail);
		}
		public boolean equals(Object obj){
			Transition other = (Transition) obj;
			return src==other.src && dest==other.dest && c==other.c && 
				bFail==other.bFail;
		}
		public void set(int src, char c, int dest, boolean bFail){
			this.src = src;
			this.c = c;
			this.dest = dest;
			this.bFail = bFail;
		}
		public String toString(){
			int ichar = (int) this.c;
			String sc = String.valueOf(ichar);
			return " " + src + "--> " + dest + ", char: " + sc + ", bFail: " + bFail;
		}
		
	}
	// ------------ Public Data Members ---------------------
	/** the bit-size of ASCII alphabet, i.e., 8 */
	public static final int ASCII_BIT_SIZE = 8;
	/** the bit-size of clamav alphabet, i.e., 4 */
	public static final int CLAMAV_BIT_SIZE= 4;


	// ------------ Protected Data Members -------------------
	/** alphabet_size: in bits. 
	  *We currently support two types: 4 and 8.
	  *	4 is for clamav and 8 is for ASCII char set
	*/
	public int alphabet_bit_size; 
	/** value is 2^alphabet_bit_size */
	public int alphabet_size; 
	/** number of final states, will be ste in normalize_final_states */
	public int num_final_states;
	/** terminating symbol. It's 16 when CLAM_AV mode, and it's 2^8 for
		ASCII_mode (alphabet_size) */
	public char TERM_CHAR;   //in fact any 5-bit input will be treated as TERM_CHAR
	/** the input set of keywords, where the DFA is built from */
	public String [] arrKeywords;
	/** goto table.
	  * tbl_goto[i][c] maps to the next state for state i given input char c. 
	  * If there is no next state,
	  * it has no such entry
	*/
	public ArrayList<HashMap<Character,Integer>> tbl_goto = new ArrayList();
	/** output table. tbl_out[i] is the list of output "matching" words at
		state i
	*/
	public ArrayList<ArrayList<String>> tbl_output = new ArrayList();

	/** maps each state to its fail state (one and only one), that is
		the next state of its fail edge */
	public ArrayList<Integer> tbl_fail = new ArrayList<Integer>();

	/** maps each state to its depth, i.e., the min-distance from the init
	state */
	public ArrayList<Integer> tbl_depth = new ArrayList<Integer>();
	/** maps each state to its source keyword that generates it in buildTrie
	state 0 will have -1, but the others will have valid idx */
	public ArrayList<Integer> tbl_src_keyword_idx= new ArrayList<Integer>();
	


	// For deserialize()
	/** List of State IDs */
	public ArrayList<Integer>states_des;

	/** List of Transition IDs */
	public ArrayList<Integer>trans_des;

	/** List of State IDs with Final States */
	public ArrayList<Integer>finals_des;

	// ------------ Private Data Members -------------------
	// Variables for optimization of digitizeTransition()

	/** Number of bits needed to encode states */
	private int k;

	/** 2^k */
	private int pow2k;

	/** 2^(2k) */
	private int pow2k2;

	// ------------ Methods ---------------------
	/** constructor of Aho-Corasick DFA. Feed the alphabet_size and keywords.
	* It then starts the build().
	*	@param	alphabet_bit_size: in bits. 
	*/
	public AC(int alphabet_bit_size, String [] keywords){
		this.alphabet_bit_size = alphabet_bit_size;
		this.alphabet_size = 1;
		for(int i=0; i<this.alphabet_bit_size; i++){
			this.alphabet_size = this.alphabet_size * 2;
		}
		this.TERM_CHAR = (char )this.alphabet_size;
		this.arrKeywords = keywords;
		this.build();
	}

	/** deserialized constructor of Aho-Corasick DFA. Feed deserialized lists to rebuild automaton
	* Some data is not recoverable
	*/
	public AC(int alphabet_bit_size, ArrayList<Integer> states, ArrayList<Integer> trans, ArrayList<Integer> fails, ArrayList<Integer> finals){

		this.alphabet_bit_size = alphabet_bit_size;
		this.states_des = states;
		this.trans_des = trans;
		this.finals_des = finals;
		this.tbl_fail = fails;
	}

	/** build hex4 AC-DFA. Note: the keywords are in the nice form
		hex strings such as "01abcd". They are passed into the real strings
	*/
	public static AC build_clamav_ac(String [] keywords){
		String [] real_arr = new String [keywords.length];
		for(int i=0; i<keywords.length; i++){
			real_arr[i] = Tools.parse_hex4(keywords[i]);
		}
		AC ac = new AC(4, real_arr);
		return ac;
	}

	/** load the clam av from pattern file */
	public static AC load_clamav_fixed(String filename){
		String all = Tools.read_file(filename);
		String [] arrs = all.split("\n");	
		AC ac = AC.build_clamav_ac(arrs);
		return ac;
	}

	/** genrerate a random clamav AC using the given seed.
	inputsize is the TOTAL length of input strings.
	the automata size is almost the same (slightly slower) than
	input size. Same seed always leads to SAME automata generated.
	 */
	public static AC rand_clamav_ac(long seed, int inputsize){
		Random rand = new Random(seed);
		int nStr = rand.nextInt(inputsize/10+1)+1;
		int avglen = inputsize/nStr + 1;
		String alphabet = "0123456789abcdef";
		ArrayList<String> al = new ArrayList<>();
		for(int i=0; i<nStr && inputsize>0; i++){
			int len = rand.nextInt(avglen+1)+1;
			if(i==nStr-1){
				len = inputsize;
			}
			StringBuilder sb = new StringBuilder();
			for(int j=0; j<len && j<inputsize; j++){
				int rdx = rand.nextInt(16);
				char c = alphabet.charAt(rdx);
				sb.append(c);	
			}
			String word = sb.toString();
			al.add(word);
			inputsize -= len;
		}
		String [] res = al.toArray(new String [al.size()]);
		AC ac = AC.build_clamav_ac(res);
		return ac;
	}

	/** return the number of final states */
	public int get_num_final_states(){
		return this.num_final_states;
	}

	/** return the number of states */
	public int get_num_states(){
		return this.tbl_goto.size();	
	}

	/**
		Normalize the final states so that all final states are numbered
	from 0 to max_final_state_id. It sets up the num_final_states attribute.
	*/
	public void normalize_final_states(){
		//1. count how many final states
		this.num_final_states = 0;
		int num_states = this.tbl_goto.size(); 
		for(int i=0; i<tbl_output.size(); i++){
			if(tbl_output.get(i).size()==0) num_final_states++;
		}	

		//2. create a map table
		int [] tbl_map = new int [tbl_output.size()];
		int idx_final = 0; //where final states starts
		int idx_non_final = num_final_states; //where non-accept state starts
		for(int i=0; i<tbl_output.size(); i++){
			if(tbl_output.get(i).size()==0){
				tbl_map[i] = idx_final++;
			}else{
				tbl_map[i] = idx_non_final++;
			}
		}	

		//3. reset all related tables 
		//3.1 create new tbl_goto
		ArrayList<HashMap<Character, Integer>> new_tbl_goto = new ArrayList(
			Collections.nCopies(num_states, null));
		for(int i=0; i<num_states; i++){
			HashMap<Character,Integer> map = tbl_goto.get(i);
			HashMap<Character,Integer> new_map = new HashMap();
			int new_src = tbl_map[i];
			for(Character c: map.keySet()){
				int nxt_state = map.get(c);
				int new_nxt_state = tbl_map[nxt_state];
				new_map.put(c, new_nxt_state);
			}
			new_tbl_goto.set(new_src, new_map);
		} 
		this.tbl_goto.clear();
		this.tbl_goto = new_tbl_goto;

		//3.2 create a new tbl_output
		ArrayList<ArrayList<String>> new_tbl_output = new ArrayList(
			Collections.nCopies(num_states, null));
		for(int i=0; i<num_states; i++){
			ArrayList<String> words = tbl_output.get(i);
			int new_src = tbl_map[i];
			new_tbl_output.set(new_src, words);
		} 
		this.tbl_output.clear();
		this.tbl_output= new_tbl_output;

		//3.3 create a new tbl_fail_
		ArrayList<Integer> new_tbl_fail= new ArrayList(
			Collections.nCopies(num_states, null));
		for(int i=0; i<num_states; i++){
			Integer fstate = tbl_fail.get(i);
			int new_src = tbl_map[i];
			int new_fstate = tbl_map[fstate];
			new_tbl_fail.set(new_src, new_fstate);
		} 
		this.tbl_fail.clear();
		this.tbl_fail= new_tbl_fail;

		//3.4 create a new tbl_depth
		ArrayList<Integer> new_tbl_depth= new ArrayList(
			Collections.nCopies(num_states, null));
		for(int i=0; i<num_states; i++){
			Integer depth = tbl_depth.get(i);
			int new_src = tbl_map[i];
			new_tbl_depth.set(new_src, depth);
		} 
		this.tbl_depth.clear();
		this.tbl_depth= new_tbl_depth;
		
		//3.4 create a new tbl_keyword_idx
		ArrayList<Integer> new_tbl_keyword_idx= new ArrayList(
			Collections.nCopies(num_states, null));
		for(int i=0; i<num_states; i++){
			Integer keyword_idx = tbl_src_keyword_idx.get(i);
			int new_src = tbl_map[i];
			new_tbl_keyword_idx.set(new_src, keyword_idx);
		} 
		this.tbl_src_keyword_idx.clear();
		this.tbl_src_keyword_idx= new_tbl_keyword_idx;

	}
	

	/** add a self loop to each state about term char */
	public void add_loop_term_char(){
		for(int i=0; i<this.tbl_goto.size(); i++){
				this.tbl_goto.get(i).put(this.TERM_CHAR, i);
		}
	}
	

	/** build the trie and the backedges
	*/
	public void build(){
		this.buildTrie();
		this.buildFailEdges();
		this.trapNonAcceptStates();
		this.normalize_final_states();
		//NO NEED ANYMORE. We we pad 1111's
		//this.add_loop_term_char(); 
	}


	// ------------ Protected Methods --------------
	/*** Find the next state. If not exist, return -1 */
	public int next_state(int cur_state, char ch){
		if(cur_state>=this.tbl_goto.size()) return -1;
		HashMap<Character,Integer> map = this.tbl_goto.get(cur_state);
		if(map.containsKey(ch)){
			return map.get(ch);
		}else{
			return -1;
		}
	}

	/*** set goto(cur_state, ch) = next_state */
	public void set_next_state(int cur_state, char ch, int next_state){
		HashMap<Character,Integer> map = this.tbl_goto.get(cur_state);
		map.put(ch, next_state);
		int cur_dist = this.tbl_depth.get(cur_state);
		int new_dist = cur_dist + 1;
		int dest_depth = this.tbl_depth.get(next_state); //should be there
		int val = new_dist<dest_depth? new_dist: dest_depth;
		this.tbl_depth.set(next_state, val);		
	}

	/*** add a new state to goto table, return the new state ID */
	public int add_new_state(int src_keyword_idx){
		this.tbl_goto.add(new HashMap<Character, Integer>());
		this.tbl_output.add(new ArrayList<String>());
		if(this.tbl_depth.size()==0){
			this.tbl_depth.add(0); //init state distance to itself is 0
		}else{
			this.tbl_depth.add(Integer.MAX_VALUE);
		}
		this.tbl_src_keyword_idx.add(src_keyword_idx);
		return this.tbl_goto.size()-1;
	}

	/*** add s to the output table */
	public void add_output(int state, String s){
		this.tbl_output.get(state).add(s);
	}

	/** build the Trie structure. */
	public void buildTrie(){
		Tools.start_timer("build_trie");
		Tools.log(Tools.INFO, "Build the Trie ...");

		this.add_new_state(-1); //for state 0
		for(int i=0; i<	this.arrKeywords.length; i++){
			String s = this.arrKeywords[i];
			//1. search the longest prefix of s	
			int cur_state = 0; 
			int nx_state = -1;
			int idx=0;
			while(idx<s.length()){
				nx_state = next_state(cur_state, s.charAt(idx));
				if(nx_state==-1) {break;}
				cur_state = nx_state;
				idx++;	
			}

			//2. build the trie for the rest
			for(; idx<s.length(); idx++){
				int nxt_state = this.add_new_state(i);	
				this.set_next_state(cur_state, s.charAt(idx), nxt_state);
				cur_state = nxt_state;
			}
			
			//3. set the output table
			this.add_output(cur_state, s); 
		}

		//patch state 0
		for(char i=0; i<this.alphabet_size; i++){
			if(next_state(0, i)==-1){
				set_next_state(0, i, 0);
			}
		}	
		long ms = Tools.stop_timer("build_trie");
		Tools.log(Tools.INFO, "Build Trie Time: " + ms + " ms");
		
		this.setStatesBits(); // for digitizeTransition()
	}

	/** set all transitions from each non-accepting state back to itself,
		because once trapped in an non-accept (final) state, it's regarded
		as a bad string */ 
	public void trapNonAcceptStates(){
		for(int i=0; i<this.tbl_goto.size(); i++){
			if(!isFinal(i)){
				this.tbl_goto.get(i).clear(); //first
				for(char j=0; j<alphabet_size; j++){
					this.tbl_goto.get(i).put(j, i);
				}
			}
		}
		//will keep the set_fail entry, but it will not be used anyway.
	}

	/** return the nice format of string given the alphabet size */
	public String nice(Character c){
		if(this.alphabet_bit_size==4){
			return Tools.hex4c_print(c);
		}else{
			return String.valueOf(c);
		}
	}

	/** similarly print the string in nice format for 4-bit alphabet */
	public String nices(String c){
		if(this.alphabet_bit_size==4){
			return Tools.hex4s_print(c);
		}else{
			return c;
		}
	}

	/** just dump the summar */
	public void dump_summary(){
		System.out.println("AC-DFA States: " + this.tbl_goto.size());
	}

	/** dump the depth information */
	public void dump_depth(){
		//1. get the max depth and total counts
		int max_depth = 0;
		for(int i=0; i<this.tbl_depth.size(); i++){
			int depth = this.tbl_depth.get(i);
			max_depth = depth>max_depth? depth: max_depth;
		}
		System.out.println("MAX_DEPTH: " + max_depth);
		//2. collect the counters
		Integer [] counters = new Integer [max_depth+1];
		for(int i=0; i<counters.length; i++) counters[i] = 0;	
		for(int i=0; i<this.tbl_depth.size(); i++){
			int depth = this.tbl_depth.get(i);
			counters[depth] = counters[depth]+1;
		}
		//3. print out the stats
		int total_states = this.tbl_depth.size();
		int sum = 0;
		for(int i=0; i<counters.length; i++){
			sum += counters[i];
			double val = sum*100.0/total_states;
			String str = String.format("%2.2f", val);
			System.out.println("Depth " + i + ": " + str);
		}
	}

	/** dump the depth information, but counting the setExclude */
	public void dump_depth_new(HashSet<Integer> freq_set){
		//1. get the max depth and total counts
		int max_depth = 0;
		for(int i=0; i<this.tbl_depth.size(); i++){
			int depth = this.tbl_depth.get(i);
			max_depth = depth>max_depth? depth: max_depth;
		}
		System.out.println("MAX_DEPTH: " + max_depth);
		//2. collect the counters
		Integer [] counters = new Integer [max_depth+1];
		//accumulated: counters_acc[i] includes all depth <= i
		//AND also the setExclude (freq_set)
		Integer [] counters_acc= new Integer [max_depth+1]; 
		for(int i=0; i<counters.length; i++){
			 counters[i] = 0;	
			 counters_acc[i] = 0;
		}
		//process each state i
		for(int i=0; i<this.tbl_depth.size(); i++){
			int depth = this.tbl_depth.get(i);
			counters[depth] = counters[depth]+1;

			Integer word_idx = this.tbl_src_keyword_idx.get(i);
			if(freq_set.contains(word_idx)){
				for(int j=0; j<=max_depth; j++){//coz it will be included in each depth set
					counters_acc[j] = counters_acc[j]+1;
				}
			}else{
				for(int j=depth; j<=max_depth; j++){
					counters_acc[j] = counters_acc[j]+1;
				}
			}
		}
		//3. print out the stats
		int total_states = this.tbl_depth.size();
		int sum = 0;
		int sum2 = 0;
		for(int i=0; i<counters.length; i++){
			sum += counters[i];
			sum2 = counters_acc[i]; //as it's accumulated
			double val = sum*100.0/total_states;
			double val2 = sum2*100.0/total_states;
			String str = String.format("%2.2f  freq_set counted: %2.2f, states: " + counters[i]+ " " + counters_acc[i], val, val2);
			System.out.println("Depth " + i + ": " + str);
		}
	}
	/** dump the goto table and output table */
	public void dump(){
		System.out.println("========== GOTO Table =============");
		for(int i=0; i<this.tbl_goto.size(); i++){
			HashMap<Character, Integer> map = this.tbl_goto.get(i);
			for(Character ch: map.keySet()){
				int next_s = map.get(ch);
				System.out.println(i + " -> " + next_s + ": " + nice(ch));
			}
		}
		System.out.println("========== Output Table =============");
		for(int i=0; i<this.tbl_output.size(); i++){
			System.out.print(i + ": " );
			ArrayList<String> arrs = this.tbl_output.get(i);
			for(String s: arrs){
				System.out.print(nices(s) + " ");
			}
			System.out.println("");
		}
		System.out.println("========== Fail Edges=============");
		for(int i=0; i<this.tbl_output.size(); i++){
			System.out.println(i + " FAIL-> " + get_fail(i));
		}
	}

	/** set the fail state for a state */
	public void set_fail(int state, int fail_state){
		this.tbl_fail.set(state, fail_state);
		int cur_dist = this.tbl_depth.get(state);
		int new_dist = cur_dist + 1;
		int dest_depth = this.tbl_depth.get(fail_state); //should be there
		if(dest_depth>new_dist){
			throw new RuntimeException("ERROR for set_fail: dest_depth: " + dest_depth + ">new_dist: " + new_dist);
		}
	}

	/** init all entries to 0 */
	public void init_fail_table(int n){
		for(int i=0; i<n; i++){
			this.tbl_fail.add(0);
		}
	}

	/** return the fail state for the given state */
	public int get_fail(int state){
		return this.tbl_fail.get(state);
	}

	/** build the fail edges */
	public void buildFailEdges(){
		Tools.start_timer("build_failedge");
		Tools.log(Tools.INFO, "Build the Fail Edges...");

		//1. build the 1st layer descendents' fail edges
		this.init_fail_table(this.tbl_output.size());
		Queue<Integer> queue = new LinkedList<Integer>();
		for(char a=0; a<this.alphabet_size; a++){
			int nx_state = next_state(0,a);
			if(nx_state!=0){
				queue.add(nx_state);
				set_fail(nx_state, 0);
			}
		}

		//2. build the others following FIFO order
		while(!queue.isEmpty()){
			int state = queue.remove();
			for(char a=0; a<this.alphabet_size; a++){
				int nx_state = next_state(state, a);
				if(nx_state!=-1){
					queue.add(nx_state);
					int old_fail = this.get_fail(state);
					while(next_state(old_fail, a)==-1){
						old_fail = this.get_fail(old_fail);
					}
					
					int new_fail_state = next_state(old_fail, a);
					set_fail(nx_state, new_fail_state);
					this.tbl_output.get(nx_state).addAll(
						this.tbl_output.get(new_fail_state) );
				}
			}
		}
		long ms = Tools.stop_timer("build_failedge");
		Tools.log(Tools.INFO, "Build FailEdge Time: " + ms + " ms");
	}


	/** an sample of DFA.dat */
	private String get_sample_serialization(){
		String s = 
			"AlphabetBits: 4 \n" +
			"States: 3 \n" +
			"0 1\n" +  //NOTE: 1 marks this is a final state
						//a state is FINAL if tbl_output[state_id] is EMPTY!
			"1 \n" +
			"2 \n" +
			"GOTO: 5 \n" + 
			"11 \n" +
			"17 \n" +
			"19 \n" +
			"23 \n" +
			"25 \n" +
			"FAIL: 2 \n" +
			"28 \n" +
			"37 \n" 
			;
		return s;
	}

	
	/** return the array of digitalized transitions, write the
		values into fpath. Reason: ArrayList could too big.
		write small chunks at a time */
	public int write_trans_as_num(String fpath){
		return write_trans_as_num_worker(Integer.MAX_VALUE, new HashSet<Integer>(), fpath);
	}
	
	/** return the array of digitalized transitions, for those
		whose source state depth less than or equal to depth_limit,
		or to_include includes it. ALSO append to the given filepath.
		Return the total number of transitions appended */
	public int write_trans_as_num_worker(int depth_limit,
		HashSet<Integer> to_include, String path){
		ArrayList<BigInteger> arr = new ArrayList<>();
		int LIMIT = 1024*128-1;
		int count = 0;


		Transition trans = new Transition(0, (char )0, 0, false);
		for(int i=0; i<this.tbl_goto.size(); i++){
			if(tbl_depth.get(i)>depth_limit && !to_include.contains(tbl_src_keyword_idx.get(i))) continue;
			HashMap<Character, Integer> map = this.tbl_goto.get(i);
			for(char ch = 0; ch<this.alphabet_size; ch++){
				int next_s = next_state(i, ch);
				//1. regular transitions
				if(next_s!=-1){
					trans.set(i, ch, next_s, false);
					arr.add(digitizeTransition(trans));
				}else{
					//2. fail transitions
					next_s = get_fail(i); 
					trans.set(i, ch, next_s, true);
					arr.add(digitizeTransition(trans));
				}
				count++;
			}
			//3. self-loop transitions 
			trans.set(i, this.TERM_CHAR, i, true);
			arr.add(digitizeTransition(trans));
			count++;
			trans.set(i, this.TERM_CHAR, i, false);
			arr.add(digitizeTransition(trans));
			count++;

			//4. quick append if buffer is full	
			if(arr.size()>LIMIT){
				Tools.append_arr_to_file(arr, path);
				arr.clear();
			}
		}
		
		if(arr.size()>0){
			Tools.append_arr_to_file(arr, path);
		}
		return count;
	}
	
	/** write the array of digitalized states, return the count*/
	public int write_states_as_num(String fpath){
		return write_states_as_num_worker(Integer.MAX_VALUE, new HashSet<Integer>(), fpath);
	}

	/** write the array of digitalized states if the depth of the state
	is less than or equal to depth_limit or its keyword source is
	contained in to_include, return the count*/
	public int write_states_as_num_worker(int depth_limit, HashSet<Integer> to_include, String path){
		int LIMIT = 1024*128-1;
		int count = 0;
		ArrayList<BigInteger> arr = new ArrayList<>();
		for(int i=0; i<this.tbl_output.size(); i++){
			if(tbl_depth.get(i)>depth_limit && !to_include.contains(tbl_src_keyword_idx.get(i))) continue;
			BigInteger bi = BigInteger.valueOf(i);
			arr.add(bi);
			count++;

			if(arr.size()>LIMIT){
				Tools.append_arr_to_file(arr, path);
				arr.clear();
			}
		}
		if(arr.size()>0){
			Tools.append_arr_to_file(arr, path);
		}
		return count;
	}

	/** write the array of digitalized states*/
	public ArrayList<BigInteger> get_final_states_as_num(String fpath){
		ArrayList<BigInteger> arr = new ArrayList<>();
		for(int i=0; i<this.tbl_output.size(); i++){
			if(tbl_output.get(i)==null || tbl_output.get(i).size()==0){
				BigInteger bi = BigInteger.valueOf(i);
				arr.add(bi);
			}
		}
		return arr;
	}

	// ***************************************************
	// *** PART1: serialize the automaton ****
	// ***************************************************

	/** Set K values using member variables as to only calculate once */
	public void setStatesBits(){
		this.k = (int)ceil(log10(tbl_goto.size())/log10(2)); // convert to log2
		this.pow2k = (int)pow(2, this.k); // 2^k
		this.pow2k2 = (int)pow(this.pow2k,2); // (2^k)^2 = 2^2k
		//this.pow2k2 = (int)pow(2, this.k*2); // 2^2k unoptomized
	}

	//get the number of states needed to encode a state
	public int getStateBits(){
		return this.k; 
	}

	/** Encode Transitions for serialization. Our assumption is that
	combining all components, the LOGICAL length is less than 61 bits
	(before applying the +2^61 at the end).
		Structure:
	char (usually 4 bits) | state1 (usually 28 bits) | state2 (28 bits) | bFail
	+ 2^62
	assumption: state never greater than 28 bits.  
	Thus: it always makes set of states and set of transitions
	disjoint. Also, if one tries to use a transition as a state
	to fake transition it could not be successful.
	Legal transition sets: [2^61, 2^61+2^60] = [2^61, 2^62)
	If one fakes a state using a transition, the fake transition
	falls in range [2^62 + 2^61, 2^(62+28) + 2^61] = (2^62, 2^91)
	So a "faked" transition will not fall in the set of transitions.
	 */
	public BigInteger digitizeTransition(Transition trans){

		// formula: given (s1, c, s2)
		// let k be the number of bits needed to encode states
		// k should be ceil(log2(number_of_states))
		// val = c*2^{2k} + s1*2^k + s2;
		// Transition {int src,char c,int dest} 
		// optimized
		// UPDATED: 
		// val  = c*2^{2*k+1} + s1*2^{k+1] +s2*2 + bFail
		//UPDATED 07/08/2022: add a 2^62 component to make state and trans
		// set disjoint!
		long comp1 = trans.c;
		comp1 = comp1 << (2*k + 1);
		long comp2 = trans.src;
		comp2 = comp2 << (k+1);
		long comp3 = trans.dest;
		comp3 = comp3 << 1;
		long comp4 = trans.bFail? 1: 0;
		long res = comp1 + comp2 + comp3 + comp4;
		
		BigInteger pow62 = BigInteger.valueOf(1).shiftLeft(62);
		BigInteger ret = BigInteger.valueOf(res).add(pow62);
		return ret;
	}

	/** save the entire AC-DFA to the given file */
	public void serialize_to(String path){
		new_serialize_to(path);
	}

	/** lazy approach: will reuse old_serialzie_to later for saving
		space */
	public void new_serialize_to(String path){
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
			out = new ObjectOutputStream(bos);   
		  	out.writeObject(this);
		  	out.flush();
		  	byte[] bsFile = bos.toByteArray();

			File f1 = new File(path);
			FileOutputStream fs = new FileOutputStream(f1);
			//BufferedWriter buf = new BufferedWriter(new OutputStreamWriter(fs));
			fs.write(bsFile);
			fs.flush();
			fs.close();
		}catch(IOException exc){
			Tools.panic(exc.toString());
		}finally {
		  try {
			bos.close();
		  } catch (IOException ex) {
			Tools.panic(ex.toString());
		  }
		}
	}

	/** 
	Serialize and dump the goto table and fail table of AH-DFA.
	Note: (1) instead of writing the entire contents into file,
			do it line by line (to save memory)
		  (2) call digitaizeTransition 
			to generate the output. This needs to be separate
			for refactoring/future change purpose.
		  (3) refer to get_sample_seralization() as an example
	*/
	public void old_serialize_to(String path){
		try{
			// Initialize BufferedWriter
			File f1 = new File(path);
			FileOutputStream fs = new FileOutputStream(f1);
			BufferedWriter buf = new BufferedWriter(new OutputStreamWriter(fs));

			// AlphabetBits: 
			buf.write("AlphabetBits: " + Integer.toString(this.alphabet_bit_size));
			buf.newLine();

			// States:
			int gtSize = this.tbl_goto.size();
			buf.write("States: " + Integer.toString(gtSize)); 
			buf.newLine();
			
			// Initialize variables to maintain GOTO data
			String gtStr = "";
			int numTrans = 0; // count transitions for GOTO: <numTrans>

			// loop over GOTO to get State and GOTO information
			for (int i = 0; i < gtSize; i++){

				// Directly write States data
				buf.write(Integer.toString(i)+" ");
				if (tbl_output.get(i).size()==0) buf.write("1");
				buf.newLine();
				
				// Collect and maintain GOTO data
				HashMap<Character, Integer> map = this.tbl_goto.get(i);
				numTrans += map.size(); 
				gtStr+=this.gtTranstoStr(map, i);
			}

			// GOTO:
			buf.write("GOTO: " + Integer.toString(numTrans));
			buf.newLine();
			buf.write(gtStr); // gtStr ends with \n so no newLine needed

			// FAIL: 
			int fSize = this.tbl_fail.size();
			buf.write("FAIL: " + Integer.toString(fSize));
			buf.newLine();
			for (int i = 0; i < fSize; i++){
				buf.write(Integer.toString(get_fail(i)));
				buf.newLine();
			}
			buf.close();
		}

		catch(IOException e){
			System.out.println("Could not generate file: " + path);
			System.out.println("serialize_to throws exception: " + e.toString());
			e.printStackTrace();
		}

		/*String sContent = get_sample_serialization();
		Tools.write_to_file(path, sContent);*/
	}

	/** Convert a line into an integer using regex */
	public static int[] lineToInt(String line){
		String[] regex = line.split(" ");
		int value = Integer.parseInt(regex[0]);
		int fin = regex.length==2?1:0;
		int[] ints = {value, fin};
		return ints;
	}

	/** read AC from file */
	public static AC deserialize(String path){
		return new_deserialize(path);
	}

	/** adapt old_deserialize when having time */
	public static AC new_deserialize(String sPath){
		AC ac = null;
	  	try{
			Path path = Paths.get(sPath);
			byte [] bytes = Files.readAllBytes(path);
			InputStream is = new ByteArrayInputStream(bytes);
			ObjectInputStream ois = new ObjectInputStream(is); 
		  	ac = (AC) ois.readObject();
	  	}catch(Exception exc){
			Tools.panic(exc.toString());
	  	}
		return ac;
	}

	/** reconstruct the AC from the path, in this case you don't
		have the complete info, fill the output_table
		for non-accepting states with some string as place holder */
	public static AC old_deserialize(String path){
		try{
			BufferedReader r = new BufferedReader(new FileReader(path));

			// AlphabetBits:
			String line = r.readLine();
			int alphBitSize = sizeFromHead(line);
			line = r.readLine();

			// States: 
			int stateSize = sizeFromHead(line);
			ArrayList<Integer> States = new ArrayList();
			ArrayList<Integer> Finals = new ArrayList(); 

			int i = 0;
			line = r.readLine(); // move from header line
			while (line != null && i<stateSize){ 
				// e.g. "1 " -> ["1"] & "1 1" -> ["1", "1"]
				int[] state = lineToInt(line);
				States.add(state[0]);

				// final state
				if (state[1] == 1){
					Finals.add(state[0]);
				}
				line = r.readLine();
				i++;
			}


			// Transitions
			int gtSize = sizeFromHead(line);
			ArrayList<Integer> Trans = new ArrayList();
			line = r.readLine();
			i = 0;
			while (line != null && i < gtSize){
				// "1 " -> "1"
				Trans.add(lineToInt(line)[0]);
				line = r.readLine();
				i++;
			}	

			// Fails
			int failSize = sizeFromHead(line);
			line = r.readLine();
			ArrayList<Integer> Fails = new ArrayList();
			while (line != null){
				Fails.add(lineToInt(line)[0]);
				line = r.readLine();
			}

			AC des = new AC(alphBitSize, States, Trans, Fails, Finals);
			return des;
		}
		catch (IOException e){
			System.out.println("Could not generate file: " + path);
			System.out.println("deserialize throws exception: " + e.toString());
			e.printStackTrace();
		}
		return null;
	}

	/** return the list of final/accept states, the list of final states
		are those which have NO output words associated. */
	public HashSet<Integer> getFinalStates(){
		// for loop over output??
		HashSet<Integer> finals = new HashSet<Integer>();
		for (int i = 0; i < this.tbl_goto.size(); i++){
			if(isFinal(i)){
				finals.add(i);
			}
		}		
		return finals;
	} 

	// For creating transitions outside of class
	public String getDigit(int cstate, Character ch, int nstate){
		Transition trans = new Transition(cstate, ch, nstate, false);
		return digitizeTransition(trans).toString();
		
	}

	/** Serialize GOTO maps by conversion to transitions */
	public String gtTranstoStr(HashMap<Character, Integer> map, int cstate){
		String serial = "";
		for (Character c: map.keySet()){
			int nstate = map.get(c);
			String digit = getDigit(cstate,c,nstate);
			//Transition toDigit = new Transition(cstate, c, nstate);
			serial += digit + " \n";
			//serial += digitizeTransition(toDigit).toString() + " \n"; 
		}
		return serial;
	}

	/** Given a 'header' line from a serialized file, split string and 
	convert to an integer value	
	*/
	public static int sizeFromHead(String line){
		String[] regex = line.split(": *");
		// regex[0] = "States"; regex[1] = "3";
		if (regex.length != 2){
			return -1;
		}
		return Integer.parseInt(regex[1]); 
	}


	// *****************************************************
	// PART2: generate run of a string
	// *****************************************************

	/** return the list of transitions by running the input string.
		Note: the handling of fail edges. If a character is traveling
		on fail edges, it should CONTINUE to travel, until it is
		consumed by a real goto edge.
	*/
	public ArrayList<Transition> run(String inputstr){
		int curr_state = 0;
		int next_state = 0;
		ArrayList<Transition> transitions = new ArrayList<Transition>();
		for(int i = 0; i < inputstr.length(); i++) {
			char c = inputstr.charAt(i);
			// handle fail edges:
			while((next_state(curr_state, c) == -1) && (tbl_fail.get(curr_state) != curr_state)) {	// fail edge = no next state and the fail edge cannot point to itself
				// transitions include fail edges:
				int curr_state2 = tbl_fail.get(curr_state);
				transitions.add(new Transition(curr_state, c, curr_state2, true));
				curr_state = curr_state2;
			}
			next_state = next_state(curr_state, c);
			transitions.add(new Transition(curr_state, c, next_state, false));
			curr_state = next_state;
		}
		return transitions;
	}

	/** Get the max depth of the input string by run it. exclude the
	setExclude */
	public int get_max_depth_by_run(String inputstr, HashSet<Integer> setExclude){
		int curr_state = 0;
		int next_state = 0;
		int max_depth = 0;
		for(int i = 0; i < inputstr.length(); i++) {
			char c = inputstr.charAt(i);
			if(c==TERM_CHAR){//self loop
				continue;
			}
			// handle fail edges:
			while((next_state(curr_state, c) == -1) && (tbl_fail.get(curr_state) != curr_state)) {	// fail edge = no next state and the fail edge cannot point to itself
				// transitions include fail edges:
				int curr_state2 = tbl_fail.get(curr_state);
				int depth = tbl_depth.get(curr_state);
				int word_idx = tbl_src_keyword_idx.get(curr_state);
				if(!setExclude.contains(word_idx)){
					max_depth = max_depth<depth? depth : max_depth;
				}
				curr_state = curr_state2;
			}
			next_state = next_state(curr_state, c);
			int depth = tbl_depth.get(curr_state);
			int word_idx = tbl_src_keyword_idx.get(curr_state);
			if(!setExclude.contains(word_idx)){
				max_depth = max_depth<depth? depth : max_depth;
			}
			curr_state = next_state;
		}
		return max_depth;
	}

	/** Get compression rate: set_of_(transitions+states) / list_of_transition size. Might be larger than 1.00. */
	public double get_compression_rate(String inputstr){
		HashSet<BigInteger> setST = new HashSet<>();
		int curr_state = 0;
		int next_state = 0;
		for(int i = 0; i < inputstr.length(); i++) {
			char c = inputstr.charAt(i);
			if(c==TERM_CHAR) continue; //do not count
			while((next_state(curr_state, c) == -1) && (tbl_fail.get(curr_state) != curr_state)) {	
				// transitions include fail edges:
				int curr_state2 = tbl_fail.get(curr_state);
				curr_state = curr_state2;
				Transition trans = new Transition(curr_state, c, curr_state2, true);
				BigInteger it = digitizeTransition(trans); 
				setST.add(it);
				setST.add(BigInteger.valueOf(curr_state));
				setST.add(BigInteger.valueOf(curr_state2));
			}
			next_state = next_state(curr_state, c);
			Transition trans = new Transition(curr_state, c, next_state, false);
			BigInteger it = digitizeTransition(trans); 
			setST.add(it);
			setST.add(BigInteger.valueOf(curr_state));
			setST.add(BigInteger.valueOf(next_state));
			curr_state = next_state;
		}
		return setST.size()*1.0/inputstr.length();
	}


	/** generate a chuncked run. Each chunk run chunk_size of input characters, and generate 2*chunk_size transitions (by padding) with TERM_CHAR transitions.
NOTE: each chunk (except the last one) should have the SAME chunk_size. 
The size of return: 2*len(inputstr)
	Note this function will be deprecated. As it MIGHT occasionally fail
	depending on some "unlucky" inputs with a lot of back-edges
 */
	public ArrayList<Transition> run_by_chunks(String inputstr, int num_chunks){
		//1. input sanity check
		throw new RuntimeException("run_by_chunks deprecated. call adv_run_by_chunks instead");
		/*
		int total_len = inputstr.length();
		int chunk_size = total_len/num_chunks; 

		//2. build up the transitions
		int curr_state = 0;
		int next_state = 0;
		ArrayList<Transition> transitions = new ArrayList<Transition>();
		for(int j = 0; j < num_chunks; j++) {
			int cur_size = transitions.size();
			int my_size = j<num_chunks-1? chunk_size: total_len%num_chunks + chunk_size;
			for(int i=0; i<my_size; i++){
				char c = inputstr.charAt(i+j*chunk_size);
				// handle fail edges:
				while((next_state(curr_state, c) == -1) 
					&& (tbl_fail.get(curr_state) != curr_state)) {	
					int curr_state2 = tbl_fail.get(curr_state);
					transitions.add(new Transition(curr_state, c, curr_state2, true));
					curr_state = curr_state2;
				}
				next_state = next_state(curr_state, c);
				transitions.add(new Transition(curr_state, c, next_state, false));
				curr_state = next_state;
			}
			int added = transitions.size()-cur_size;
			int num_remain = 2*my_size - added;
			for(int i=0; i<num_remain; i++){
				Transition self_loop = new Transition(curr_state, TERM_CHAR, 
					curr_state, false); //TREAT IT AS ok-edge now (it's there)
				transitions.add(self_loop);
			}
		}
		if(transitions.size()!=2*total_len){
			Tools.panic("generated transition length: " + transitions.size()
				+ "!= 2*total_len: " + 2*total_len);
		}
		return transitions;
		*/
	}


	/**  Fill the transitions into the input transitions. It will be clear
	at the beginning. If ERROR. return an int [] which
		contains information of:
	[idx_of_chunk_with_err, the_last_value_of_num_remain]
	return NULL if ok
	*/
	public int [] adv_run_by_chunks(String inputstr, int init_state, int num_chunks, ArrayList<Transition> transitions, boolean b_debug){
		//1. input sanity check
		transitions.clear();
		int total_len = inputstr.length();
		int chunk_size = total_len/num_chunks; 

		//2. build up the transitions
		int curr_state = init_state;
		int next_state = 0;
		for(int j = 0; j < num_chunks; j++) {
			int cur_size = transitions.size();
			int my_size = j<num_chunks-1? chunk_size: total_len%num_chunks + chunk_size;
			int max_back_depth = 0;
			for(int i=0; i<my_size; i++){
				char c = inputstr.charAt(i+j*chunk_size);
				//special handling for TERM_CHAR (as padding chars)
				if(c==TERM_CHAR){
					Transition trans = new Transition(curr_state, c, curr_state, false);
					transitions.add(trans);
					if(b_debug){
						System.out.println("chunk: " + j + ", TERM CHAR " + 
							i + ": "+trans);
					}
					continue;
				}

				// handle fail edges:
				int cur_back_depth = 0;
				while((next_state(curr_state, c) == -1) 
					&& (tbl_fail.get(curr_state) != curr_state)) {	
					int curr_state2 = tbl_fail.get(curr_state);
					Transition trans = new Transition(curr_state, c, curr_state2, true);
					transitions.add(trans);
					if(b_debug){
						System.out.println("chunk: " + j + ", CHAR " + i + ": "+trans);
					}
					curr_state = curr_state2;
					cur_back_depth ++;
				}
				if(cur_back_depth>max_back_depth) {max_back_depth=cur_back_depth;}
				next_state = next_state(curr_state, c);
				Transition trans = new Transition(curr_state, c, next_state, false);
				transitions.add(trans);
				if(b_debug){
					System.out.println("chunk: " + j + ", CHAR " + i + ": "+trans);
				}
				curr_state = next_state;
			}
			int added = transitions.size()-cur_size;
			int num_remain = 2*my_size - added;
			if(num_remain<0){//ERROR!
				return new int [] {j, num_remain, max_back_depth};
			}
			for(int i=0; i<num_remain; i++){
				Transition self_loop = new Transition(curr_state, TERM_CHAR, 
					curr_state, true); //self-loop fail edge (char not count!)
				//NOTE: if there are SPECIFICALLY padded TERM_CHAR by
				//read_and_pad iteration  in RustProver, they ARE
				//regarded as valid paraters (non-fail edges!)
				transitions.add(self_loop);
			}
		}
		if(transitions.size()!=2*total_len){
			Tools.panic("generated transition length: " + transitions.size()
				+ "!= 2*total_len: " + 2*total_len);
		}

		return null;
	}
	/** generate a random ACCEPTED run (with no states in non-accept states).
	NOTE: the length is the DESIRED LENGTH of the actual input
	characters. That is: the number of NON-FAILING edges in
	the resulting ArrayList<Tranistion) return. In another word,
	run collect_input on the return generates an input string
	of n chars.
	 */
	public ArrayList<Transition> rand_accept_run(long seed, int length){
		Random rand  = new Random(seed);
		int curr_state = 0;
		int next_state = 0;
		int MAX_ATTEMPTS = alphabet_size*2;
		
		ArrayList<Transition> transitions = new ArrayList<Transition>();
		int nChars = 0;
		for(int i = 0; i < length; i++) {
			int attempt = 0;
			boolean bFound = false;
			for(attempt=0; attempt<MAX_ATTEMPTS && !bFound; attempt++){
				char c = (char) rand.nextInt(alphabet_size);
				ArrayList<Transition> toAdd = new ArrayList();
				int old_cur_state = curr_state;
				
				//1. process backedges
				while((next_state(curr_state, c) == -1) && 
					(tbl_fail.get(curr_state) != curr_state)) {	
					// transitions include fail edges:
					int curr_state2 = tbl_fail.get(curr_state);
					toAdd.add(new Transition(curr_state, c, curr_state2, true));
					curr_state = curr_state2;
				}
				//2. process good edge
				next_state = next_state(curr_state, c);
				toAdd.add(new Transition(curr_state, c, next_state, false));

				//3. check if there is any un-accpeted state 
				boolean bHasNonAccState = false;
				for(int k=0; k<toAdd.size(); k++){
					if(!isFinal(toAdd.get(k).dest)){
						bHasNonAccState = true;
						break;
					}
				}
				if(bHasNonAccState){
					curr_state = old_cur_state; //try again
				}else{
					curr_state = next_state;
					bFound = true;
					for(int k=0; k<toAdd.size();  k++){
						transitions.add(toAdd.get(k));
					}
				}
			}//end for attempt
			if(attempt>=MAX_ATTEMPTS){
				Tools.panic("Can't find accepted path. Exceeded max attempt: " + MAX_ATTEMPTS);
				return null;
			}
			nChars ++;
		}
		String sinp = collect_inputs(transitions);
		if(sinp.length()!=length) {
			Tools.panic("sinp.len!=desired length, sinp.len: " +
				sinp.length() + ", length: " + length +
				", trans.length: " + transitions.size());
		
		}
		return transitions;
	}


	/** return True for final states */
	public boolean isFinal(int state){
		return tbl_output.get(state).size() == 0;
	}

	/** call run, and check if the last state is one of the final states */
	public boolean accepts(String inputstr){
		int curr_state = 0;
		int next_state = 0;
		for(int i = 0; i < inputstr.length(); i++) {
			char c = inputstr.charAt(i);
			// handle fail edges:
			while((next_state(curr_state, c) == -1) && (tbl_fail.get(curr_state) != curr_state)) {	// fail edge = no next state and the fail edge cannot point to itself
				// transitions include fail edges:
				int curr_state2 = tbl_fail.get(curr_state);
				curr_state = curr_state2;
			}
			next_state = next_state(curr_state, c);
			curr_state = next_state;
		}
		
		boolean bret = this.isFinal(curr_state);
		if(!bret){
			ArrayList<String> strs = tbl_output.get(curr_state);
			for(String s: strs){
				System.out.println("DEBUG USE 300: failed on pattern: " + nices(s) + ", len: " + s.length());
			}
		}
		return bret;
	}

	/** print the stats of the exclude set */
	public void dump_excludeset_stats(HashSet<Integer> set){
		int total_states = 0;
		for(int i=0; i<this.tbl_src_keyword_idx.size(); i++){
			Integer ele = tbl_src_keyword_idx.get(i);
			if(set.contains(ele)){
				total_states += 1;
			}
		}	
		double ratio = total_states * 100.0/ this.tbl_src_keyword_idx.size();
		System.out.println("Exclude set size: " + set.size() + ", ratio among states: " + ratio + "%" +", total_states: " + total_states + ", ALL automata states: " + tbl_src_keyword_idx.size());
	}

	/** return max_depth of source of each trans */
	public int get_max_depth(ArrayList<Transition> arr_trans, HashSet<Integer> setToExclude){
		int max_depth = 0;
		for(Transition trans: arr_trans){
			int src_state = trans.src;
			int depth = this.tbl_depth.get(src_state);
			int idxWord = this.tbl_src_keyword_idx.get(src_state);
			if(!setToExclude.contains(idxWord)){
				max_depth = max_depth<depth? depth: max_depth;
			}
		}
		return max_depth;
	}

	/** returns for each depth an hashset of the index of source keyword
	strings */
	public ArrayList<HashSet<Integer>> get_depth_stats(ArrayList<Transition> arr_trans){
	HashSet<Integer> setEmpty = new HashSet<>();
	ArrayList<HashSet<Integer>> res = new ArrayList<HashSet<Integer>>();
	int max_depth = get_max_depth(arr_trans, setEmpty);
	for(int i=0; i<=max_depth; i++){ res.add(new HashSet<Integer>()); }
	for(Transition trans: arr_trans){
			int src_state = trans.src;
			Integer src_keyword_idx = this.tbl_src_keyword_idx.get(src_state);
			int depth = this.tbl_depth.get(src_state);
			res.get(depth).add(src_keyword_idx);
	}
	return res;
}

	/** Generate a string dump: dump from the max depth to the set of index */
	public String dump_depth_stats(ArrayList<HashSet<Integer>> stats,
		int max_set_size){
		StringBuilder sb = new StringBuilder();
		int max_depth = stats.size()-1;
		HashSet<Integer> cur_set = new HashSet<>();
		for(int i = max_depth; i>=0 && cur_set.size()<max_set_size; i--){
			HashSet<Integer> set = stats.get(i);
			if(!set.equals(cur_set)){
				String str = String.format("depth " + i + ": " + set.toString() + "; ");
				sb.append(str);
			}
			cur_set = set;	
		}	
		return sb.toString();
	}

	/** pad the input to 2^k */
	public String pad_inputs(String sinput){
		if (2>1+0) throw new RuntimeException("pad_inputs is deprecated. call padd_nibbles!");
		int n = sinput.length();
		int n2 = Tools.ceil_power2(n);
		if(n2>n){
			byte [] bzeros = new byte [n2-n];
			String s2 = new String(bzeros);
			String res = sinput + s2;
			return res;
		}else{
			return sinput;
		}
	}


	/** run but return the list of states. If the length
		is n, the array returned will be n+1.
	*/
	public int [] get_run_states(String sinput){
		if (3+2>4) {throw new RuntimeException("accepts() is deprecated. call adv_run_by_chunks instead!");}
		ArrayList<Transition> arr = run(sinput);
		int [] states = new int [arr.size()+1];
		states[0] = 0;
		for(int i=0; i<arr.size(); i++){
			states[i+1] = arr.get(i).dest;
		}
		return states;
	}

	/** Collect the inputs from the transitions (ignoreing back/fail
		edges */
	public String collect_inputs(ArrayList<Transition> al){
		StringBuilder sb = new StringBuilder();
		//1. calculate length
		int nChars = 0;
		for(int i=0; i<al.size(); i++){
			if(!al.get(i).bFail){
				nChars ++;
			}	
		}

		//2. get the char array
		char [] arr = new char [nChars];	
		int idx = 0;
		for(int i=0; i<al.size(); i++){
			if(!al.get(i).bFail){
				arr[idx++] =al.get(i).c;
			}	
		}
		String sRet = new String(arr);
		return sRet;
	}


	/** return true if filename is a virus */ 
	public boolean isVirus(String filename){
		byte[] nibbles = Tools.read_nibbles_from(filename);
		String nibbles_str = new String(nibbles);
		return !(this.accepts(nibbles_str));
	}

	/** list the viruses in the folder. max_depth is the max depth to 
	explore, max_num_files is the max_number of files to  inspect.
		when they are -1, -1 means to get the complete list.
	*/
	public String [] listVirus(String destName, int max_depth, int max_num_files){
		String[] files = Tools.getFiles(destName, max_depth, max_num_files, Long.MAX_VALUE );
		ArrayList<String> viruses = new ArrayList<String>();

		for (String f : files){
			if (isVirus(f)) viruses.add(f);
		}

		String[] bad_files = new String[viruses.size()];
		viruses.toArray(bad_files);
		return bad_files;
		//throw new UnsupportedOperationException("NOT DONE");
	}



}
