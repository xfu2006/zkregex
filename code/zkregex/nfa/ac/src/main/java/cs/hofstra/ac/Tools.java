package cs.Employer.ac;
import java.nio.file.Files;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.io.PrintWriter;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;   
import java.io.FileWriter;
import java.math.BigInteger;
import java.io.BufferedReader;
import java.io.FileReader;

/** Utility class.
* It provides logging and file operations
* Authors: Dr. CorrAuthor, Author2, Author1, Author3
*/

public class Tools{
	static class Timer{
		long startTime = 0;
		long elapsed_ms = 0;
		String name;

		public Timer(String name){
			this.name = name;
		}
		public void start(){
			this.startTime = System.currentTimeMillis();
		}
		public void stop(){
			this.elapsed_ms = (System.currentTimeMillis()-this.startTime);
			this.startTime = 0;
		}
		public long get_elapsed_ms(){
			return this.elapsed_ms;
		}
	}
	public static final int INFO2 = 1;
	public static final int INFO = 2;
	public static final int WARNING = 3;
	public static final int ERROR = 4;
	public static int cur_log_level = 0;
	public static HashMap<String, Timer> map_timer= new HashMap();


	/** log/print the message 
	* @param level - one of INFO, WARNING, and ERROR. Only when the
	*	cur_log_level above the given level, the message will be printed
	* @msg - the message to log
	*/	
	public static void log(int level, String msg){
		if(level>=Tools.cur_log_level){
			System.out.println(msg);
		}
	} 

	/** set the log level, must be one of INFO, WARNING, ERROR */
	public static void set_log_level(int level){
		Tools.cur_log_level = level;
	}

	/** read the file contents into one string */
	public static String read_file(String filename){
		try{
        	byte[] encoded = Files.readAllBytes(Paths.get(filename));
        	return new String(encoded, StandardCharsets.UTF_8);
		}catch(Exception e){
			System.out.println(e.toString());
			System.out.println("This error was thrown by read_file in Tools.java");
			return null;
		}
	}

	/** read line by line */
	public static ArrayList<String> read_file_lines(String fname){ 
		BufferedReader bf;
		ArrayList<String> arr = new ArrayList<>();
		try{
			bf = new BufferedReader(new FileReader(fname));
			String line = bf.readLine();
			while(line!=null){
				 if(line.length()>3){
					line = line.trim();
					arr.add(line);
				 }
				line = bf.readLine();
			}
		}catch(Exception e){
			e.printStackTrace();
			panic("ERROR read file: " + fname);
		}
		return arr;	
	}

	/** read the file contents (as 4-bit nibbles) into byte array.
		Each byte is split into 2 nibbles in BIG-endian.
		E.g., "\x03\xab" is tranlated to
		"03ab". (nibble order swapped) The resulting length of the string
		is TWice the file size. */
	public static byte [] read_nibbles_from(String filename){
		try{
        	byte[] encoded = Files.readAllBytes(Paths.get(filename));
			byte[] nibbles = new byte [2*encoded.length];
			for(int i=0; i<encoded.length; i++){
				byte ch = encoded[i];
				byte low_nibble = (byte) (ch & 0x0F);
				byte high_nibble = (byte) ((ch & 0xF0) >>> 4);
				nibbles[i*2+1] = low_nibble;
				nibbles[i*2] = high_nibble;
			}
        	return nibbles;
		}catch(Exception e){
			System.out.println(e.toString());
			return null;
		}
	}

	/** convert byte array to string */
	public static String bytearr_to_str(byte [] arr){
		return new String(arr, StandardCharsets.UTF_8);
	}
	/** Write the array list to the file. Each number per line.
		Note: FIRST number is the total number of lines.
		ASSUMPTION: all values are below 64-bit! */
	public static void write_arr_to_file(ArrayList<BigInteger> arr, 
		String fname){
		try{
			int size = arr.size();
			FileWriter fw = new FileWriter(fname);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(String.valueOf(size) + "\n");
			for (int i = 0; i < size; i++) {
				bw.write(arr.get(i).toString()+"\n");
			}
			bw.close();
			fw.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
 	}

	/** ONLY recommended for small files, TODO: define some
		additional function for sequentially write to file 
		line by line */
	public static void write_to_file(String filename, String contents){
		try{
			PrintWriter out = new PrintWriter(filename);
			out.println(contents);
			out.close();
		}catch(Exception exc){
			panic("write_to_file ERROR: " + exc.toString());
		}
	}

	/** append list of numbers to file */
	public static void append_arr_to_file(ArrayList<BigInteger> arr, String fpath){
		try{
			int size = arr.size();
			FileWriter fw = new FileWriter(fpath, true); //append mode
			for (int i = 0; i < size; i++) {
				fw.write(arr.get(i).toString()+"\n");
			}
			fw.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
}

	/** start the timer */
	public static void start_timer(String name){
		if(!map_timer.containsKey(name)){
			map_timer.put(name, new Timer(name));
		}
		Timer timer = map_timer.get(name);
		timer.start();
	}

	/** stop the timer and get time in milli-seconds */
	public static long stop_timer(String name){
		if(!map_timer.containsKey(name)){
			map_timer.put(name, new Timer(name));
		}
		Timer timer = map_timer.get(name);
		timer.stop();
		return timer.get_elapsed_ms();
	}

	/** stop running */
	public static void panic(String s){
		System.err.println("FATAL ERROR: " + s);
		System.exit(1);
	}

	/** translate each character regarded as a 4-bit hex number,
		e.g., "ab01" is translated into unicode "\xa\xb\x0\x1" */ 
	public static String parse_hex4(String s){
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<s.length(); i++){
			char ch = s.charAt(i);
			char newch = (char) Integer.decode("0x"+String.valueOf(ch)).intValue();
			if(newch>16){panic("ch: " + newch + "  out of range:");}
			sb.append(newch);
		}
		return sb.toString();
	}

	/** treat a unicode string as 4-bit chunks and print the human
		friendly reading. Assumption: each char of s is 4-bit */
	public static String hex4c_print(char c){
		if(c>16){
			System.err.println("ERROR in hex4_print: char: " + c + " out of range");	
			System.exit(1);
		}else if(c==16){
			return "TERMCHAR";
		}
		String s = Integer.toHexString(c);
		return s;	
	}

	/** treat each char of s as a 4-bit hex and dump in user friendly form */
	public static String hex4s_print(String s){
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<s.length(); i++){
			char c = s.charAt(i);
			String s2 = hex4c_print(c);
			sb.append(s2);
		}
		return sb.toString();
	}

	/** return ceil(log2(n)). Assume n<2^30 */
	public static int ceil_log2(int n){
		if(n<0) panic("n<0!");
		if(n>(1<<30)) panic("n>2^30");
		int ceil_pow2 = ceil_power2(n);
		int i=0;
		for(; ceil_pow2>1; i++){
			ceil_pow2 = ceil_pow2 >> 1;
		}
		return i;
	}

	/** get closest power of 2 that is greater than or equal to n
	e.g., returns 2 for n=2, returns 8 for n = 5
	*/
	public static int ceil_power2(int n){
		if(n<0) panic("n<0!");
		if(n>(1<<30)) panic("n>2^30");
		int res = Integer.highestOneBit(n);
		res = res<n? res*2: n;
		return res;
	}

	/** assumption n less than 2^30 */
	public static boolean is_power2(int n){
		int n2= ceil_power2(n);
		return n2==n;
	}
	

	/** Given relative path return the absolute file path */
	public static String toAbsolutePath(String relativePath){
		try{
			File file = new File(relativePath);
			String absPath = file.getCanonicalPath();
			return absPath;
		}catch(Exception exc){
			panic("ERROR: " +exc.toString());	
			return null;
		}
	}
	public static String[] getFiles (String srcDir, int max_depth, int max_num_files, long size_limit){
	
		srcDir = toAbsolutePath(srcDir);
		File src = new File(srcDir);
		if (src.isDirectory()){
			ArrayList<File> allFiles = getFiles_Rec(src, max_depth, max_num_files, size_limit);
			int len = allFiles.size();
			String[] files = new String[len];
			for (int i = 0; i < len; i++){
				files[i] = allFiles.get(i).toPath().toString();
			}
			return files;
		}else{
			return new String [] {srcDir};
		}
	}

	/** check if str in arr */
	private static boolean in_arr(String [] arr, String str){
		for(int i=0; i<arr.length; i++){
			if(str.indexOf(arr[i])==0){
				return true;
			}
		}
		return false;
	}

	/** given a directory, add all regular files to the output.
		size_limit: file size limit
	 */	
	private static ArrayList<File> getFiles_Rec(File dir, int max_depth, int max_num_files, long size_limit){
		String [] arr_avoid= {"/var/run", "/run", "/tmp", "/proc", "/dev"};	
		ArrayList<File> allFiles = new ArrayList<File>();
		//1. base case
		if (max_depth <= 0 || max_num_files <=0){
			//System.out.println("DEBUG USE 010: max_depth: " + max_depth + 
			//	", max_num_files: " + max_num_files);
			return allFiles;
		}
		//2. recursive case
		File[] child_files = dir.listFiles();
		for(int i=0; child_files!=null && i<child_files.length && max_num_files>0; i++){
			File child = child_files[i];
			//System.out.println("DEBUG USE 011: child is: " + child);
			if(child.isDirectory()){
				String fpath = child.getAbsolutePath();
				if(in_arr(arr_avoid, fpath)){
					System.err.println("INFO: skip: " + fpath);
					continue;
				}
				ArrayList<File> rec_result = getFiles_Rec(child, max_depth-1, max_num_files, size_limit);
				max_num_files -= rec_result.size();
				allFiles.addAll(rec_result);
			}else{//regulra file
				if(child.canExecute() && child.length()<size_limit){ 
					allFiles.add(child);
					max_num_files--;
				}
			}
		}
		return allFiles;
	}

	/** Recursive helper for getFiles.
	Utilizes ArrayList and File[] for linear recursive search
	*/
	private static ArrayList<File> getFilesRec (File[] files, int max_depth, int max_num_files){
		ArrayList<File> allFiles = new ArrayList<File>();
		if (max_depth <= 0 || max_num_files <=0 || files.length == 0){
			return allFiles;
		}
		File[] next_files = Arrays.copyOfRange(files, 1, files.length);
		if (files[0].isDirectory()){
			File[] new_files = files[0].listFiles();
			allFiles.addAll(getFilesRec(next_files, max_depth-1, max_num_files-1));
			allFiles.addAll(getFilesRec(new_files, max_depth-1, max_num_files-allFiles.size()));
		}
		else{
			allFiles.add(files[0]);
			allFiles.addAll(getFilesRec(next_files, max_depth, max_num_files-1));
		}
		return allFiles;
	}

	/** extract 7z password protected file */
	public void extract7zWithPassword(File zipFile, String password, String dest) 
		throws IOException {
		SevenZFile sevenZFile = new SevenZFile(zipFile, password.toCharArray());
		SevenZArchiveEntry entry = sevenZFile.getNextEntry();
		System.out.println(entry.getName());
		FileOutputStream output = new FileOutputStream(dest + entry.getName());
		int entrySize = (int)entry.getSize();
		byte[] content = new byte[entrySize];
		sevenZFile.read(content, 0, content.length);
		output.write(content);
		output.close();
		sevenZFile.close();
	}

	/**  remove directory completely.  */
	public static void del_dir_worker(File todel){
		if(!todel.exists()) {return;}
		File[] allContents = todel.listFiles();
    	if (allContents != null) {
        	for (File file : allContents) {
            	del_dir_worker(file);
        	}
		}
		try{
			todel.delete();
		}catch(Exception exc){
			System.out.println("DEL error: " + exc.toString());
		}
    }

	/** remove a directory */
	public static void del_dir(String dirpath){
		validate_path(dirpath);
		del_dir_worker(new File(dirpath));
	}

	/** security check: no space bars, and must contain DATA */
	public static void validate_path(String dirpath){
		if(dirpath.indexOf(" ")>=0 || (dirpath.indexOf("DATA")<0 &&  dirpath.indexOf("data")<0)){
			Tools.panic("newdir does not allow dirpath: " + dirpath);
		}
	}

	/** if the dir exists, remove all; and then create */
	public static void new_dir(String dirpath){
		del_dir_worker(new File(dirpath));
		new File(dirpath).mkdirs();
	}

		
}
