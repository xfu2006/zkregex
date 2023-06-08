/** Efficient Zero Knowledge Project
	Main Controller File
	Author: Dr. CorrAuthor, Author1
	Created: 04/09/2022
*/ 
package cs.Employer.zkregex;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.lang.Runtime;
import java.util.Arrays;
import java.util.Map;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.math.BigInteger;
import java.util.Random;
import java.util.HashMap;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.concurrent.*;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

import org.apache.spark.api.java.JavaPairRDD;
import algebra.fields.AbstractFieldElementExpanded;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.SparkConf;
import org.apache.spark.storage.StorageLevel;
import configuration.Configuration;
import scala.Tuple2;

/**
 * Utility Class. Provide some Utility functions.
 */
public class Tools{
	/** panic and exit */
	public static void panic(String msg){
		//System.err.println("PANIC: " + msg);
		//System.exit(1);
		throw new RuntimeException("FATAL: " + msg);
	}

	public static void warn(String msg){
		System.err.println("WARNING: " + msg);
	}

	public static void myassert(boolean bval, String msg){
		if(!bval){
			panic(msg);
		}
	}

	/** run the given commands and return both string output and stderr
		in one string. WARNING: don't run program that generates a LOT OF
		output
	*/
	public static String run(String [] cmds){
		return run_worker(cmds, Integer.MAX_VALUE);
	}

	// by default: do not set rayon_single_thread
	public static void run_worker2(String [] inp_cmds, int timeout, String dumpfile, boolean bmpi){
		run_worker3(inp_cmds, timeout, dumpfile, bmpi, false);
	}

	public static void run_worker3(String [] inp_cmds, int timeout, String dumpfile, boolean bmpi, boolean b_rayon_single_thread){
	  try{
		//1. set up
		for(int i=0; i<inp_cmds.length; i++){
			if(inp_cmds[i].indexOf("mpi")>=0) bmpi=true;
		}
		String [] cmds = !bmpi? inp_cmds: new String [inp_cmds.length+2];
		if(bmpi){
			cmds[0] = inp_cmds[0];
			cmds[1] = "--timeout";
			cmds[2] = String.valueOf(timeout);
			for(int i=1; i<inp_cmds.length; i++){cmds[i+2] = inp_cmds[i];}
		}
	
		String sall = "";
		for(int i=0; i<cmds.length; i++) sall += cmds[i] + " ";
		System.out.println("RUN with timeout: " + timeout);
		System.out.println(sall + "\n");

		List args = Arrays.asList(cmds);
		ProcessBuilder pb = new ProcessBuilder(args);
		pb.redirectErrorStream(true);
		pb.redirectOutput(ProcessBuilder.Redirect.appendTo(new File(dumpfile)));
		if(b_rayon_single_thread){
			Map<String, String> env = pb.environment();
        	env.put("RAYON_NUM_THREADS", "1");
		}
		Process proc = pb.start();
		if(timeout!=Integer.MAX_VALUE) {timeout+=5;}
		if(!proc.waitFor(timeout, TimeUnit.SECONDS)){
			System.out.println("WARNING: TIME OUT ACTIONS. kill mpirun ...");
			run(new String [] {"killall", "acc"});
			run(new String [] {"killall", "mpirun"});
			Thread.sleep(5*1000);
			proc.destroy();
		}
	  }catch(Exception exc){
		exc.printStackTrace();
		Tools.panic("ERROR: " + exc.toString());
	  }
	}


	public static String run_worker(String [] inp_cmds, int timeout){
	  try{
		//1. set up
		boolean bmpi = false;
		for(int i=0; i<inp_cmds.length; i++){
			if(inp_cmds[i].indexOf("mpi")>=0) bmpi=true;
		}
		String [] cmds = !bmpi? inp_cmds: new String [inp_cmds.length+2];
		if(bmpi){
			cmds[0] = inp_cmds[0];
			cmds[1] = "--timeout";
			cmds[2] = String.valueOf(timeout);
			for(int i=1; i<inp_cmds.length; i++){cmds[i+2] = inp_cmds[i];}
		}
	
		String sall = "";
		for(int i=0; i<cmds.length; i++) sall += cmds[i] + " ";
		System.out.println("RUN with timeout: " + timeout);
		System.out.println(sall + "\n");

		Runtime rt = Runtime.getRuntime();
		Process proc = rt.exec(cmds);
		BufferedReader stdin= new BufferedReader(new 
			InputStreamReader(proc.getInputStream()));
		BufferedReader stderr= new BufferedReader(new 
     		InputStreamReader(proc.getErrorStream()));
	
		if(timeout!=Integer.MAX_VALUE) {timeout+=5;}
		if(!proc.waitFor(timeout, TimeUnit.SECONDS)){
			System.out.println("WARNING: TIME OUT ACTIONS. kill mpirun ...");
			run(new String [] {"killall", "acc"});
			run(new String [] {"killall", "mpirun"});
			Thread.sleep(5*1000);
			proc.destroy();
			return "Task Timed Out: " + sall;
		}
		StringBuilder sb = new StringBuilder();
		String s = null;
		while ((s = stdin.readLine()) != null) {
			sb.append(s + "\n");
		}
		while ((s = stderr.readLine()) != null) {
    		sb.append(s);
		}
		return sb.toString();
	  }catch(Exception exc){
		Tools.panic("ERROR: " + exc.toString());
		return null;
	  }
	}

	/** run the sequence of command in background */
	public static void run_in_background(String [] cmds, String dumpFile){
		System.out.println("RUN IN BACKGROUND: Dump Info -> " + dumpFile);
		for (String cmd : cmds){
			System.out.print(cmd + " ");
		}
		System.out.println();
		
		BackgroundThread t = new BackgroundThread(cmds, dumpFile);	
		t.run();
	}

	/* Given relative path return the absolute path */
	public static String getAbsolutePath(String relPath){
		try {
            File f = new File(relPath);
            String absPath= f.getAbsolutePath();
			return absPath;
        }catch (Exception e) {
			panic("ERROR: " + e.toString());
			return null;
		}
	}

	/** convert an arraylist of FieldT to Pairs, but started from
		the given base. This is a simple adaptation of dizk's
		common/Utils.java:cvonverToPairs 
		* NOTE: this can only be called on input with size <2^31
	*/
    public static <T> ArrayList<Tuple2<Long, T>> convertToPairsShifted(final 
		List<T> input, int base) {
        ArrayList<Tuple2<Long, T>> result = new ArrayList<>(input.size());
        for (int i = 0; i < input.size(); i++) {
            result.add(new Tuple2<>((long) i+base, 
				input.get(i)));
        }
        return result;
    }
	protected static Configuration cur_config = null;
	
	/** get the global config */
	public static Configuration getCurrentConfig(){
		return cur_config;
	}
	/** build a local config */
	public static Configuration buildLocalConfig1(){
		SparkConf conf =  new SparkConf()
                   .setMaster("local")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("local", "local1");
		//1 exec, 1 core, 1 mem, 1 partition
        Configuration config = new Configuration(1, 1, 1, 1, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}
	/** build a local config */
	public static Configuration buildLocalConfig2(){
		SparkConf conf =  new SparkConf()
                   .setMaster("local")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("local[2]", "local2");
		//2 exec, 2 core, 1 mem, 2 partition
        Configuration config = new Configuration(2, 2, 1, 2, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}

	/** build a local config */
	public static Configuration buildLocalConfig4(){
		SparkConf conf =  new SparkConf()
                   .setMaster("local[16]")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("local[16]", "local4");
		//2 exec, 2 core, 2 mem, 4 partition
        Configuration config = new Configuration(4, 2, 4, 4, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}

	public static Configuration buildLocalConfig8(){
		SparkConf conf =  new SparkConf()
                   .setMaster("local[8]")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("local[8]", "local8");
		//16 exec, 8 core, 8 mem, 8 partition
        Configuration config = new Configuration(16, 8, 8, 8, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}
	public static Configuration buildLocalConfig16(){
		SparkConf conf =  new SparkConf()
                   .setMaster("local[16]")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("local[16]", "local16");
		//32 exec, 16 core, 16 mem, 32partition
        Configuration config = new Configuration(32, 16, 16, 32, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}
	/** build a local config */
	public static Configuration buildStandAloneConfig1(){
/*
		SparkConf conf =  new SparkConf()
                   .setMaster("spark://192.168.1.8:7077")
                   .setAppName("zkregex");
		JavaSparkContext sc = new JavaSparkContext("spark://192.168.1.8:7077", "standalone1");
*/
		SparkConf conf = new SparkConf().setAppName("zkreg");
        JavaSparkContext sc = new JavaSparkContext(conf);
		//2 exec, 2 core, 1 mem, 2 partition
        Configuration config = new Configuration(1, 8, 4, 8, 
			sc, StorageLevel.MEMORY_ONLY());
		cur_config = config;
		return config;
	}


	/** stop the SparkContenst contained in the config */
	public static void stopSC(Configuration config){
		config.getSC().stop();
	}

	/** generate a random BigInteger array */
	public static BigInteger [] randArrBi(int bits, int size){
		BigInteger [] arr = new BigInteger [size];
		Random rand = new Random();
		for(int i=0; i<size; i++){
			arr[i] = new BigInteger(bits, rand);
		}
		return arr;
	}

	/** generate a random long array */
	public static long [] randArrLong(int size){
		long [] arr = new long [size];
		Random rand = new Random();
		for(int i=0; i<size; i++){
			arr[i] = rand.nextLong();
		}
		return arr;
	}

	/** generate a random int array */
	public static int [] randArrInt(int size){
		int [] arr = new int [size];
		Random rand = new Random();
		for(int i=0; i<size; i++){
			arr[i] = rand.nextInt();
		}
		return arr;
	}

	/** generate a random folder name */
	public static String randStr(String prefix){
		Random rand = new Random();
		String ret = prefix+"_" + rand.nextInt(9999999);
		return ret;
	}

	/** log level ERROR */
	public static final int ERR = 0;
	/** log level WARNING */
	public static final int WARN = 1;
	/** log level log level 1*/
	public static final int LOG1 = 2;
	/** log level log level 2*/
	public static final int LOG2 = 3;
	/** log level log level 3*/
	public static final int LOG3 = 4;
	/** GLOBAL log level */
	public static int CUR_LOG_LEVEL = 0;

	/** set the current log level to be one of ERR, WARN, LOG1, LOG2, LOG3 */	
	public static void set_log_level(int level){
		CUR_LOG_LEVEL = level;
	} 

	/** print the message only when the current log level <= level */
	public static void log(int level, String msg){
		String [] slevel = {"ERR", "WARN", "LOG1", "LOG2", "LOG3"};
		if(CUR_LOG_LEVEL>=level){
			System.out.println(slevel[level] + ": " + msg);
		}
	}

	// display the time and clear the timer
	public static void log_perf(String name, NanoTimer timer){
		timer.end();
		log(LOG1, name + " " + timer.getDuration()/1000000 + " ms");
		timer.clear_start();
	}

	/** print the message only when the current log level <= level */
	public static void flog(int level, String msg, BufferedWriter writer){
		String [] slevel = {"ERR", "WARN", "LOG1", "LOG2", "LOG3"};
		if(CUR_LOG_LEVEL>=level){
			System.out.println(slevel[level] + ": " + msg);
			try{
				writer.write(slevel[level] + ": " + msg +"\n");
				writer.flush();
			}catch(Exception exc){
				panic(exc.toString());
			}
		}
	}

	// display the time and clear the timer
	public static void flog_perf(String name, NanoTimer timer, BufferedWriter writer){
		timer.end();
		flog(LOG1, name + " " + timer.getDuration()/1000000 + " ms", writer);
		timer.clear_start();
	}

	/** write just a line of number to file, pad v to 9 digits */
	public static void write_num_to_arr(BigInteger v, String fname){
		try{
			FileWriter fw = new FileWriter(fname);
			String line = String.format("%09d", v);
			fw.write(line+"\n");
			fw.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
	}

	/** overwrite the file beginning with the given string */
	public static void overwrite_file_begin(String fpath, String line){
	  try{
		RandomAccessFile rac = new RandomAccessFile(fpath, "rw");
		rac.writeBytes(line);
		rac.close();
	  }catch(Exception exe){
		panic(exe.toString());
	  }
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
	/** Read the array list from the file. Each number per line.
		Note: FIRST number is the total number of lines */
	public static ArrayList<BigInteger> read_arr_bi_from_file(String fname){
		BufferedReader reader;
		ArrayList<BigInteger> arr = new ArrayList();
		try{
			reader = new BufferedReader(new FileReader(fname));
			String firstline = reader.readLine();
			int num = Integer.valueOf(firstline);
			String line = reader.readLine();
			while(line!=null){
				BigInteger bi = new BigInteger(line);
				arr.add(bi);
				line = reader.readLine();
			}
			reader.close();
			if(arr.size()!=num){
				throw new RuntimeException("read_arr_bi size: " + arr.size() + "!= num: " + num);
			}
		}catch(IOException exc){
			panic(exc.toString());
		}
		return arr;
 	}

	/* return power of 2 */
	public static long pow2(int exp){
		return 1L << exp;
	}

	/* write lines to file */
	public static void write_lines_to_file(String [] arr,
		String fname){
		try{
			int size = arr.length;
			FileWriter fw = new FileWriter(fname);
			for (int i = 0; i < size; i++) {
				fw.write(arr[i]+"\n");
			}
			fw.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
 	}

	/* write lines to file */
	public static void write_lines_to_file(ArrayList<String> arr,
		String fname){
		try{
			int size = arr.size();
			FileWriter fw = new FileWriter(fname);
			for (int i = 0; i < size; i++) {
				fw.write(arr.get(i)+"\n");
			}
			fw.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
 	}

	public static void write_bytes_to_file(byte [] bytes,
		String fname){
		try{
			File fw = new File(fname);
			FileOutputStream os = new FileOutputStream(fw);
			os.write(bytes);
			os.close();
		}catch(IOException exc){
			panic(exc.toString());
		}
 	}

	public static byte [] read_bytes_from_file(String fname){
	  try{
		File f = new File(fname);
		byte [] fc= Files.readAllBytes(f.toPath());
		return fc;
	  }catch(Exception exc){
		Tools.panic(exc.toString());
	  }
	  return null;
	}

	public static byte [] to_bytes(BigInteger [] arr){
	 try{
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		ObjectOutputStream outputStream = new ObjectOutputStream(bs);
		outputStream.writeObject(arr);
		byte[] arrb = bs.toByteArray();
		return arrb;
	  }catch(Exception exc){
		panic(exc.toString());
	  }
	  return null;
	}

	public static BigInteger [] from_bytes(byte [] arr){
	 try{
		ObjectInputStream in = new ObjectInputStream(
			new ByteArrayInputStream(arr));
		BigInteger [] res1= (BigInteger [])in.readObject();
		in.close();
		return res1;
	  }catch(Exception exc){
		panic(exc.toString());
	  }
	  return null;
	}

	/** delete a file */
	public static void del_file(String fpath){
		File obj = new File(fpath);
		obj.delete();
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
		todel.delete();
    }

	/** security check: no space bars, and must contain DATA */
	public static void validate_path(String dirpath){
		if(dirpath.indexOf(" ")>=0 || dirpath.indexOf("DATA")<0){
			Tools.panic("newdir does not allow dirpath: " + dirpath);
		}
	}

	/** get the parent dir */
	public static String get_parent_dir(String path){
		return Paths.get(path).getParent().toString();
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

	/** dump a vector of numbers */
	public static void dump_vec(String prefix, ArrayList<BigInteger> arr){
		System.out.println("=========== " + prefix + " ============");
		for(int i=0; i<arr.size(); i++){
			System.out.println(i + ": " + arr.get(i));
		}
	}


	/* Read a configuration file. All lines excluding comment line
	has the syntax of key: value.
	Ignore all lines started with #
	*/
	public static HashMap<String,String> readConfigFile(String fpath){
		HashMap<String,String> map = new HashMap<>();	
		BufferedReader reader;
		try{
			reader = new BufferedReader(new FileReader(fpath));
			String line = reader.readLine();
			while(line!=null){
				if(line.charAt(0)!='#'){
					String [] arr = line.split(":");
					if(arr.length!=2){Tools.panic("ERROR on reading config: " + line);}
					map.put(arr[0].trim(), arr[1].trim());	
				}
				line = reader.readLine();
			}
		} catch(Exception exc){
				Tools.panic(exc.toString());
		}
		return map;
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
				throw new RuntimeException("ERROR read_arr_from_file: " + fpath +". total_len%n !=0. Total_len: " + 
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
				if(bi.signum()<0){
					Tools.panic("Get a negative field element!");
				}
				arr.add(bi);
			}
			return arr; 
		}catch(Exception exc){
			Tools.panic(exc.toString());
			return null;
		}
	}

	/** read all lines of a file */
	public static String [] readLines(String fpath){
		ArrayList<String> arr = new ArrayList<>();
		BufferedReader reader;
		try{
			reader = new BufferedReader(new FileReader(fpath));
			String line = reader.readLine();
			while(line!=null){
				arr.add(line);
				line = reader.readLine();
			}
		} catch(Exception exc){
				Tools.panic(exc.toString());
		}
		return arr.toArray(new String [] {});
	}


	/** convert String to integer */
	public static int str2i(String s){
		return Integer.parseInt(s);
	}

	/** convert a number to 9 digit string */
	public static String num2str9(int num){
		return String.format("%09d", num);
	}

	/** read the contents as a string and chop off the last char */
	public static String read_bin_file(String fname){
	  try{
		File f = new File(fname);
		byte [] fc= Files.readAllBytes(f.toPath());
		byte [] chopped = new byte [fc.length-1];
		for(int i=0; i<chopped.length; i++) {chopped[i] = fc[i];}
		String sc = new String(chopped);
		return sc;	
	  }catch(Exception exc){
		Tools.panic(exc.toString());
	  }
	  return null;
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

	/** asuumption TWO arrays are the same length,
		only 2 rows */
	public static void dump_2darr(String name, BigInteger [][] arr2d){
		System.out.println("===== 2D Array Dump: " + name + "======");
		for(int i=0; i<arr2d.length; i++){
			System.out.println("----- ROW: " + i + "------");
			for(int j=0; j<arr2d[i].length; j++){
				System.out.println("    " + j + ": " + arr2d[i][j]);
			}
		}
	}

	public static void dump_arr(String name, BigInteger [] arr){
		System.out.println("===== 1D Array Dump: " + name + "======");
		for(int j=0; j<arr.length; j++){
			System.out.println("    " + j + ": " + arr[j]);
		}
	}
}


