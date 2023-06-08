/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/18/2021
* ***************************************************/

package za_interface.za;
import java.math.BigInteger;
import java.util.Random;
import java.util.ArrayList;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import circuit.config.Config;
import za_interface.za.ZaConfig;
import circuit.structure.Wire;
import util.*;
import java.net.*;
import java.io.*;
import java.lang.ProcessBuilder;

/** **************************************************
Utility class for debugging and logging
* ****************************************************/
public class Utils{
	//** CONSTANTS **
	public final static int ERR = 0;
	public final static int WARN = 1;
	public final static int LOG1 = 2;
	public final static int LOG2 = 3;
	public final static int LOG3 = 4;
	public static int log_level = ERR;

	//** Operations **

	/** set the current log level*/
	public static void setLogLevel(int level){
		log_level = level;
	}

	/** generate the fail message */
	public static void fail(String msg){
		System.err.println("Failure: " + msg);
		System.exit(101);
	}

	/** generate the warning message */
	public static void warn(String msg){
		System.err.println("WARN: " + msg);
	}

	/** convert int to BigInt */
	public static BigInteger itobi(int n){
		return BigInteger.valueOf(n);
	}

	/** convert into to BigInt array */	
	public static BigInteger [] arr_itobi(int [] arr){
		int n = arr.length;
		BigInteger [] res = new BigInteger [n];
		for(int i=0; i<n; i++){
			res[i] = itobi(arr[i]);
		}
		return res;
	}

	/** treat s as hex */
	public static BigInteger stobi(String s){
		return new BigInteger(s, 16); 
	}

	/** generate random big integer of given bits*/
	public static BigInteger randbi(int numbits){
		Random rand = new Random();
		BigInteger res = new BigInteger(numbits, rand);
		return res;
	}
	/** always generates a 'fixed' random number given seed
		and the sequence id
	*/
	public static BigInteger randbi(int numbits, int seed, int id){
		Random rand = new Random(seed);
		BigInteger res = new BigInteger(numbits, rand);
		for(int i=0; i<id-1; i++){
			res = new BigInteger(numbits, rand); 
		}
		return res;
	}

	/** genreate random bit integer of given bits */
	public static BigInteger randbi(int numbits, Random rand){
		BigInteger res = new BigInteger(numbits, rand);
		return res;
	}

	/** log the error message */
	public static void log(int level, String msg){
		if(level<=log_level){
		//	System.err.println(msg);
			System.out.println(msg);
		}
	}

	/** generate the hex string */ 
	public static String b2hex(byte val){
		return String.format("0x%02X", val);
	}

	/** generate a random prime field element (256 bit upper limit */
	public static BigInteger randpf(ZaConfig config){
		BigInteger a = randbi(256);
		BigInteger modulus = config.getFieldOrder();
		return a.mod(modulus);
	}

	// convert ArrayList to BigInteger []
	public static BigInteger [] toArray(ArrayList<BigInteger> list){
		BigInteger [] arr = new BigInteger[list.size()];
		for(int i=0; i<arr.length; i++){
			arr[i] = list.get(i);
		}
		return arr;
	}

	public static void dumpArr(String title, ArrayList<BigInteger> list){
		System.out.println("====== " + title + " ====");
		for(int i=0; i<list.size(); i++){
			System.out.println(i + ": " + list.get(i));
		}
	}

	public static void dumpArr(String title, BigInteger [] list){
		System.out.println("====== " + title + " ====");
		for(int i=0; i<list.length; i++){
			System.out.println(i + ": " + list[i]);
		}
	}

	public static void dumpWireArr(String title, Wire [] list){
		System.out.println("====== " + title + " ====");
		for(int i=0; i<list.length; i++){
			System.out.println(i + ": " + list[i]);
		}
	}



	/** write sContent to file */
	public static void writeFile(String fpath, String sContent){
		try{
			FileWriter f1 = new FileWriter(fpath);
			f1.write(sContent);
			f1.close();
		}catch(Exception e){
			System.err.println("writeFile exception: " + e);
			e.printStackTrace();
		}
	}

	/** Send the given request to the ip/port and read all
		return and return as a string. 
		Return the string with "OUTPUT:"
	*/
	public static String sendRequest(String request, String ip, int port){
		try{
			Socket socket = new Socket(ip, port);
			InputStream si = socket.getInputStream();
			BufferedReader reader = new BufferedReader(
				new InputStreamReader(si));
			StringBuilder sb = new StringBuilder();
			OutputStream os = socket.getOutputStream();
			PrintWriter pw = new PrintWriter(os, true);
			pw.println(request);
			String line = null;
			while((line=reader.readLine())!=null){
				if(line.indexOf("OUTPUT:")>=0){
					return line;
				}
			}
			return null;
		}catch(Exception ex){
			ex.printStackTrace();
			throw new RuntimeException(ex.getMessage());
		}
	}

	public static String [] runSage_worker_NEW(String sSage){
		//1. write the sage file
		String fpath = "run_dir/test001.sage";
		writeFile(fpath, sSage);	

		//2. invoke server
		String line = sendRequest("HI", "localhost", 9999);
		if(line.indexOf("OUTPUT")>=0){
			String [] arr = line.split(" ");
			String [] arr2 = new String [arr.length-1];
			for(int k=0; k<arr.length-1; k++){
				arr2[k] = arr[k+1];
			}
			return arr2;
		}
		return null;
	}

	public static String [] runSage_worker_poseidon(String sSage){
		//1. write the sage file
		String fpath = "poseidon_script/poseidonHash.sage";
		writeFile(fpath, sSage);	

		//2. invoke server
		String line = sendRequest("HI", "localhost", 9999);
		if(line.indexOf("OUTPUT")>=0){
			String [] arr = line.split(" ");
			String [] arr2 = new String [arr.length-1];
			for(int k=0; k<arr.length-1; k++){
				arr2[k] = arr[k+1];
			}
			return arr2;
		}
		return null;
	}


	public static String [] runSage_worker(String sSage){
		return runSage_worker_NEW(sSage);
	}

	/** run the given sage code and return the result. Expecting
		the sage code produces one line as OUTPUT: big_integer ...*/
	public static String [] runSage_worker_OLD(String sSage){

		//1. write the sage file
		String fpath = "run_dir/test001.sage";
		writeFile(fpath, sSage);	

		//2. run the process
		try {
			Process p;
			p = Runtime.getRuntime() .exec(new String[] {Config.PATH_TO_SAGE, fpath});
			p.waitFor();
			System.out.println(
					"\n-----------------------------------RUNNING Sage-----------------------------------------");
			String line;
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			StringBuffer buf = new StringBuffer();
			while ((line = input.readLine()) != null) {
				if(line.indexOf("OUTPUT")>=0){
					String [] arr = line.split(" ");
					String [] arr2 = new String [arr.length-1];
					for(int k=0; k<arr.length-1; k++){
						arr2[k] = arr[k+1];
					}
					return arr2;
				}
			}
			input.close();
			System.out.println(buf.toString());
			throw new Exception("can't find prefix 'OUTPUT:'");
		} catch (Exception e) {
			e.printStackTrace();
		}

		//3. collect the result
		return new String [] {};
	}

	/* expecting just one output */
	public static BigInteger runSage(String sSage){
		String [] str = runSage_worker(sSage);
		BigInteger x = new BigInteger(str[0]);
		return x;
	}

	/* expecting an array of output */
	public static BigInteger [] runSageArr(String sSage){
		String [] str = runSage_worker(sSage);
		BigInteger [] res = new BigInteger[str.length];
		for(int i=0; i<res.length; i++){
			res[i] =  new BigInteger(str[i]);
		}
		return res;
	}

	/** treat x as bits integer and rotate shiftBits to the left.
		Note: when x is not in range, its overflowimg bits will
		be CHOPPED. */ 
	public static BigInteger rotate_left_bi(BigInteger x, int bits, int shiftBits){
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);
		BigInteger chunkLow = x.shiftRight(bits - shiftBits);
    	BigInteger mask = one.shiftLeft(bits).subtract(one);
    	BigInteger res = x.shiftLeft(shiftBits).and(mask).or(chunkLow);
		return res;
	}

	/** prserve the last significant x bits */
	public static BigInteger trimBits(BigInteger x, int bits){
		BigInteger one = Utils.itobi(1);
    	BigInteger mask = one.shiftLeft(bits).subtract(one);
    	BigInteger res = x.and(mask);
		return res;
	}

	/** x-or bit wise */
	public static BigInteger xorBitwise(BigInteger x, BigInteger y, int bits){
		x = trimBits(x, bits);
		y = trimBits(y, bits); 
		return x.xor(y);
	}
	
	/** treat x as bits integer and rotate shiftBits to the right.
		Note: when x is not in range, its overflowimg bits will
		be CHOPPED. */ 
	public static BigInteger rotate_right_bi(BigInteger x, int bits, int shiftBits){
		BigInteger one = Utils.itobi(1);
		BigInteger zero = Utils.itobi(0);
		BigInteger chunkLow = trimBits(x, shiftBits);
		chunkLow = chunkLow.shiftLeft(bits-shiftBits);
    	BigInteger mask = one.shiftLeft(bits).subtract(one);
    	BigInteger res = x.shiftRight(shiftBits).and(mask).or(chunkLow);
		return res;
	}


	/** split into n bits */
	public static BigInteger [] split(BigInteger x, int bits){
		return Util.split(x, bits, 1);
	}

	/** build a huge array which is the result of split on each */
	public static BigInteger [] getBits(BigInteger [] arr, int bits){
		int n = arr.length * bits;
		BigInteger [] res = new BigInteger [n];
		for(int i=0; i<arr.length; i++){
			BigInteger [] tmp = split(arr[i], bits);
			for(int k=0; k<bits; k++){
				res[k+i*bits] = tmp[k];
			}
		}
		return res;
	}

	/** pack bits into BigInteger */
	public static BigInteger pack(BigInteger [] bits){
		BigInteger x = BigInteger.ZERO;
		for(int i=0; i<bits.length; i++){
			x = x.add(bits[i].shiftLeft(i));
		}
		return x;
	}	

	/** pack bits into BigInteger array, bits length should be multiple of
wordlength*/
	public static BigInteger [] packBitsIntoWords(BigInteger [] bits, int wordwidth){
		if(bits.length % wordwidth != 0){
		 	throw new UnsupportedOperationException("bits length not a multiple of wordwidth");
		}
		int blocks = bits.length/wordwidth;
		BigInteger [] arr = new BigInteger[blocks];
		for(int k=0; k<blocks; k++){
			BigInteger x = BigInteger.ZERO;
			for(int i=0; i<wordwidth; i++){
				x = x.add(bits[i+k*wordwidth].shiftLeft(i));
			}
			arr[k] = x;
		}
		return arr;
	}	

	/** run the new_r1csrunner given the parameters, return the 
		result */
	public static String runR1csRunner(String driver_name, 
		String config_name, String circ_name){

		//2. run the process
		try {
			Process p;
			//p = Runtime.getRuntime() .exec(new String[] {Config.PATH_TO_R1CS_RUNNER, driver_name, config_name, circ_name});
			ProcessBuilder pb = new ProcessBuilder().command(new String [] {Config.PATH_TO_R1CS_RUNNER, driver_name, config_name, circ_name}).redirectErrorStream(true);
			pb.directory(new File(Config.PATH_TO_R1CS_DIR));
			p = pb.start();
			p.waitFor();
			System.out.println(
					"\n-----------------------------------RUNNING R1cs Runner-----------------------------------------");
			String line;
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while ((line = input.readLine()) != null) {
				if(line.indexOf("OUTPUT: ")>=0){
					input.close();
					return line.substring(7);
				}
			}
			input.close();
			throw new Exception("can't find prefix 'OUTPUT:'");
		} catch (Exception e) {
			e.printStackTrace();
		}

		//3. collect the result
		return new String("");
	}


	/** serialize the object to file */
	public static void serialize_to(Serializable obj, String filename){
		try {
			FileOutputStream fout = new FileOutputStream(filename);
			ObjectOutputStream oos = new ObjectOutputStream(fout);
			oos.writeObject(obj);
			oos.close();
			fout.close();
      	}catch(Exception e) {
			e.printStackTrace();
         	throw new RuntimeException(e.getMessage());
      	}
	}

	/** read from a file */
	public static Object deserialize_from(String filename){
		try{
				FileInputStream fs= new FileInputStream(filename);
				ObjectInputStream is = new ObjectInputStream(fs);
				Object obj = is.readObject();
				is.close();
				fs.close();
				return obj;
      	}catch(Exception e) {
			e.printStackTrace();
         	throw new RuntimeException(e.getMessage());
      	}
	}

	public static boolean file_exists(String fname){
		File f = new File(fname);
		return f.exists();
	}

	public static BigInteger [] concat(BigInteger [] arr1,
		BigInteger [] arr2){
		BigInteger [] res = new BigInteger [arr1.length + arr2.length];
		for(int i=0; i<arr1.length; i++){
			res[i] = arr1[i];
		}
		for(int i=0; i<arr2.length; i++){
			res[i+arr1.length] = arr2[i];
		}
		return res;
	}

	public static Wire [] concat(Wire [] arr1, Wire [] arr2){
		Wire [] res = new Wire [arr1.length + arr2.length];
		for(int i=0; i<arr1.length; i++){
			res[i] = arr1[i];
		}
		for(int i=0; i<arr2.length; i++){
			res[i+arr1.length] = arr2[i];
		}
		return res;
	}

	/** take a slice out of arr */
	public static BigInteger [] slice(BigInteger [] arr, int idx, int size){
		BigInteger [] res = new BigInteger [size];
		for(int i=0; i<size; i++){
			res[i] = arr[i+idx];
		}	
		return res;
	}

	public static Wire [] slice(Wire [] arr, int idx, int size){
		Wire [] res = new Wire [size];
		for(int i=0; i<size; i++){
			res[i] = arr[i+idx];
		}	
		return res;
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
			fail(exc.toString());
		}
 	}
}


