/* ***************************************************
Dr. CorrAuthor
Author1
@Copyright 2021
Created: 07/01/2021
Completed: 07/19/2021
Modified: 07/21/2021 (only take one output from hash)
	- 
* ***************************************************/

/** **************************************************
This generates the sage script that will be used in ZaPoseidon.
Given a set of constants (see Constants.java), it generates the proper sage
script that creates a secure Poseidon hash
* ***************************************************/

package za_interface.za.circs.hash.poseidon;

import java.math.BigInteger;
import java.util.HashMap;
import circuit.structure.Wire;
import za_interface.za.ZaCirc;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.poseidon.Constants;
import za_interface.za.circs.hash.ZaHash2;
import za_interface.za.circs.curve.*;
import util.Util;
import examples.gadgets.math.ModConstantGadget;
import examples.gadgets.math.FieldDivisionGadget;
import java.util.*;
import java.io.*;
import java.io.Serializable;


/**
This generates a sage script that will create a Poseidon Hash.
Given a ZaConfig object, SageGenerator can find the proper constants
to be used for the Poseidon hash and translate it into a sage script 
that will create the hash
*/
public class SageGenerator implements Serializable{
	/**
	* Object containing all constants.
	* See Constants.java 
	*/
	protected Constants constants;
	
	/**Line by line*/
	protected static List<String> template;

	/** 
	* Constructor.
	* @param config ZaConfig object used to create Constants for sage script
	* @return SageGenerator with constants and filled out sage template
	*/
	public SageGenerator(ZaConfig config){
		constants = new Constants(config);
		template = Constants.readFile("template.txt");
	}
	
	/**
	* Creates and runs Poseidon Hash in sage.
	* @param x,y are elements to be hashed
	* @return BigInteger[] with hashed output
	*/
	protected BigInteger[] generateHash(BigInteger x, BigInteger y){
		// create sage script file from scriptStr+template
		BigInteger[] input = {x,y};
		String sage = allToString(input, constants);
	

		// ensure proper format
		for (String s : template){
			sage+=s+"\n";
		}

		// generate and convert ouput
		String[] output = Utils.runSage_worker(sage);

		// Poseidon returns a 1-to-1 bit ratio from input to output
		// we input 508 or 506 bits and expect 254 or 253 bits in return
		BigInteger element = new BigInteger(trimHex(output[0]),16); // good
		BigInteger[] hashed = {element}; // good
		
		return hashed;
	}
	
	// remove "0x" from hex strings
	private static String trimHex(String s){
		return s.substring(2,s.length());
	}

	/**
	* Converts a set of input values and Constants to a String with sage script syntax
	* @param input,constObj input values and constants to be converted to sage script
	* @return a String in sage syntax
	*/
	private static String allToString(BigInteger[] input, Constants constObj){
		String sage = "";
		// input = [x,y]
		// these are index values of F = GF(prime)
		sage += "input = [" + input[0].toString() + ", " + input[1].toString() + "]\n";

		// N = n*t
		sage+="N = "+Integer.toString(constObj.t*constObj.n)+"\n";

		// t
		sage+="t = "+Integer.toString(constObj.t)+"\n";
		
		// n
		sage+="n = "+Integer.toString(constObj.n)+"\n";
		
		// R_F
		sage+="R_F = "+Integer.toString(constObj.R_F)+"\n";
		
		// R_P
		sage+="R_P = "+Integer.toString(constObj.R_P)+"\n";
		
		// prime
		sage+="prime = 0x"+constObj.prime.toString(16)+"\n";
		
		// round_constants
		sage+="round_constants = "+arrToString(constObj.round_constants)+"\n";

		// MDS_Matrix
		sage+=mdsToString(constObj.MDS_Matrix)+"\n";

		return sage;
	}

	/**
	* Converts an array into sage syntax
	* @param rc is a BigInteger array of field elements
	* @return a String version of this array
	*/
	private static String arrToString(BigInteger[] arr){
		// prepare return String
		String sage = "[";

		// convert each element 
		for (BigInteger i : arr){
			sage+="'0x"+i.toString(16)+"', ";
		}

		// remove final ", " and add final bracket
		sage = sage.substring(0,sage.length()-2); 
		sage+="]";

		return sage;
	}

	/**
	* Converts a matrix (MDS_Matrix) to a sage Syntax String
	* @param mds is a BigInteger matrix that will be converted
	* @return a String of this matrix in sage syntax
	*/
	private static String mdsToString(BigInteger[][] mds){
		// prepare return String
		String sage = "MDS_matrix = [";

		int rows = mds.length;

		// separate by rows and columns
		for (int i = 0; i < rows; i++){
			// separate columns
			sage+=arrToString(mds[i])+",";	
		}
		
		// remove final "," and append closing bracket "]"
		sage = sage.substring(0,sage.length()-1); 
		sage+="]";
		return sage;
	}
}











