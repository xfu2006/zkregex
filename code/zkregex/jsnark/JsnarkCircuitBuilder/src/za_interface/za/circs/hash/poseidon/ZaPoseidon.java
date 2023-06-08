/* ***************************************************
Dr. CorrAuthor
Author1
@Copyright 2021
Created: 07/1/2021
Finalized: 07/27/2021
Revised: add a new logical eval function
Revised: 11/19/2022. Add a w_one wire to remove rippling
add building up LinearTerms too long (check ZaMiMC)
* ***************************************************/

/** **************************************************
This is a wrapper for Poseidon's sage script.
Given a curve setting (see za_interface/za/circ/curves/Curve.java),
input_bits (e.g. ,for the curve25519 customized for libsnark, this 
is about 253 bits and for the curve25519 customized for spartan 
this is about 251 bits.

*** note if the "x" and "r" are out of range, the "x%2^input_bits"
will be applied ***
* ***************************************************/


package za_interface.za.circs.hash.poseidon;

import java.math.BigInteger;
import java.util.HashMap;
import circuit.structure.Wire;
import circuit.structure.ConstantWire;
import za_interface.za.ZaCirc;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.ZaHash2;
import za_interface.za.circs.curve.*;
import util.Util;
import examples.gadgets.math.ModConstantGadget;
import examples.gadgets.math.FieldDivisionGadget;
import java.io.Serializable;


public class ZaPoseidon extends ZaHash2 implements Serializable{
	
	// *** Data Members ***

	/**SageGenerator Object.*/
	protected SageGenerator sage;
	protected Wire w_one; //used for reducing size of LinearCombs caused
							//by ADD

	// ** Operations **
	public ZaPoseidon(ZaConfig config_in, ZaGenerator zg){
		this(config_in, zg, null);
	}
	public ZaPoseidon(ZaConfig config_in, ZaGenerator zg, Wire w_one){
		super(config_in, "Poseidon", zg);
		if(w_one!=null && w_one instanceof ConstantWire){
			throw new RuntimeException("ZaPoseidonERR: need to pass w_one as a regular wire but NOT ConstantWire");
		}
		this.w_one = w_one;
		if(config_in.hash_alg != ZaConfig.EnumHashAlg.Poseidon){
			throw new UnsupportedOperationException("Config.hash option does not match Poseidon: " + config_in.hash_alg);
		}

		// contains Constants object with specified ZaConfig 
		// and member functions to run sage version of Poseidon Hash
		sage = new SageGenerator(config_in);
	}

	/** logical operation. Generate Poseidon Hash using sage 
	return hashed elements */
	public BigInteger [] sage_logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		// get and check input
		BigInteger x = arrWitness[0];
		BigInteger y = arrWitness[1];
		//x = forceValidElement_logical(x);
		//y = forceValidElement_logical(y);
		
		// compute hash
		return sage.generateHash(x,y);
	}
	/** logcical eval the circuit. Needs to supply the input wires */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){ 
		BigInteger modulus = this.config.getFieldOrder();
		Constants constants = sage.constants;
		//1. format variables for permutation
		BigInteger [] input = {arrWitness[0], arrWitness[1]};
		int round_constants_counter = 0;
		int R_f = constants.R_F/2;
		int ALPHA = 5;

		BigInteger [] round_constants = buildArr_logical(constants.round_constants);
		BigInteger [][] MDS_Matrix = buildMatrix_logical(constants.MDS_Matrix);

		//2. run permutation
		// First full rounds
		for (int r = 0; r < R_f; r++){
			/* Round constants, nonlinear layer, 
				matrix multiplication*/
			for (int i = 0; i < 2; i++){ // t = input.length = 2
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
				input[i] = pow(input[i],(ALPHA)); 
			}
			input = matMul(input,MDS_Matrix);
		}

		// Middle partial rounds
		for (int r = 0; r < constants.R_P; r++){
			for (int i = 0; i < 2; i++){
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
			}
			input[0] = pow(input[0],(ALPHA));
			input = matMul(input,MDS_Matrix);
		}
		
		// Last full rounds
		for (int r = 0; r < R_f; r++){
			/* Round constants, nonlinear layer, 
				matrix multiplication*/
			for (int i = 0; i < 2; i++){ // t = input.length = 2
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
				input[i] = pow(input[i],(ALPHA)); 
			}
			input = matMul(input,MDS_Matrix);
		}		

		return new BigInteger [] {input[0]};
	}



	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){ 

		Constants constants = sage.constants;
		//1. format variables for permutation
		Wire [] input = {arrWitness[0], arrWitness[1]};
		int round_constants_counter = 0;
		int R_f = constants.R_F/2;
		int ALPHA = 5;

		Wire [] round_constants = buildArr(constants.round_constants);
		Wire [][] MDS_Matrix = buildMatrix(constants.MDS_Matrix);

		//2. run permutation
		
		// First full rounds
		for (int r = 0; r < R_f; r++){
			/* Round constants, nonlinear layer, 
				matrix multiplication*/
			for (int i = 0; i < 2; i++){ // t = input.length = 2
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
				input[i] = pow(input[i],(ALPHA)); 
			}
			input = matMul(input,MDS_Matrix);
		}

		// Middle partial rounds
		for (int r = 0; r < constants.R_P; r++){
			for (int i = 0; i < 2; i++){
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
			}
			input[0] = pow(input[0],(ALPHA));
			input = matMul(input,MDS_Matrix);
		}
		
		// Last full rounds
		for (int r = 0; r < R_f; r++){
			/* Round constants, nonlinear layer, 
				matrix multiplication*/
			for (int i = 0; i < 2; i++){ // t = input.length = 2
				input[i] = input[i].add(round_constants
					[round_constants_counter++]);
				input[i] = pow(input[i],(ALPHA)); 
			}
			input = matMul(input,MDS_Matrix);
		}		

		return new Wire [] {input[0]};
	}


	/** check if x is a valid element that could be hashed */
        public boolean isValidElement(BigInteger x){
                BigInteger order = this.config.getFieldOrder();
                return x.compareTo(order)<0 && x.compareTo(Utils.itobi(0))>=0;
        }

	 /** if x is out of bound, convert it to a valid input */
        public BigInteger forceValidElement_logical(BigInteger x){
		// Poseidon ensures points are valid
                return x;
        }


	/** if x is out of bound, convert it to a valid input */
	public Wire forceValidElement(Wire x){
		// Poseidon ensures points are valid
		return x;
	}

	/**Converts a BigInteger [] to Wire []*/
	protected Wire [] buildArr(BigInteger[] arr){
		int len = arr.length;
		Wire [] res = new Wire [len];
		for (int i = 0; i < len; i++){
			res[i] = this.generator.createConstantWire(arr[i]);
		}
		return res;
	}

	/**Converts a BigInteger [] to Wire []*/
	protected BigInteger [] buildArr_logical(BigInteger[] arr){
		BigInteger modulus = this.config.getFieldOrder();
		int len = arr.length;
		BigInteger [] res = new BigInteger [len];
		for (int i = 0; i < len; i++){
			res[i] = arr[i].mod(modulus);
		}
		return res;
	}

	

	/**Converts a BigInteger[][] to a Wire[][]*/
	protected Wire [][] buildMatrix(BigInteger[][] matrix){
		int rows = matrix.length;
		int columns = matrix[0].length;
		Wire[][] res = new Wire[rows][columns];

		for (int i = 0; i < rows; i++){
			res[i] = buildArr(matrix[i]);
		}
	
		return res;
	}	

	protected BigInteger [][] buildMatrix_logical(BigInteger[][] matrix){
		int rows = matrix.length;
		int columns = matrix[0].length;
		BigInteger[][] res = new BigInteger[rows][columns];

		for (int i = 0; i < rows; i++){
			res[i] = buildArr_logical(matrix[i]);
		}
	
		return res;
	}	


	/**Runs matrix multiplication over the given input
	* @param input,mat are the input and MDS_Matrix used in the hash
	* @return newly permutated input
	*/
	private Wire [] matMul(Wire [] input, Wire [][] mat){
		Wire [] res = new Wire[2];
		for (int i = 0; i < 2; i++){
			res[i] = this.generator.createConstantWire(0);
		}
		int count = 0;
		for (int row = 0; row < 2; row++){
			for (int i = 0; i < mat.length; i++){
				// input 0 * left point + input 1 * right point
				res[row] = res[row].add(mat[row][i].mul(input[i]));
			}
		}
		//Added 11/20/2022 -> to reduce LinearComb size by ADD
		if(w_one!=null){
			res[0] = res[0].mul(w_one);
			res[1] = res[1].mul(w_one);
		}
		//Added 11/20/2022 Above
		
		return res;
	}

	private BigInteger [] matMul(BigInteger [] input, BigInteger [][] mat){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger [] res = new BigInteger[2];
		for (int i = 0; i < 2; i++){
			res[i] = Utils.itobi(0);
		}
		int count = 0;
		for (int row = 0; row < 2; row++){
			for (int i = 0; i < mat.length; i++){
				// input 0 * left point + input 1 * right point
				res[row] = res[row].add(mat[row][i].multiply(input[i])).mod(modulus);
			}
		}
		
		return res;
	}

	/** Raises the given wire to the given exponent	*/
	private Wire pow(Wire w, int exp){
		if (exp == 5){
			Wire sq = w.mul(w);
			return sq.mul(sq.mul(w));
		}
		else if (exp == 3){
			return w.mul(w.mul(w));
		}
		else{
			Wire base = w;
			for(int i = 0; i < exp-1; i++){
				w = w.mul(base);
			}
			return w;
		}
	}

	/** Raises the given wire to the given exponent	*/
	private BigInteger pow(BigInteger w, int exp){
		BigInteger modulus = this.config.getFieldOrder();
		if (exp == 5){
			BigInteger sq = w.multiply(w).mod(modulus);
			return sq.multiply(sq.multiply(w)).mod(modulus);
		}
		else if (exp == 3){
			return w.multiply(w.multiply(w)).mod(modulus);
		}
		else{
			BigInteger base = w;
			for(int i = 0; i < exp-1; i++){
				w = w.multiply(base).mod(modulus);
			}
			return w;
		}
	}

}
















