/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/25/2021
Modified: 04/28/2021 (to inherit from ZaHash2)
Modified: 04/29/2021 (fixed the jsnark optimization bug - split/pack
   equiv conversion issue.
* ***************************************************/

/** **************************************************
This is a wrapper of jsSnark's SHA256 gadget.
It takes 2 prime field elements (assumption: curve
group order is lower than 256 bits), convert each prime element
into a 256-bit number (32 bytes each) and feed it to
the jsSnark SHA gadget. It returns a Prime Field Element (256-bit)
* ***************************************************/
package za_interface.za.circs.hash.sha;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;
import za_interface.za.ZaCirc;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.ZaHash2;
import util.Util;
import java.io.Serializable;

/**
	SHA256 hash which takes 2 prime field elements (assume
each has at most 256 bits). Both are HIDDEN. It generates
ONE 256-bit prime field element (note: if the hash result
greater than the prime field order, the mod field_order
operation is applied).
*/
public class ZaSha2 extends ZaHash2 implements Serializable{

	// ** Operations **
	public ZaSha2(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "Sha2", zg);
		if(config_in.hash_alg != ZaConfig.EnumHashAlg.Sha){
			System.out.println("WARNING: Config.hash option does not match Sha: " + config_in.hash_alg);
		}
	}

	//don't call it  - for Serializable
	public ZaSha2(){
	}

	/** converting reverse the order of 4-byte integers */
	private byte [] barr_to_be(byte [] arr){
		int n = arr.length;
		byte [] abi = new byte [n+1];
		for(int i=0; i<n/4; i++){
			int idx = i*4;
			for(int j=0; j<4; j++){//also reverse the word sequence
				abi[(n/4-i-1)*4+j+1] = arr[idx+j]; //reversed
			}	
		}
		abi[0] = 0;
		return abi;
	}

	/** logical operation, assuming the two number less than 
	prime field order. Used for unit testing to compare with circuit
	output. It calls the reference implementation of Sha2-256
    by Meyfa. */	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. split into bytes
		BigInteger a = arrWitness[0];
		BigInteger b = arrWitness[1];
		BigInteger [] a_bytes = Util.split(a, 32, 8);	
		BigInteger [] b_bytes = Util.split(b, 32, 8);	
		byte [] input_bytes = new byte[64];
		for(int i=0; i<32; i++){ //build 64-bytes (512-bit) input
			input_bytes[i] = (byte) a_bytes[i].intValue();
			input_bytes[i+32] = (byte) b_bytes[i].intValue();
		} 

		//2. call the referemce implementation
		byte [] byte_arr = MeyfaSha256.hash(input_bytes);
		byte [] barr2 = barr_to_be(byte_arr);
	
		//3. merge the result
		BigInteger [] arrout = new BigInteger [1];
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger res = new BigInteger(barr2);
		BigInteger rem = res.mod(modulus);
		arrout[0] = rem;
		return arrout;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire dummy_zero = arrWitness[0].sub(arrWitness[0]);
		SHA256Gadget sg = new SHA256Gadget(arrWitness, 256, 64, true, false);
		Wire [] arr_outbits = sg.getOutputWires();
		Wire [] arrout = new Wire [1];
		Wire res = new WireArray(arr_outbits).packAsBits(256);
		// ******************************************************
		// !!! THIS IS to prevent jsSnark to REUSE the pack gate to replace
		// the SPLIT gate when the result is composed with a second hash
		// ******************************************************
		arrout[0] = res.add(dummy_zero); 
		return arrout;
	}

	/** check if x is a valid element that could be hashed */
	public boolean isValidElement(BigInteger x){
		BigInteger order = this.config.getFieldOrder();	
		return x.compareTo(order)<0 && x.compareTo(Utils.itobi(0))>=0;	
	}

	/** if x is out of bound, convert it to a valid input */
	public BigInteger forceValidElement_logical(BigInteger x){
		//as long as it's a valid 256-bit element, it's ok.
		//we assume it's 256-bit
		return x;
	}

	/** if x is out of bound, convert it to a valid input */
	public Wire forceValidElement(Wire x){
		return x;
	}

	
}
