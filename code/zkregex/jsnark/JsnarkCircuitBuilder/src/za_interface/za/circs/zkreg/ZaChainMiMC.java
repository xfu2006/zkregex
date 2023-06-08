/* ***************************************************
Dr. CorrAuthor
@Copyright 2022
Created: 11/18/2022
* ***************************************************/

/** **************************************************
This is a file for testing ZaMiMC only.
* ***************************************************/
package za_interface.za.circs.zkreg;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import java.util.Arrays;
import java.util.ArrayList;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.PrimeFieldInfo;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.zero_audit.*;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.hash.poseidon.*;
import za_interface.za.circs.hash.mimc.*;
import util.Util;
import cs.Employer.ac.AC; 
import cs.Employer.zkregex.App;


public class ZaChainMiMC extends ZaCirc{
	//number of instances of MiMC
	protected int n; 

	/** Given a[] is an array of 4-bit numbers, build
		an array of 252-bit numbers (to accompodate bn254). 
		The size of the returned array is ceil(a.length/63). 
		Each a[i] is split into 4-bit wires and (verified it's indeed
		4-bit), and then every 252-bit is grouped
	*/
	protected Wire [] build_252bit(Wire [] a){
		int total_bits = a.length*4;
		if(total_bits%252!=0) {
			throw new RuntimeException("total_bits: "+total_bits + "%252!=0");
		}
		int len = total_bits%252==0? total_bits/252: total_bits/252 + 1;
		Wire [] bits = new Wire [total_bits];
		Wire [] res = new Wire [len];

		//1. split into ALL bits (verification included)
		for(int i=0; i<a.length; i++){
			Wire [] wa = a[i].getBitWires(4).asArray();
			for(int j=0; j<4; j++){
				bits[i*4 + j] = wa[j];
			}
		}

		//2. merge every 252 bits
		for(int i=0; i<len; i++){
			int start = i*252;
			int end = (i+1)*252>=total_bits? total_bits: (i+1)*252; //not inc.
			WireArray wa = new WireArray(Arrays.copyOfRange(
				bits, start, end));
			res[i] = wa.packAsBits();
		}
		return res;
	}

	protected Wire [] fake_build_252bit(Wire [] a){
		int total_bits = a.length*4;
		if(total_bits%252!=0) {
			throw new RuntimeException("total_bits: "+total_bits + "%252!=0");
		}
		int len = total_bits%252==0? total_bits/252: total_bits/252 + 1;
		Wire [] bits = new Wire [total_bits];
		Wire [] res = new Wire [len];
		for(int i=0; i<len; i++){
			res[i] = a[i];
		}
		return res;
	}


	protected BigInteger [] logical_build_252bit(BigInteger [] a){
		int total_bits = a.length*4;
		if(total_bits%252!=0) {
			throw new RuntimeException("total_bits: "+total_bits + "%252!=0");
		}
		int len = total_bits%252==0? total_bits/252: total_bits/252 + 1;
		BigInteger [] bits = new BigInteger [total_bits];
		BigInteger [] res = new BigInteger [len];

		//1. split into ALL bits (verification included)
		for(int i=0; i<a.length; i++){
			BigInteger [] wa = Util.split(a[i], 4, 1);
			for(int j=0; j<4; j++){
				bits[i*4 + j] = wa[j];
			}
		}

		//2. merge every 252 bits
		BigInteger modulus = this.config.getFieldOrder(); 
		for(int i=0; i<len; i++){
			int start = i*252;
			int end = (i+1)*252>=total_bits? total_bits: (i+1)*252; //not inc.
			res[i] = Util.group(Arrays.copyOfRange(
				bits, start, end), 1).mod(modulus);
		}
		return res;
	}

	/** assume arrAlignedInput are 4-bit wires. First pack them
		into 252-bit wires, and encrypt them using
		CBC mode (takes an encrypt_in for CBC initial vector)
		and a key. 
	*/
	public Wire [] build_encrypt(Wire [] arrAlignedInput, Wire encrypt_in, Wire key){
		//1. pack every 63 elements of arrAlignedInput as a 252-bit number
		//Wire [] arr252bits = build_252bit(arrAlignedInput);
		Wire [] arr252bits = fake_build_252bit(arrAlignedInput);
		System.out.println("DEBUG USE 100: blocks: " + arr252bits.length);
		Wire [] output = new Wire [arr252bits.length];

		//2. hash the arr252bitInt 
		ZaMiMC hash = null;
		// temporarily use encrypt_in to test size
		// should actually pass a wire guarantted to be 1.
		hash = new ZaMiMC(config, (ZaGenerator) this.generator, encrypt_in);
        Wire res = encrypt_in;
		for(int i=0; i<arr252bits.length; i++){
			//this is NOT quite effective, can be improved later
			//should do an operation between key and res for real CBC
			//but that bit-wise operation could be costly too 
        	Wire [] enc = hash.encrypt(new Wire [] {res, arr252bits[i]}, key);
        	res = enc[0].add(enc[1]);
			output[i] = res;
		}
/*

		ZaHash2 hash;
        Wire res = encrypt_in;
		for(int i=0; i<arr252bits.length; i++){
			hash = new ZaPoseidon(config, (ZaGenerator) this.generator, encrypt_in);
			hash.build_circuit(new Wire [] {}, new Wire [] {res, arr252bits[i]});
			res = hash.getOutputWires()[0];
			output[i] = res;
		}
*/
		return output;
	}

	/** logical version of build_encrypt */
	public BigInteger [] logical_build_encrypt(BigInteger [] arrAlignedInput, BigInteger encrypt_in, BigInteger key){
		//1. pack every 63 elements of arrAlignedInput as a 252-bit number
		BigInteger [] arr252bits = logical_build_252bit(arrAlignedInput);
		BigInteger [] output = new BigInteger [arr252bits.length];
		BigInteger modulus = this.config.getFieldOrder();

		//2. hash the arr252bitInt 
		ZaMiMC hash = null;
        BigInteger res = encrypt_in;
		for(int i=0; i<arr252bits.length; i++){
			hash = new ZaMiMC(config, (ZaGenerator) this.generator);
			//this is NOT quite effective, can be improved later
			//should do an operation between key and res for real CBC
			//but that bit-wise operation could be costly too 
        	BigInteger [] enc = hash.logical_encrypt(new BigInteger [] {res, arr252bits[i]}, key);
        	res = enc[0].add(enc[1]).mod(modulus);
			output[i] = res;
		}
		return output;
	}



	public ZaChainMiMC(ZaConfig config_in, ZaGenerator zg, int n){
		super(config_in, "ZaChainMiMC", zg);
		this.n = n;
	}

	public int getNumPublicInputs(){
		return 0;
	}

	/** the length of all witness inputs.  */
	public int getNumWitnessInputs(){
		int expected_len = n * 252/4;
		return expected_len;
	}

	public int getNumOutputs(){ 
		int expected_len = n * 252/4;
		return expected_len;
	}

	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		
		BigInteger [] res = logical_build_encrypt(arrWitness, arrWitness[0], arrWitness[1]);
		return res;
	}


	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire [] res = build_encrypt(arrWitness, arrWitness[0], arrWitness[1]);
		return res;
	}

	
	/** Generate the random inputs. Mainly rely on dizkDriver */
	public BigInteger[][] genRandomInput(int seed_n){
		//1. generate random AC and random input
		int total_len = this.n * 63;
		BigInteger [] arrWit = new BigInteger [total_len];
		for(int i=0; i<arrWit.length; i++){
			arrWit[i] = Utils.itobi((i+107)%255);
		}
		BigInteger [][] all = new BigInteger [][]{
			new BigInteger [] {},
			arrWit
		};
		return all;
	}
}
