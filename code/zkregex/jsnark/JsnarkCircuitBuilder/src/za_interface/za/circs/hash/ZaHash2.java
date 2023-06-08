/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/28/2021
* ***************************************************/

/** **************************************************
This is a base class for all two operands hashers.
A 2-input hasher
2 prime field elements (assumption: curve
group order is lower than 256 bits), convert each prime element
into a 256-bit number (32 bytes each), it
generates ONE output line of Prime Field Element (256-bit).
Derived classes: SHA2 (256), PedersenHash, PoseidonHash

This is an abstract class but it already provides
getNumInputs, getNumWitness, getNumOutput(), genRandomInputs().
It provides a logical operation: hash2().
The child classes needs to implement two functions:
logical_eval(), and build_circuit_worker
* ***************************************************/
package za_interface.za.circs.hash;

import circuit.structure.Wire;
import java.math.BigInteger;
import za_interface.za.circs.hash.sha.*;
import za_interface.za.circs.hash.pedersen.*;
import za_interface.za.circs.hash.poseidon.*;
import circuit.operations.Gadget;
import za_interface.za.ZaCirc;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import java.io.Serializable;

/**
  Base class for all 2-inputs hashers such as SHA2-256, 
Poseidon, and PedersenHash.
*/
public abstract class ZaHash2 extends ZaCirc implements Serializable{

	// ** Operations **
	public ZaHash2(ZaConfig config_in, String name, ZaGenerator zg){
		super(config_in, name, zg);
	}
	public ZaHash2(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "ZaHash2", zg);
	}

	//for serialize - don't call it.
	public ZaHash2(){
	}

	/** Given the option in config, create the corresponding hash */
	public static ZaHash2 new_hash(ZaConfig config, ZaGenerator zg){
		if(config.hash_alg == ZaConfig.EnumHashAlg.Sha){
			return new ZaSha2(config, zg);
		}else if(config.hash_alg == ZaConfig.EnumHashAlg.Pedersen){
			return new ZaPedersen(config, zg);
		}else if(config.hash_alg == ZaConfig.EnumHashAlg.Poseidon){
			return new ZaPoseidon(config, zg);
		}else{
			throw new UnsupportedOperationException("new_hash: Hash option not supported yet: " + config.hash_alg);
		}
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** two prime field elements regarded as private witness */
	public int getNumWitnessInputs(){
		return 2;
	}

	/** return one 256-bit prime field element, value always
	less than prime field order */
	public int getNumOutputs(){ 
		return 1;
	}

	/** hash2 - given two prime field elements, hash it to
	 to one prime field element */
	public BigInteger hash2(BigInteger a, BigInteger b){
		BigInteger modulus = this.config.getFieldOrder();
		a = a.mod(modulus);
		b = b.mod(modulus);
		BigInteger [] arrPubInput = new BigInteger [] {};
		BigInteger [] arrWitness = new BigInteger [] {a, b};
		//polymorphic call
		BigInteger [] res = this.logical_eval(arrPubInput, arrWitness);
		return res[0];	
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	@Override
	public BigInteger[][] genRandomInput(int n){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a, b;
		BigInteger bn = BigInteger.valueOf(n);
		if(n==0){//simple case
			a = Utils.stobi("0102030405060708091011121314151617181920212223242526272829303132").mod(modulus); //256 bits
			b = Utils.stobi("0aa2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2").mod(modulus); //256 bits
		}else{
			a = modulus.subtract(Utils.itobi(1001)).multiply(bn).mod(modulus);
			b = Utils.itobi(n).add(Utils.itobi(1732)).mod(modulus);
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {b, a}
		};
		return ret;
	}

	/** check if x is a valid element that could be hashed */
	public abstract boolean isValidElement(BigInteger x);

	/** if x is out of bound, convert it to a valid input */
	public abstract BigInteger forceValidElement_logical(BigInteger x);

	/** if x is out of bound, convert it to a valid input */
	public abstract Wire forceValidElement(Wire x);

	//TO BE OVERRIDEN by child class
	//public BigInteger [] logical_eval(BigInteger [] arrPubInput, BigInteger [] arrWitness);

	//TO BE OVERRIDEN by child class
	//public Wire [] build_circuit_worker(Wire [] arrPubInput, Wire [] arrWitness);
		
}
