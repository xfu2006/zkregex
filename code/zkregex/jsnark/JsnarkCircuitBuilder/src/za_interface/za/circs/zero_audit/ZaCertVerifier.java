/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/22/2021
* ***************************************************/

/** **************************************************
This is a verifier for a Cert.
Note: in the genRandomInput() its input is FIXED to the
cert's contents, regardless of int n. To generate a random 
cert, use the static genRandCert() function from Cert.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.range.*;
import util.Util;

/** **************************************************
This is a verifier for a Cert.
Note: in the genRandomInput() its input is FIXED to the
cert's contents, regardless of int n. To generate a random 
cert, use the static genRandCert() function from Cert.
* ***************************************************/
public class ZaCertVerifier extends ZaCirc{
	// *** data members ***
	protected Cert cert; //for setting data source

	// *** Operations ***
	public ZaCertVerifier(ZaConfig config_in, Cert cert, ZaGenerator zg){
		super(config_in, "CertVerifier", zg);
		this.cert= cert;
	}

	/** returns 0. All input in witness */
	public int getNumPublicInputs(){
		return 0;
	}

	/**
		7: pk, counter, nonce, SID, q, ts, root
	*/
	public int getNumWitnessInputs(){
		return 7;
	}

	/**
		Either 1 or 0 for yes or no
	*/	
	public int getNumOutputs(){ 
		return 1;
	}

	//check if val is 64-bit non-negative int
	protected BigInteger logical_checkInRange(BigInteger val){
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		ZaRange zr = new ZaRange(config, 64, zg);
		BigInteger res = zr.logical_eval(new BigInteger [] {}, 
			new BigInteger [] {val})[0];
		return res; 
	}

	//check if val is 64-bit non-negative int
	protected Wire checkInRange(Wire val){
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		ZaRange zr = new ZaRange(config, 64, zg);
		zr.build_circuit(new Wire [] {}, new Wire [] {val});
		Wire res = zr.getOutputWires()[0];
		return res; 
	}
	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - [0] element to prove, [1] hash, [2-n+1]
			the proof
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. check hash
		BigInteger [] a = arrWitness;
		Cert cert = new Cert(a[0], a[1], a[2], a[3], a[4], a[5], this.config);
		BigInteger root2 = a[6];
		BigInteger res = root2.equals(cert.root)? Utils.itobi(1): Utils.itobi(0);	
		//2. check all in range (counter, SID, q, ts)
		res = res.and(logical_checkInRange(a[1])); //counter
		res = res.and(logical_checkInRange(a[3])); //SID
		res = res.and(logical_checkInRange(a[4])); //q
		res = res.and(logical_checkInRange(a[5])); //ts

		return new BigInteger [] {res};
	}

	private Wire myhash(Wire w1, Wire w2){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaHash2 hash = ZaHash2.new_hash(config, zg); 
		hash.build_circuit(new Wire []{}, new Wire [] {w1, w2});
		Wire temp = hash.getOutputWires()[0];
		return temp;
	}

	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		pk, counter, nonce, SID, q, ts, root
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. check root
		Wire pk = arrWitness[0];
		Wire counter = arrWitness[1];
		Wire nonce = arrWitness[2];
		Wire SID = arrWitness[3];
		Wire q = arrWitness[4];
		Wire ts = arrWitness[5];
		Wire root = arrWitness[6];

		Wire temp = myhash(pk, counter);
		Wire serial_no = myhash(temp, nonce);
		Wire b1 = myhash(serial_no, SID);
		Wire b2 = myhash(q, ts);
		Wire root2 = myhash(b1, b2);
		
		Wire res = root.isEqualTo(root2);

		//2. check all in range (counter, SID, q, ts)
		Wire [] a = arrWitness;
		res = res.and(checkInRange(a[1])); //counter
		res = res.and(checkInRange(a[3])); //SID
		res = res.and(checkInRange(a[4])); //q
		res = res.and(checkInRange(a[5])); //ts
		return new Wire [] {res};
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		Note: regardless of n, it only generates the input based on
		the data member cert. If need a random cert, call
		the genRandCert() function of the Cert class */
	public BigInteger[][] genRandomInput(int n){
		BigInteger [] arrwit = new BigInteger [] {
			cert.pk,
			cert.counter,
			cert.nonce,
			cert.SID,
			cert.q,
			cert.ts,
			cert.root
		};
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			arrwit
		};
		return ret;
	}
	
}
