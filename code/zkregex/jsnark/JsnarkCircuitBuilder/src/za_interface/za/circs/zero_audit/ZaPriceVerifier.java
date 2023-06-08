/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/26/2021
* ***************************************************/

/** **************************************************
This is a verifier for a valid price information.
Input: member_to_verify, root, proof
It is essentially a wrapper of ZaMerkleTreeVerifier.
It has a reference to PriceServer to 
determine the number of input lines.
*** here we use "ts" and "ts" interchangeably
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
import za_interface.za.circs.accumulator.merkle.*;
import util.Util;

/** **************************************************
This is a verifier for a valid price information.
Input: member_to_verify, root, proof
It is essentially a wrapper of ZaMerkleTreeVerifier.
It has a reference to PriceServer to 
determine the number of input lines.
* ***************************************************/
public class ZaPriceVerifier extends ZaCirc{
	// *** data members ***
	protected PriceServer ps; 

	// *** Operations ***
	/** NOTE: setPriceServer has to be called later */
	public ZaPriceVerifier(ZaConfig config_in, PriceServer ps, ZaGenerator zg){
		super(config_in, "PriceVerifier", zg);
		this.ps= ps;
	}


	/** returns 0. All input in witness */
	public int getNumPublicInputs(){
		return 0;
	}

	/**
		5+n: ts, sid, price, pricetre_root (this should be
		ADDITIONALLY verified externally by PriceServer given ts),
		proof [n+1] where n is the log_capacity.
	*/
	public int getNumWitnessInputs(){
		int n = this.ps.log2_stocks; //log capacity
		return 5+n;
	}

	/**
		Either 1 or 0 for yes or no
	*/	
	public int getNumOutputs(){ 
		return 1;
	}

	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - 
		5+n: ts, sid, price, pricetre_root (this should be
		ADDITIONALLY verified externally by PriceServer given ts),
		proof [n+1] where n is the log_capacity.
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		if(this.ps==null){
			throw new RuntimeException("PriceServer not set!");
		}
		//1. set up input
		int n = this.ps.log2_stocks; //log capacity
		BigInteger [] a = arrWitness;
		BigInteger ts = a[0];
		BigInteger sid= a[1];
		BigInteger price = a[2];
		BigInteger ts_root= a[3];
		BigInteger [] proof = new BigInteger [n+1];
		for(int i=0; i<proof.length; i++) proof[i] = a[4+i];

		//2. generate the price record
		ZaHash2 hash = ZaHash2.new_hash(config, (ZaGenerator) this.generator); 
		BigInteger rec = hash.hash2(sid, price);
		BigInteger root2 = ps.getRoot(ts.intValue());
		if(!root2.equals(ts_root)){
			throw new RuntimeException("ts root supplied not correct");
		};

		//3. call the price tree to verify the record
		MerkleAccumulator acc = ps.accs[ts.intValue()];
		ZaMerkleAccVerifier za = new ZaMerkleAccVerifier(config, acc, (ZaGenerator) this.generator);
		BigInteger res = za.verify(rec, new BigInteger [] {root2}, proof)?
			Utils.itobi(1): Utils.itobi(0);
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
		arrWitness - 
		5+n: ts, sid, price, pricetre_root (this should be
		ADDITIONALLY verified externally by PriceServer given ts),
		proof [n+1] where n is the log_capacity.
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		if(this.ps==null){
			throw new RuntimeException("PriceServer not set!");
		}
		//1. set up input
		int n = this.ps.log2_stocks; //log capacity
		Wire [] a = arrWitness;
		Wire ts = a[0];
		Wire sid= a[1];
		Wire price = a[2];
		Wire ts_root= a[3];
		Wire [] proof = new Wire [n+1];
		for(int i=0; i<proof.length; i++) proof[i] = a[4+i];

		//2. generate the price record
		Wire rec = myhash(sid, price);
		//NOTE! check if the root given is ok or not is DONE EXTERNALLY!

		//3. call the price tree to verify the record
		MerkleAccumulator acc = ps.accs[0]; //DOES NOT MATTER as za
		//does not read its detailed data
		ZaMerkleAccVerifier za = new ZaMerkleAccVerifier(config, acc, (ZaGenerator) this.generator);
		Wire [] arrWit = new Wire [proof.length+2];
		arrWit[0] = rec;
		arrWit[1] = ts_root;
		for(int i=0; i<proof.length; i++) arrWit[2+i] = proof[i]; 
		za.build_circuit(new Wire [] {}, arrWit);
		Wire [] res =za.getOutputWires();
		return res;
	}

	/** Generate the input for ths (ts, sid) pair.
		Use the data in the priceServer */
	public BigInteger [][] genInput(int ts, int sid){
		BigInteger root = ps.getRoot(ts);
		BigInteger [] arrwit = new BigInteger [ps.log2_stocks + 5];
		BigInteger [] proof = ps.gen_proof(ts, sid);
		int price = ps.getPrice(ts, sid);
		arrwit[0] = Utils.itobi(ts);
		arrwit[1] = Utils.itobi(sid);
		arrwit[2] = Utils.itobi(price);
		arrwit[3] = root;
		for(int i=0; i<proof.length; i++) arrwit[i+4] = proof[i];
		
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			arrwit
		};
		return ret;
	}
	
	/** Generate the random inputs.  The inputs are actually NOT random,
		the data is from the n%tss records from PriceServer */
	public BigInteger[][] genRandomInput(int n){
		Random rand = new Random(n);
		int ts = rand.nextInt(ps.n_tss);
		int sid = rand.nextInt(1<<(ps.log2_stocks-1));
		int price = ps.getPrice(ts, sid);
		BigInteger [][] ret = genInput(ts, sid);
		if(n%2==0){//introduce fault
			ret[1][2].add(Utils.itobi(3));//introduce err
		}
		return ret;
	}
	
}
