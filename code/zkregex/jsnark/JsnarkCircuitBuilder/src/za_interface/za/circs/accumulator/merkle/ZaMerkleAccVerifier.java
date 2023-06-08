/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/18/2021
* ***************************************************/

/** **************************************************
This is an abstract class should be extended by all
accmulators.
A circuit responsible for verifying the provided proof
to show that an element is a member of the accmulator.
* ***************************************************/
package za_interface.za.circs.accumulator.merkle;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import examples.gadgets.diffieHellmanKeyExchange.ECDHKeyExchangeGadget;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import util.Util;

/** **************************************************
This is an abstract class should be extended by all
accmulators.
A circuit responsible for verifying the provided proof
to show that an element is a member of the accmulator.
* ***************************************************/
public class ZaMerkleAccVerifier extends ZaAccumulatorVerifier{
	// *** data members ***
	protected ZaHash2 hash;
	protected MerkleAccumulator acc;

	// *** Operations ***
	public ZaMerkleAccVerifier(ZaConfig config_in, MerkleAccumulator acc, ZaGenerator zg){
		super(config_in, "MerkleAccVerifier_"+acc.get_capacity_log(), zg);
		this.hash = ZaHash2.new_hash(config_in, zg);
		this.acc = acc;
	}

	public int getNumPublicInputs(){
		return 0;
	}

	/**
		1 for element to verify, 1 for root_hash, and 1 for bits 
		of verify path and n for all nodes on verify path.
		Altogether: n + 3
	*/
	public int getNumWitnessInputs(){
		int n = this.acc.get_capacity_log();
		return n+3;
	}

	/**
		Either 1 or 0 for yes or no
	*/	
	public int getNumOutputs(){ 
		return 1;
	}

	/** verify if the given hash of accmulator and the proof is good.
		@param element - the element to verify membership
		@param hash - root of merkle tree
		@param proof - the proof (see gen_proof of the 
		MerkleTreeAccumulator.java for descriptio of format.
		proof[0] is the packed bits of position of sibiling and
		proof[1-n] is the siblings (verif path).
	 */
	public boolean verify(BigInteger element, BigInteger [] hash,
		BigInteger [] proof){
		BigInteger root_hash = hash[0]; //just hash as tree root
		int n = this.acc.get_capacity_log();
		if(proof.length!=n+1){
			throw new UnsupportedOperationException("proof len != n + 1");
		}
		BigInteger bi_bits = proof[0];
		BigInteger [] bits = Utils.split(bi_bits, n);
		BigInteger [] nodes = new BigInteger [n];
		for(int i=0; i<n; i++) nodes[i] = proof[i+1];
		BigInteger zero = Utils.itobi(0);
		BigInteger cur_node = element;
		for(int i=0; i<n; i++){
			BigInteger left = bits[i].equals(zero)? nodes[i]: cur_node; 
			BigInteger right= bits[i].equals(zero)? cur_node: nodes[i];
			cur_node = this.hash.hash2(left, right);
		}
		boolean res = cur_node.equals(root_hash);
		return res;
	}

	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - [0] element to prove, [1] hash, [2-n+1]
			the proof
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger ele = arrWitness[0];
		BigInteger [] root_hash = new BigInteger [] {arrWitness[1]};
		int n = this.acc.get_capacity_log();
		BigInteger [] proof = new BigInteger [n+1];
		for(int i=0; i<n+1; i++){
			proof[i] = arrWitness[2+i];
		}
		boolean bres = verify(ele, root_hash, proof);
		BigInteger res = bres? Utils.itobi(1): Utils.itobi(0);
		return new BigInteger [] {res};
	}

	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		arrWit[0] - element to verify membership
		arrWit[1] - the hashtree root
		arrWit[2..n+2] the proof
		Altogether: n+3 elements
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. set up inputs
		int n = this.acc.get_capacity_log();
		if(arrWitness.length!=n+3){
			throw new UnsupportedOperationException("arrWit len != n + 3");
		}
		Wire cur_node = arrWitness[0];
		Wire root_hash = arrWitness[1]; //just hash as tree root
		Wire bi_bits = arrWitness[2];
		Wire [] bits = bi_bits.getBitWires(n).asArray();
		Wire [] nodes = new Wire [n];
		for(int i=0; i<n; i++) nodes[i] = arrWitness[i+3];

		//2. verify the path
		Wire one = this.generator.createConstantWire(1);
		for(int i=0; i<n; i++){
			Wire left = bits[i].mul(cur_node).add(
					one.sub(bits[i]).mul(nodes[i])
			);	//bits[i]*nodes[i] + (1-bits[i])*cur_node
			Wire right= bits[i].mul(nodes[i]).add(
					one.sub(bits[i]).mul(cur_node)
			);	
			ZaHash2 cur_hash = ZaHash2.new_hash(this.config, 
				(ZaGenerator) this.generator);
			cur_hash.build_circuit(new Wire [] {}, new Wire [] {left, right});	
			cur_node = cur_hash.getOutputWires()[0];
		}
		Wire res = cur_node.isEqualTo(root_hash);
		return new Wire [] {res};
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		Note: if the accmulator does not have any elements,
		we will randomly add some elements to it. */ 
	public BigInteger[][] genRandomInput(int n){
		//1. populate the accmulator if necessary 
		int cn = this.acc.get_capacity_log();
		int capacity = 1<<cn;
		int size = 4*cn<capacity? 4*cn: capacity-1;
		int ridx = new Random(n).nextInt()%size;
		ridx = ridx<0? 0-ridx: ridx;
		BigInteger element = null;
		if(this.acc.get_size()==0){//assumption 
			for(int i=0; i<size; i++){
				BigInteger ele= this.hash.genRandomInput(n+i)[1][0];
				this.acc.add_element(ele);	
				if(i==ridx) {
					element = ele;
				}
			}
		}
		BigInteger [] arrwit = acc.gen_witness(element);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			arrwit
		};
		//introduce an error randomly
		if(n%2==0){
			arrwit[5] = arrwit[5].add(Utils.itobi(13));
		}
		return ret;
	}
	
}
