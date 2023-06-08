/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/30/2021
* ***************************************************/

/** **************************************************
This is a commit2 algorithm that uses hash to acomplish
the job. Main idea:
commit(x) = hash(nonce||x)
The hash algorithm is given in the Config.hash_alg option.
Assumption: random oracle assumption.
* ***************************************************/
package za_interface.za.circs.commit;

import java.util.Random;
import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.ZaHash2;
import util.Util;

/**
	Commit to one prime field element x using
hash(nonce||x). Hash algorithm is determiend by
the config.hash_alg.

	Security analysis: let t be the number of attempts
made by the adversary. Given SHA256 as one example:
256-bit output and 256-bit randon nonce. (note: the nonce
and input can be both restricted to 251 or 253 bit
if Pedersen hash is used!
   
	Binding-security (t, t^2/2^256) e.g., let t= 2^80
binding security is (2^80, 2^-80) - that is 
if adversary make 2^80 attempts, the success rate is 2^-80
to create a fake proof.

	Conceiling-security (t, t/^256) - that is
take t = 2^80 as one example it is (2^80, t^-160).
Assume the adversary make 2^80 queries, the likelihood
she can confirm x is the one that generates Hash(r||x) is 2^-160.

See sample analysis at:
Wagner, David (2006), Midterm Solution, p. 2, retrieved 26 October 2015
*/
public class ZaHashCommit extends ZaCommit{

	// ** Operations **
	public ZaHashCommit(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "HashCommit", zg);
		Random rand = new Random();
		int rn = rand.nextInt();
		this.nonce = this.genRandomHashInput(rn); //THIS IS REQUIRED AND
		//NEED TO E RESET as some hash such as Pedersen is restricted
		//to 251- or 253- bit depending on the zk-field used
	}


	/** logical operation: perform hash(nonce || x) */	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger x = arrWitness[0];
		ZaHash2 zh = ZaHash2.new_hash(this.config, (ZaGenerator) this.generator);
		BigInteger y = zh.hash2(this.nonce, x);
		BigInteger [] arrout = new BigInteger [1];
		arrout[0] = y;
		return arrout;
	}

	/** build the circuit. Nonce is set as a constant wire */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		ZaHash2 zh = ZaHash2.new_hash(this.config, (ZaGenerator) this.generator);
		System.out.println("generator is " + generator);
		Wire nonceWire = generator.createConstantWire(this.nonce);
		zh.build_circuit(new Wire [] {}, 
				new Wire [] {nonceWire, arrWitness[0]});
		return zh.getOutputWires();
	}

	/** Get one BigInt that is allowed by the hash.
	Some hash, such as Pedersen allows ONLY restrict bits
	and specific patterns (e.g., only 251-bit or 253-bit
	depending on the zk-platform. See PerdersenHash.java
	*/
	protected BigInteger genRandomHashInput(int n){
		ZaHash2 zh = ZaHash2.new_hash(this.config, (ZaGenerator) this.generator);
		BigInteger [][] ret = zh.genRandomInput(n);
		return ret[1][0]; //the first random input generated
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		Note: since some hash e.g., PedersenHash only accepts
		restricted ranges (e.g., 251-bit input), call the
		genRandomInput from the Hash component. */ 
	public BigInteger[][] genRandomInput(int n){
		ZaHash2 zh = ZaHash2.new_hash(this.config, (ZaGenerator) this.generator);
		BigInteger rn = this.genRandomHashInput(n);
		BigInteger [][] ret = new BigInteger [][]{
			new BigInteger [] {},
			new BigInteger [] {rn},
		};
		return ret;
	}
}
