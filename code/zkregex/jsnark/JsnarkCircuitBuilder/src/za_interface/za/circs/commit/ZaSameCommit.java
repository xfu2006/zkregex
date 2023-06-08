/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/01/2021
* ***************************************************/

/** **************************************************
To show that two commitments have the same number behind it.
Parameterized by which hash/commit algorithm specified in config.
One input line (the number to commit) and two output lines:
the two commitments.
* ***************************************************/
package za_interface.za.circs.commit;

import java.math.BigInteger;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import circuit.structure.Wire;

/**
	To show one prime field element generates two commitments.
Note commitment is parameterized by the Config, e.g., Pederson,
Sha256 or Poseidon.
*/
public class ZaSameCommit extends ZaCirc{
	// ** data members **
	protected ZaCommit zc1;
	protected ZaCommit zc2;

	// ** Operations **
	public ZaSameCommit(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "SameCommit", zg);
		ZaGenerator zg2 = (ZaGenerator) this.generator;
		this.zc1 = ZaCommit.new_commit(this.config, zg2);
		this.zc2 = ZaCommit.new_commit(this.config, zg2);
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** ONE prime field element to commit to */
	public int getNumWitnessInputs(){
		return 1;
	}

	/** return two 256-bit prime field element as commitments*/
	public int getNumOutputs(){ 
		return 2;
	}

	/** logical evaluation: produes two commitments */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, BigInteger [] arrWitness){
		BigInteger x = arrWitness[0];
		ZaGenerator zg = (ZaGenerator) this.generator;
		BigInteger [] res = new BigInteger [] {
			zc1.commit(x),
			zc2.commit(x)
		};	
		return res;
	}

	/** takes one input line and use two za commit components to produce
		the outline */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, Wire [] arrWitness)	{
		Wire x = arrWitness[0];
		ZaGenerator zg = (ZaGenerator) this.generator;
		zc1.build_circuit(new Wire [] {}, new Wire [] {x});
		zc2.build_circuit(new Wire [] {}, new Wire [] {x});
		Wire o1 = zc1.getOutputWires()[0];
		Wire o2 = zc2.getOutputWires()[0];
		return new Wire [] {o1, o2};
		
	}


	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a;
		BigInteger bn = BigInteger.valueOf(n);
		if(n==0){//simple case
			a = Utils.stobi("0102030405060708091011121314151617181920212223242526272829303132").mod(modulus); //256 bits
		}else{
			a = Utils.randpf(config);
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {a}
		};
		return ret;
	}

		
}
