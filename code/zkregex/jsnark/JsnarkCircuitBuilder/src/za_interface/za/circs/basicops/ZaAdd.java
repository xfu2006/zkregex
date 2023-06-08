/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/20/2021
* ***************************************************/

/** **************************************************
This is a simple add gate.
* ***************************************************/
package za_interface.za.circs.basicops;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.operations.Gadget;

import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;

/**
  Base class of all circuits (gadgets) related to zero_audit
*/
public class ZaAdd extends ZaCirc{

	// ** Operations **
	public ZaAdd(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "Add", zg);
	}

	public int getNumPublicInputs(){
		return 1;
	}
	public int getNumWitnessInputs(){
		return 3;
	}
	
	public int getNumOutputs(){ 
		return 1;
	}
	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger a = arrPubInput[0];
		BigInteger b = arrWitness[0];
		BigInteger [] res = new BigInteger [1];
		BigInteger modulus = this.config.getFieldOrder();
		res[0] = a.add(b).mod(modulus);
		return res;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire o1 = arrPubInput[0].add(arrWitness[0]);
		Wire [] arrout = new Wire [1];
		arrout[0] = o1;
		return arrout;
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a, b;
		BigInteger bn = BigInteger.valueOf(n);
		if(n==0){//simple case
			a = BigInteger.valueOf(2);
			b = BigInteger.valueOf(3);
			System.out.println("Use 2 and 3 as input");
		}else{
			a = modulus.subtract(Utils.itobi(1001)).multiply(bn).mod(modulus);
			b = Utils.itobi(n).add(Utils.itobi(1732)).mod(modulus);
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {a},
			new BigInteger [] {b}
		};
		return ret;
	}
		
}
