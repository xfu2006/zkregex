/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/26/2021
* ***************************************************/

/** **************************************************
This is a simple Split gate. In its constructor,
can set the integer n.
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
	Split a n-bit BigInt into bits. Takes one wire and
split it into n-bit. Assumption: the wire value is within
range: less than field order. Note: input is secret.
One witness input, oue output.
*/
public class ZaSplit extends ZaCirc{
	protected int nbits = 32;

	// ** Operations **
	public ZaSplit(ZaConfig config_in, int n, ZaGenerator zg){
		super(config_in, "Split", zg);
		this.nbits = n;
	}

	public int getNumPublicInputs(){
		return 0;
	}
	public int getNumWitnessInputs(){
		return 1;
	}
	
	public int getNumOutputs(){ 
		return 1;
	}
	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger a = arrWitness[0].add(Utils.itobi(0));
		BigInteger [] res = new BigInteger [nbits];
		BigInteger two = Utils.itobi(2); 
		for(int i=0; i<res.length; i++){
			res[i] = a.mod(two);
			a = a.divide(two);
		}
		return res;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire ain = arrWitness[0];
		Wire [] arrout = ain.getBitWires(nbits).asArray();
		return arrout;
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a;
		BigInteger bn = BigInteger.valueOf(n);
		if(n==0){//simple case
			a = BigInteger.valueOf(2234);
		}else{
			a = Utils.randbi(nbits).mod(modulus);
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {a}
		};
		return ret;
	}
		
}
