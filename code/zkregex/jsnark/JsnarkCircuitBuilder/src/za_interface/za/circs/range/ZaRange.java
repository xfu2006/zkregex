/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/21/2021
* ***************************************************/

/** **************************************************
This is a verifier to verify that the number hidden
is in range [0, 2^n-1] (i.e., n-bits unsigned integer).
The assumption is that 2^n-1 is less than the
prime field order
* ***************************************************/
package za_interface.za.circs.range;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.eval.CircuitEvaluator;
import circuit.operations.Gadget;

import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;

/**
This is a verifier to verify that the number hidden
is in range [0, 2^n-1] (i.e., n-bits unsigned integer).
The assumption is that 2^n-1 is less than the
prime field order
*/
public class ZaRange extends ZaCirc{
	protected int nbits = 32;

	// ** Operations **
	public ZaRange(ZaConfig config_in, int n, ZaGenerator zg){
		super(config_in, "Range_" + String.valueOf(n), zg);
		this.nbits = n;
		BigInteger order = config_in.getFieldOrder();
		BigInteger pow2n = Utils.itobi(1).shiftLeft(n);
		if(pow2n.compareTo(order)>0){
			throw new UnsupportedOperationException("2^bits " + n + " greater than field order");
		}
	}

	public int getNumPublicInputs(){
		return 0;
	}

	/** the number to show in range */
	public int getNumWitnessInputs(){
		return 1;
	}

	/** a bit representing true/false */	
	public int getNumOutputs(){ 
		return 1;
	}

	/** returns 1 if input is in range [0, 2^nbits-1] */	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger a = arrWitness[0].add(Utils.itobi(0));
		BigInteger pow2n = Utils.itobi(1).shiftLeft(nbits);
		BigInteger zero = Utils.itobi(0);
		BigInteger res = a.compareTo(zero)>=0 && a.compareTo(pow2n)<0?
			Utils.itobi(1): zero;
		return new BigInteger [] {res};
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire ain = arrWitness[0];
		BigInteger order = config.getFieldOrder();
		int fullbits = order.bitLength();
		WireArray arrout = ain.getBitWiresIfExistAlready(); 
		if(arrout==null){
			arrout = ain.getBitWires(fullbits); //a bit of waste
				//but if too short, jsnark will complain
		}
		Wire b = arrout.packAsBits(nbits);
		Wire res = ain.isEqualTo(b);
		return new Wire [] {res};
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger pow2n = Utils.itobi(1).shiftLeft(nbits);
		BigInteger a = Utils.randbi(nbits).mod(pow2n);
		if(n%2==1){//false case, make it NOT in range
			a = pow2n.add(a);
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {a}
		};
		return ret;
	}
		
}
