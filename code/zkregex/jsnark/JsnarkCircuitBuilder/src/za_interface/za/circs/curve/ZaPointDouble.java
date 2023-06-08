
/* ***************************************************
Author: Dr. CorrAuthor
@Copyright 2021
Created: 05/09/2021
* ***************************************************/

/** **************************************************
Provides point DOUBLE POINT operation.  Assumption: input is NOT a
curve point at infinity.
This is adapted from A.  Kosba's examples/gadets/diffieHellmanKeyExchange/ECDHKeyExchangeGadget.java 
* ***************************************************/
package za_interface.za.circs.curve;

import circuit.eval.Instruction;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import java.math.BigInteger;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.operations.Gadget;
import examples.gadgets.math.FieldDivisionGadget;

/**
	two input lines: x1, y1
	two output lines: x2, y2
*/
public class ZaPointDouble extends ZaCirc{
	// *** data member ***
	protected Curve curve;

	// *** operations *** 
	public ZaPointDouble(Curve fac, ZaGenerator zg){
		super(fac.config, "PointDouble", zg); 
		this.curve = fac;
	}	

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 4 inputs (x1, y1) assume already valid points. */
	public int getNumWitnessInputs(){
		return 2;
	}

	/** two elements representing (x,y) of the resulting point.
		the resulting point will NEVER be point at infinitely */
	public int getNumOutputs(){ 
		return 2;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger [] pt1 = this.curve.getRandomPoint(n);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {pt1[0], pt1[1]}
		};
		return ret;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire x1 = arrWitness[0];
		Wire y1 = arrWitness[1];

		Wire x_2 = x1.mul(x1);
		Wire l1 = new FieldDivisionGadget(x_2.mul(3)
				.add(x1.mul(this.curve.A).mul(2)).add(1), y1.mul(2))
				.getOutputWires()[0];
		Wire l2 = l1.mul(l1);
		Wire newX = l2.sub(this.curve.A).sub(x1).sub(x1);
		Wire newY = x1.mul(3).add(this.curve.A).sub(l2).mul(l1).sub(y1);

		Wire [] arrout = new Wire [] {newX, newY};
		return arrout;
	}

	/**  Call Sage to verify
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] a = arrWitness;
		if(a[0].equals(Utils.itobi(0))){
			throw new RuntimeException("zaPointDouble dues not support y1 = 0!");
		}
		//just reuse sage point add
		BigInteger [] res = this.curve.pointAdd(a[0], a[1], a[0], a[1]);
		BigInteger [] arr = new BigInteger [] {res[0], res[1]};
		return arr;
	}

}
