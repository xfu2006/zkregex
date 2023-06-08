
/* ***************************************************
Author: Dr. CorrAuthor
@Copyright 2021
Created: 05/08/2021
* ***************************************************/

/** **************************************************
This is adapted from A. 
Kosba's examples/gadets/diffieHellmanKeyExchange/ECDHKeyExchangeGadget.java 
It provides operation for computing the Y coordinate
given X coordinate
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

/**
	One input: x coordinate.
	One output: y coordinate. Assumption: the x is x-coordinate
of a valid point
*/
public class ZaComputeY extends ZaCirc{
	// *** data member ***
	protected Curve curve;

	// *** operations *** 
	public ZaComputeY(Curve fac, ZaGenerator zg){
		super(fac.config, "ComputeY", zg); 
		this.curve = fac;
	}	

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** ONE field element as x-coordinate. Must be a valid point's x*/
	public int getNumWitnessInputs(){
		return 1;
	}

	/** ONE field element as y-coordinate*/
	public int getNumOutputs(){ 
		return 1;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a, b;
		BigInteger bn = BigInteger.valueOf(n);
		BigInteger [] pt = this.curve.getRandomPoint(n);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {pt[0]}
		};
		return ret;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire wx = arrWitness[0];
		Wire y = generator.createProverWitnessWire();
		generator.specifyProverWitnessComputation(new Instruction() {
				public void evaluate(CircuitEvaluator evaluator) {
					BigInteger x = evaluator.getWireValue(wx);
					evaluator.setWireValue(y, curve.computeYCoordinate(x));
				}
		});
		Wire [] arrout = new Wire [] {y};
		return arrout;
	}

	/**  Call Sage to verify
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] arr = new BigInteger [] {this.curve.computeYCoordinate(arrWitness[0])};
		return arr;
	}

}
