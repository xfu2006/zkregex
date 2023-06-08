
/* ***************************************************
Author: Dr. CorrAuthor
@Copyright 2021
Created: 05/08/2021
* ***************************************************/

/** **************************************************
Provides point add operation. Assumption: the x-coordinate
of the two points are different. Otherwise, use ZaDoublePoint
gadget. 
This is adapted from A.  Kosba's examples/gadets/diffieHellmanKeyExchange/ECDHKeyExchangeGadget.java 
The commented out part include
	: handle p + -p = ifinite point case and handle 
  double point case (when x coordinate are same) - note
	this increases the cost of circuit.
Revsion 2: 06/06/2021
*** for efficient reason, we comment it out and ASSUME that the
two point NEVER HAVE the x-coordinate SAME!. ***
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
	four input lines: x1, y1, x2, y2
	two output lines: x3, y3
*/
public class ZaPointAdd extends ZaCirc{
	// *** data member ***
	protected Curve curve;

	// *** operations *** 
	public ZaPointAdd(Curve fac, ZaGenerator zg){
		super(fac.config, "PointAdd", zg); 
		this.curve = fac;
	}	

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 4 inputs (x1, y1, x2, y2) assume already valid points. also x1!=x2*/
	public int getNumWitnessInputs(){
		return 4;
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
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger a, b;
		BigInteger bn = BigInteger.valueOf(n);
		BigInteger [] pt1 = this.curve.getRandomPoint(n);
		BigInteger [] pt2 = this.curve.getRandomPoint(n+1);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {pt1[0], pt1[1], pt2[0], pt2[1]}
		};
		return ret;
	}

	//inputs are x1, y1, x2, y2, outs are calculuated
	//using the default alg assuming they are not zero points
	//handle three cases: point1 is point at inifnity, point2 is at infinity,
	//or none of it is at infinity
	private Wire [] handle_zero(Wire [] inputs, Wire [] outs){
		Wire zero= this.generator.createConstantWire(0); 
		Wire one= this.generator.createConstantWire(1); 
		Wire x1 = inputs[0];
		Wire y1 = inputs[1];
		Wire x2 = inputs[2];
		Wire y2 = inputs[3];
		Wire x3 = outs[0];
		Wire y3 = outs[1];
		Wire b1 = inputs[0].isEqualTo(zero).and(inputs[1].isEqualTo(one));
		Wire b2 = inputs[2].isEqualTo(zero).and(inputs[3].isEqualTo(one));
		Wire b3 = (b1.or(b2)).invAsBit();

		Wire x12 = b1.mul(x2).add(b2.mul(one.sub(b1)).mul(x1)); //b1->x2 or b2->x1
		Wire y12 = b1.mul(y2).add(b2.mul(one.sub(b1)).mul(y1)); 
		Wire x = b3.mul(x3).add(one.sub(b3).mul(x12));
		Wire y = b3.mul(y3).add(one.sub(b3).mul(y12));
		return new Wire [] {x, y};
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker_NOTUSED(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire x1 = arrWitness[0];
		Wire y1 = arrWitness[1];
		Wire x2 = arrWitness[2];
		Wire y2 = arrWitness[3];

		Wire diffY = y1.sub(y2);
		Wire diffX = x1.sub(x2);

		Wire constZero = this.generator.createConstantWire(0); 
		Wire constOne= this.generator.createConstantWire(1); 
		Wire bSameX = x1.isEqualTo(x2);
		Wire bSameY = y1.isEqualTo(y2);

		//1. case 1: works for not same X
		Wire diffXNew = diffX.add(bSameX); //to avoid division error
//		Wire diffXNew = diffX;
		Wire q = new FieldDivisionGadget(diffY, diffXNew).getOutputWires()[0];
		Wire q2 = q.mul(q);
		Wire q3 = q2.mul(q);
		Wire newX1 = q2.sub(this.curve.A).sub(x1).sub(x2);
		Wire newY1 = x1.mul(2).add(x2).add(this.curve.A).mul(q).sub(q3).sub(y1);

		//2. case 2.1: sameX and sameY return double
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaPointDouble zd = new ZaPointDouble(curve, zg);
		Wire [] arrwit = new Wire [] {arrWitness[0], arrWitness[1]};
		zd.build_circuit(arrPubInput, arrwit);
		Wire [] arrzd =zd.getOutputWires();
		Wire newX21 = arrzd[0];
		Wire newY21 = arrzd[1];

		//3. case 2.2. sameX but NOT sameY (this implies that
		// (x,y) and (x,-y) assuming both points are valid
		Wire newX22 = zg.createConstantWire(0);
		Wire newY22 = zg.createConstantWire(1); //the point of infinite

		Wire newX2 =  bSameY.mul(newX21).add(constOne.sub(bSameY).mul(newX22));
		Wire newY2 =  bSameY.mul(newY21).add(constOne.sub(bSameY).mul(newY22));

		//merge case 1 and 2
		Wire newX = bSameX.mul(newX2).add(constOne.sub(bSameX).mul(newX1));
		Wire newY = bSameX.mul(newY2).add(constOne.sub(bSameX).mul(newY1));
		Wire [] arrout = new Wire [] {newX, newY};

		Wire [] res = handle_zero(new Wire [] {x1, y1, x2, y2},
			arrout);
		return res;
	}

	/** build the circuit. Needs to supply the input wires
		NOTE: assumption the x-coordinate of the two points
		are not equal (thus we do not handle p + -p case!
		This will be handled in pointMul  */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire x1 = arrWitness[0];
		Wire y1 = arrWitness[1];
		Wire x2 = arrWitness[2];
		Wire y2 = arrWitness[3];

		Wire diffY = y1.sub(y2);
		Wire diffX = x1.sub(x2);

		Wire q = new FieldDivisionGadget(diffY, diffX).getOutputWires()[0];
		Wire q2 = q.mul(q);
		Wire q3 = q2.mul(q);
		Wire newX1 = q2.sub(this.curve.A).sub(x1).sub(x2);
		Wire newY1 = x1.mul(2).add(x2).add(this.curve.A).mul(q).sub(q3).sub(y1);

		Wire [] arrout = new Wire [] {newX1, newY1};
		return arrout;
	}

	/**  Call Sage to verify
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] a = arrWitness;

		//2. do the work
		if(a[0].equals(a[2])){
			throw new RuntimeException("PointAdd does not support two x-coordinate same!");
		}
		BigInteger [] res = this.curve.pointAdd(a[0], a[1], a[2], a[3]);
		BigInteger [] arr = new BigInteger [] {res[0], res[1]};
		return arr;
	}

}
