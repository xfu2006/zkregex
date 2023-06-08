/* ***************************************************
Author: Dr. CorrAuthor
@Copyright 2021
Created: 05/09/2021
* ***************************************************/

/** **************************************************
Provides point Point Multiplication operation.  Assumption: input is NOT a
curve point at infinity.
This is adapted from A.  Kosba's examples/gadets/diffieHellmanKeyExchange/ECDHKeyExchangeGadget.java 
** added a special case for exponent 0 **
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
import java.util.Hashtable;

/**
	four input lines: x1, y1, exp. 
	two output lines: (x3, y3) = (x1,y1)*exp 
	i.e., it's the resulting of adding exp's copies of (x1,y1)
*/
public class ZaPointMul extends ZaCirc{
	// *** data member ***
	protected Curve curve;

	// *** operations *** 
	public ZaPointMul(Curve fac, ZaGenerator zg){
		super(fac.config, "PointMul", zg); 
		this.curve = fac;
	}	

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 4 inputs (x1, y1, x3). Assumption: (x1,y1) already valid points. 
		and x3 is already mod%sub_group_order
		*/
	public int getNumWitnessInputs(){
		return 3;
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
		BigInteger exp = this.curve.getRandomExponent(n, false);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {pt1[0], pt1[1], exp}
		};
		return ret;
	}


	/** compute the precomputeX, Y (power table) table. return two arrays */ 
	private Wire [][] preprocess(Wire x1, Wire y1) {

		int bits = this.curve.input_width;
		Wire [] precomputedX =  new Wire [bits];
		Wire [] precomputedY =  new Wire [bits];
		precomputedX[0] = x1;
		precomputedY[0] = y1;
		ZaGenerator zg = (ZaGenerator) this.generator;
		for (int j = 1; j < bits; j += 1) {
			ZaPointDouble zDouble = new ZaPointDouble(this.curve, zg);
			zDouble.build_circuit(new Wire [] {},
				new Wire [] {precomputedX[j-1], precomputedY[j-1]});
			Wire [] res = zDouble.getOutputWires();
			precomputedX[j] = res[0];
			precomputedY[j] = res[1];
		}
		Wire [][] ret = new Wire [][] {precomputedX, precomputedY};
		return ret;
	}

	/** build the circuit. Needs to supply the input wires.
		arrWitness[0,1,2] are x, y, exp (the integer to multipy with).
		Assumption: exp is already in range. */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. get the input
		int bits = this.curve.input_width;
		Wire x1 = arrWitness[0];
		Wire y1 = arrWitness[1];
		Wire zero= this.generator.createConstantWire(0); 
		Wire one = this.generator.createConstantWire(1); 
		Wire exp = arrWitness[2]; //already assumed to be input_width bits
		//!*** NOTE: when exp is 0, the following logic (which minus 
		// precomputed[bits-1] will eventually results exception in 
		// ZaPointAdd (not allowing two same x-coordinate). In this case,
		// when exp is 0, enhance change it to a fake 1 and take the alternative
		//result *** !
		Wire bExpZero = exp.isEqualTo(zero);
		exp = exp.add(bExpZero); //so 0 is changed to 1
		Wire [] bits_exp= exp.getBitWires(bits).asArray();
		Wire [][] tbl = this.preprocess(x1, y1);
		Wire [] precomputedX = tbl[0];
		Wire [] precomputedY = tbl[1];

		//2. create the point
		//NOTE: we do not assume that the most 
		//significant point is 1 (so slightly different from Kosba's impl)
		//The assumption (3-least being 0 and most signicant being 1) 
		//is assumed when the point mul is involved in DiffieHellman Exchange
		ZaGenerator zg = (ZaGenerator) this.generator;
		//pretend that most significant bit is set
		Wire newx = precomputedX[bits-1];
		Wire newy = precomputedY[bits-1];

		//3. loop to calculuate; 
		for(int j=bits-2; j>=0; j--){
			ZaPointAdd zadd = new ZaPointAdd(this.curve, zg);
			Wire xj = precomputedX[j];
			Wire yj = precomputedY[j];
			zadd.build_circuit(new Wire [] {}, 
				new Wire [] {newx, newy, xj, yj});
			Wire [] tmp = zadd.getOutputWires();
			Wire isOne = bits_exp[j];
			newx = newx.add(isOne.mul(tmp[0].sub(newx)));
			newy = newy.add(isOne.mul(tmp[1].sub(newy)));	 
		}

		//4. re-adjust the result if highest bit is 0
		Wire offset_x = precomputedX[bits-1];
		Wire offset_y = zg.createConstantWire(0).sub(precomputedY[bits-1]);
		ZaPointAdd zsub = new ZaPointAdd(this.curve, zg); //point minus last point in precomputed table
		zsub.build_circuit(new Wire [] {}, new Wire [] {newx, newy, offset_x, offset_y});
		Wire [] altarr = zsub.getOutputWires();
		Wire alt_x = altarr[0];
		Wire alt_y = altarr[1];
		Wire msbit = bits_exp[bits-1]; //most significant bit
		//Wire neg_msbit = zg.createConstantWire(1).sub(msbit);
		Wire neg_msbit = msbit.invAsBit();

		Wire res_x = msbit.mul(newx).add(neg_msbit.mul(alt_x));  //1 case
		Wire res_y = msbit.mul(newy).add(neg_msbit.mul(alt_y));  //0 case

		//if exp==0 return [0,1] (infinite point)
		//otherwise return the regular op result
		Wire out_x = bExpZero.mul(zero).add(one.sub(bExpZero).mul(res_x));
		Wire out_y = bExpZero.mul(one).add(one.sub(bExpZero).mul(res_y));
		Wire [] arrout = new Wire [] {out_x, out_y};
		return arrout;
	}

	/**  Call Sage to verify
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] a = arrWitness;
		//just reuse sage point add
		BigInteger [] res = this.curve.pointMul(a[0], a[1], a[2]);
		BigInteger [] arr = new BigInteger [] {res[0], res[1]};
		return arr;
	}

}
