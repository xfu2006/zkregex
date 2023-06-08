/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/26/2021
* ***************************************************/

/** **************************************************
This implmenets the "full" Pedersen hash in the sense that
the commitment is the full 2-element point vector (x,y)
as a curve point

* ***************************************************/
package za_interface.za.circs.hash.pedersen;

import java.math.BigInteger;
import java.util.HashMap;
import circuit.structure.Wire;
import circuit.structure.CircuitGenerator;
import za_interface.za.ZaCirc;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.ZaHash2;
import za_interface.za.circs.curve.*;
import util.Util;
import examples.gadgets.math.ModConstantGadget;
import examples.gadgets.math.FieldDivisionGadget;

/**
This implements Pedersen hash (using Pedersen commit
as a hash). Given a curve setting 
(see za_interface/za/circ/curves/Curve.java),
It applies Pedersen hash g^x h^y where x and y 
are the inputs.
Notice that x and y must be in the range of curve.input_bits (e.g.,
for the curve25519 customized for libsnark, this is about 
253 bits and for the curve25519 customized for spartan this is about
251 bits.

The inputs: x and y (as standard hash)
Both x and y are 256-bit numbers that are in range (curve.input_width, 
see above)
Output: the (x,y) point of g^x h^y
*/

public class ZaPedersenFull extends ZaCirc{
	// *** Data Members ***
	protected Curve curve;
	protected BigInteger [] g; //base point g
	protected BigInteger [] h; //base point h
	//constant for g and h if no custom setup
	protected static HashMap<ZaConfig, BigInteger [][]> configToBase = 
			new HashMap<>();

	// ** Operations **
	public ZaPedersenFull(ZaConfig config_in, ZaGenerator zg){
		//1. set up curve
		super(config_in, "PedersenFull", zg);
		this.curve = Curve.createCurve(config_in);
		if(config_in.hash_alg != ZaConfig.EnumHashAlg.Pedersen){
			//throw new UnsupportedOperationException("Config.hash option does not match Pedersen: " + config_in.hash_alg);
			System.out.println("WARNING: Config.hash option is not PedersenCommit: " + config_in.hash_alg);
		}

		//2. set up the random nonce  and g and h
		//NOTE: we assume prover and verifier have agreed
		//commonly on some public-coin process that generates g and h
		// here seeds 512 and 3712 will lead to ALWAYS the same pseudo-random
		if(!configToBase.containsKey(config_in)){

			BigInteger [] G = curve.getRandomPoint(512); //this is basepoint*512
			BigInteger [] H = curve.getRandomPoint(3721); //3712 is just ranomly picked
			configToBase.put(config_in, new BigInteger [][] {G, H});
		}else{
		}
		this.g = configToBase.get(config_in)[0];
		this.h = configToBase.get(config_in)[1];
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** two prime field elements regarded as private witness */
	public int getNumWitnessInputs(){
		return 2;
	}

	/** return two 256-bit prime field element, value always
	less than prime field order, they are the (x,y) coordinates of
	the pedersen commit */
	public int getNumOutputs(){ 
		return 2;
	}


	private void throw_width_err(String var){
		throw new UnsupportedOperationException(
			var + " length: >curve.input_width");		
	}

	/** print the point */
	private void prt(String msg, BigInteger [] pt){
		System.out.println(msg + ": " +  pt[0] + ", " + pt[1]);
	}
	/** logical operation. Generate point g^x h^r, and 
	return its (x,y) of the point */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. get and check input
		BigInteger x = arrWitness[0];
		BigInteger y = arrWitness[1];
		x = forceValidElement_logical(x);
		y = forceValidElement_logical(y);

		//2. compute g^x h^r
		BigInteger [] gx = curve.pointMul(g[0], g[1], x);
		BigInteger [] hy = curve.pointMul(h[0], h[1], y);
		BigInteger [] res = curve.pointAdd(gx[0], gx[1], hy[0], hy[1]);
		return res;
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

	/** Handle the complex point add (all cases):
		(1) sameX but not sameY: (p + -p)
		(2) sameX and sameY (call doubPoint)
		(3) not same x: regular point add
		(4) one of the point is [0,1] (infinity), return the other point
	 */
	public Wire [] pointAddAllCases(Wire x1, Wire y1, Wire x2, Wire y2){
		Wire diffY = y1.sub(y2);
		Wire diffX = x1.sub(x2);

		Wire constZero = this.generator.createConstantWire(0); 
		Wire constOne= this.generator.createConstantWire(1); 
		Wire bSameX = x1.isEqualTo(x2);
		Wire bSameY = y1.isEqualTo(y2);

		//1. case 1: works for not same X
		Wire diffXNew = diffX.add(bSameX); //to avoid division error
		Wire q = new FieldDivisionGadget(diffY, diffXNew).getOutputWires()[0];
		Wire q2 = q.mul(q);
		Wire q3 = q2.mul(q);
		Wire newX1 = q2.sub(this.curve.A).sub(x1).sub(x2);
		Wire newY1 = x1.mul(2).add(x2).add(this.curve.A).mul(q).sub(q3).sub(y1);

		//2. case 2.1: sameX and sameY return double
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaPointDouble zd = new ZaPointDouble(curve, zg);
		Wire [] arrwit = new Wire [] {x1, y1};
		zd.build_circuit(new Wire [] {}, arrwit);
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

		Wire [] res = handle_zero(new Wire [] {x1, y1, x2, y2}, arrout);
		return res;
	}


	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. prepare all wires
		Wire x = arrWitness[0];
		Wire y = arrWitness[1];
		ZaGenerator zg = (ZaGenerator) this.generator;
		Wire gx = zg.createConstantWire(g[0]);
		Wire gy = zg.createConstantWire(g[1]);
		Wire hx = zg.createConstantWire(h[0]);
		Wire hy = zg.createConstantWire(h[1]);

		//2. enforce x and y in range
		x = forceValidElement(x);
		y = forceValidElement(y);
		

		//3. g^x h^y
		ZaPointAdd zadd = new ZaPointAdd(curve, zg);
		ZaPointMul zmul_g = new ZaPointMul(curve, zg);
		ZaPointMul zmul_h = new ZaPointMul(curve, zg);
		Wire [] arrEmpty = new Wire [] {};
		zmul_g.build_circuit(arrEmpty, new Wire [] {gx, gy, x});
		zmul_h.build_circuit(arrEmpty, new Wire [] {hx, hy, y});
		Wire [] a1 = zmul_g.getOutputWires();
		Wire [] a2 = zmul_h.getOutputWires();
		Wire [] res = pointAddAllCases(a1[0], a1[1], a2[0], a2[1]);

		return res;
	}

	/** Overrwrite ZaHash's random function to limit the exponent in range */
	public BigInteger[][] genRandomInput(int n){
		BigInteger one = Utils.itobi(1);
		BigInteger [][] arr = new BigInteger [][] {
			new BigInteger [] {},
			new BigInteger [] {one, one}
		};
		//this is SLIGHTLY less than the real curve.subgruop_order
		//for convenience of check.
		BigInteger order = one.shiftLeft(curve.input_width-1);
		arr[1][0] = arr[1][0].mod(order); //this is arrWtiness[0]
		arr[1][1] = arr[1][1].mod(order); //this is arrWitness[1]

		return arr;
	}

	/** check if x is a valid element that could be hashed */
	public boolean isValidElement(BigInteger x){
		BigInteger order = this.curve.subgroup_order;
		return x.compareTo(order)>=0;
	}

	/** if x is out of bound, convert it to a valid input */
	public BigInteger forceValidElement_logical(BigInteger x){
		BigInteger order = this.curve.subgroup_order;
		return x.mod(order);
	}

	/** if x is out of bound, convert it to a valid input */
	public Wire forceValidElement(Wire x){
		BigInteger order = this.curve.subgroup_order;
		Wire r = new ModConstantGadget(x, 256, order).getOutputWires()[0];
		return r;
	}
	
}
