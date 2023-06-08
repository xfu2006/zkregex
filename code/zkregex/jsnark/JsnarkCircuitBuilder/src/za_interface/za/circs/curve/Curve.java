/* ***************************************************
Author: Dr. CorrAuthor
@Copyright 2021
Created: 05/07/2021
* ***************************************************/

/** **************************************************
This is a factory for creating circuits
related to *** Elliptic Curve 25519/Montgomery ***.

Note that given the prime field size in Config,
we'll set up the value A of the curve:
y^2 = x^3 + Ax^2 + x

This generalizes the approach given in
examples/gadgets/diffieHellmanExchange/ECDHKeyExchangeGadget.java
and the idea is presented in
https://eprint.iacr.org/2015/1093.pdf

The original ECDHKeyExchange provides zksnark curve support
for the field needed by libsnark (to support order
21888242871839275222246405745257275088548364400416034343698204186575808495617).
We extended the approach to support spartan (to support order
7237005577332262213973186563042994240857116359379907606001950938285454250989).

A similar curve25519 is configured for the A coeff with similar strategy.

We refactored the ECDHKeyExchangeGadget.java so that multiple config
can be supported and variationsof curve 25519 will be created correspondingly.
This class will be used to support Pederson commit as well (relaxing
the requirement on input x [least 3 bits be 0 etc.]).

* ***************************************************/
package za_interface.za.circs.curve;

import java.math.BigInteger;
import za_interface.za.ZaConfig;
import za_interface.za.Utils;
import za_interface.PrimeFieldInfo;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import circuit.eval.Instruction;
import java.io.Serializable;

/** 
  Based on the passed ZaConfig, set up the curve configuration
such as coeff A value and curve order. Provide factory operations
for creating ZaCircs for various zk-snark friendly curve operations
such as point add and point multiplication. This is a customized
Curve25519 (depending on different field size), initialiaze its
A coefficient.
*/
public class Curve implements Serializable{
	//** data members **
	public ZaConfig config;
	/* the order of the zk-snark platform's field order*/
	public BigInteger zk_field_order;
	/* coeffient A for y^2 = x^3 + A*x^2 + x curve 25519/Montgomery curve */
	public BigInteger A;
	/* the order of the customized curve 25519 order */
	public BigInteger curve_order;
	/* the order of base point, it will ALWAYS be 1/8 of curve_order */
	public BigInteger subgroup_order;
	/* x-coordinate of the base point */
	public BigInteger baseX;
	/* y-coordinate of the base point */
	public BigInteger baseY;
	/* bit-width of input */
	public int input_width;

	//** operations **

	public Curve(){//for serialization
	}
	/** this is the jsnark's curve25519 for supporting libsnark,
		all params see the sage_scirpts/curve/Mont_126932
		Correspods to PrimeFields:
		CONFIG.LIBSNARK and PrimeFieldInfo.AURORA
	 */
	protected void setupForCurve_126932(){
		this.zk_field_order = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");//file p in Mont_126932
		this.subgroup_order= new BigInteger("2736030358979909402780800718157159386074658810754251464600343418943805806723"); //file l in Mont_126932 folder
		this.curve_order = subgroup_order.multiply(Utils.itobi(8));
		this.baseX = Utils.itobi(4); //file x1
		this.baseY = new BigInteger("5854969154019084038134685408453962516899849177257040453511959087213437462470");
		this.input_width = this.curve_order.bitLength() - 1; //253 bits
		this.A = Utils.itobi(126932);
	}

	/** this is the OUR newly added curve25519 for supporting libspartan,
		all params see the sage_scirpts/curve/Mont_30428
		Correspods to PrimeFields:
		CONFIG.LIBSPARTAN
	 */
	protected void setupForCurve_30428(){
		this.zk_field_order = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");//file p in Mont_126932
		this.subgroup_order= new BigInteger("904625697166532776746648320380374280107890834947942155200105893906051221883"); //file l in Mont_126932 folder
		this.curve_order = subgroup_order.multiply(Utils.itobi(8));
		this.baseX = Utils.itobi(12); //file x1
		this.baseY = new BigInteger("2376992839796637419320937309940942876833155063796737539977139289637651751925");
		this.input_width = this.curve_order.bitLength() - 1; 
		this.A = Utils.itobi(30428);
	}

	/* return the corresponding curve factory given config */
	public static Curve createCurve(ZaConfig config){
		Curve cf = new Curve();
		if(config.field_info==PrimeFieldInfo.AURORA ||
			config.field_info==PrimeFieldInfo.LIBSNARK){
			cf.setupForCurve_126932();
		}else if(config.field_info==PrimeFieldInfo.LIBSPARTAN){
			cf.setupForCurve_30428();
		}else{
			throw new UnsupportedOperationException("not implemented yet");
		}
		cf.config = config;
		return cf;
	}

	/** 
		Assuming this is already the x-coordinate of a valid point.
		Adapted from A. Kosba ECDHKeyExchange.java.
	 */
	public BigInteger computeYCoordinate(BigInteger x) {
		BigInteger pfo = this.zk_field_order;
		BigInteger xSqred = x.multiply(x).mod(pfo);
		BigInteger xCubed = xSqred.multiply(x).mod(pfo);
		BigInteger ySqred = xCubed.add(this.A.multiply(xSqred)).add(x)
				.mod(pfo);
		BigInteger y = IntegerFunctions.ressol(ySqred, pfo);
		return y;
	}

	/** To test if (x,y) is a valid point */
	public boolean isValidPoint(BigInteger x, BigInteger y){
		BigInteger pfo = this.zk_field_order;
		BigInteger ySqred = y.multiply(y).mod(pfo);
		BigInteger xSqred = x.multiply(x).mod(pfo);
		BigInteger xCubed = xSqred.multiply(x).mod(pfo);
		BigInteger ySqred2 = xCubed.add(this.A.multiply(xSqred)).add(x)
				.mod(pfo);
		return ySqred.equals(ySqred2);
	}

	/** Point add, by calling sage, ASSUMING the passed points
		are already VALID points. Implemented using Sage, can
		be improved later */
	public BigInteger [] pointAdd(BigInteger x1, BigInteger y1,
		BigInteger x2, BigInteger y2){
		//1. handle special case one is point of infinity
		BigInteger zero = Utils.itobi(0);
		BigInteger one= Utils.itobi(1);
		if(x1.equals(zero) && y1.equals(one)){
			return new BigInteger [] {x2, y2}; 
		}
		if(x2.equals(zero) && y2.equals(one)){
			return new BigInteger [] {x1, y1}; 
		}

		String sSage= 
			"p = " + zk_field_order + "\n" +
			"aa = " + A + "\n" + 
			"E = EllipticCurve(GF(p),[0,aa,0,1,0])\n" +
			"pt1 = E(" + x1.toString() + ", " + y1.toString() + ") \n"+
			"pt2 = E(" + x2.toString() + ", " + y2.toString() + ") \n"+
			"pt3 = pt1 + pt2\n" +
			"print(\"OUTPUT: \" + str(pt3[0]) + \" \" +  str(pt3[1]) + \" \" + str(pt3[2]) )\n";
		BigInteger [] res = Utils.runSageArr(sSage);
		return res;
	}

	/** Point mul, by calling sage, ASSUMING the passed points
		are already VALID points. The exponent will be exp%SUBGROUP_ORDER
		*/
	public BigInteger [] pointMul(BigInteger x1, BigInteger y1,
		BigInteger exp){
		exp = exp.mod(this.subgroup_order);
		String sSage= 
			"p = " + zk_field_order + "\n" +
			"aa = " + A + "\n" + 
			"E = EllipticCurve(GF(p),[0,aa,0,1,0])\n" +
			"pt1 = E(" + x1.toString() + ", " + y1.toString() + ") \n"+
			"pt3 = pt1 * " +exp.toString() + "\n" +
			"print(\"OUTPUT: \" + str(pt3[0]) + \" \" +  str(pt3[1]) + \" \" + str(pt3[2]) )\n";
		BigInteger [] res = Utils.runSageArr(sSage);
		return res;
	}

	/** Generate a pseudo-random valid point (some power of the base point) */
	public BigInteger [] getRandomPoint(int n){
		//1. simply dummy pseudo random function on n
		BigInteger p1 = Utils.itobi(13729107);
		BigInteger p2 = Utils.itobi(37201933);
		BigInteger x = Utils.itobi(n).multiply(p1).add(p2).mod(this.subgroup_order);	

		//2. base point raise to x power
		BigInteger baseY = this.computeYCoordinate(this.baseX);
		BigInteger [] res = this.pointMul(this.baseX, baseY, x);
		return res;
	} 

	/** Generate a random exponent suitable for point multiplication.
		if bDH is true, make sure that the exponent is good for
		Diffie-Hellman exchange (masking least 3 significant bit and
		set most significant bit, "n" uniquely decide the
		pseudo-random point */
	public BigInteger getRandomExponent(int n, boolean bDH){
		//1. simply dummy pseudo random function on n
		BigInteger p1 = this.subgroup_order.subtract(Utils.itobi(7));
		BigInteger p2 = Utils.itobi(37201933);
		BigInteger x = Utils.itobi(n).multiply(p1).add(p2).mod(this.subgroup_order);	
		
		//2. if needed for diffie-hellman apply the bit-masking tool
		if(bDH){
			x = x.setBit(this.input_width-1);
			x = x.clearBit(0);
			x = x.clearBit(1);
			x = x.clearBit(2);
		}

		return x;
	} 


}
