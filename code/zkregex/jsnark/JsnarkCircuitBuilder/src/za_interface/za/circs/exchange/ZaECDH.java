/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/02/2021
Modified: 05/11/2021 -> use the Curve25519 class
* ***************************************************/

/** **************************************************
This is essentially adapted from
ECDiffieHellman coming with the JSnark.
We refactored the code so that it can use any elliptic curve
and works with a variety of prime order fields.
* ***************************************************/
package za_interface.za.circs.exchange;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import examples.gadgets.diffieHellmanKeyExchange.ECDHKeyExchangeGadget;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.curve.*;
import util.Util;

/**
 Elliptic Curve DiffieHellman Key Exchange. Note: this class
is parameterized by the curve (given the prime field). 
DiffieHellman exchange: both party agreens with curve base point Base
  own party:  secret s
  other party: secret t
  To generate common secret: 
	other party sends H = Base^t
	own party computes: H^s which is essentially Base^(t*s)
	Assumption: using variations of Curve25519 s.t. 
		y^2 = x^3 + A*x^2 + x
Input: hX (the x-coordinate of the H sent by the other party),
secret s of the own party
Output: the x-coordinate of the Base^(t*s), i.e., the x-coordinate
of the shared input.

  Note: the supported exponent (t,s), based on curve, is slightly
restricted (e.g., 251- or 253- bit based on the prime field supported
by the curve). See Curve.input_width.
*/
public class ZaECDH extends ZaCirc{
	// ** Data **
	/** the curve depends on the prime field in config */
	protected Curve curve; 

	// ** Operations **
	public ZaECDH(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "ECDH", zg);
		this.curve = Curve.createCurve(config_in);
	
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** hX (the x-coordinate of the public component of the other party),
	and s the secret. Assumption: s has to be a valid input supported
    by curve multiplication (see Curve.input_width) */
	public int getNumWitnessInputs(){
		return 2;
	}

	/** return shared secret (the x-coordinate of the computed point) */
	public int getNumOutputs(){ 
		return 1;
	}

	/** Logicla eval for unit testing
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger hX = arrWitness[0];
		BigInteger s = arrWitness[1];
		BigInteger hY = curve.computeYCoordinate(hX);
		BigInteger [] res = curve.pointMul(hX, hY, s);
		return new BigInteger [] {res[0]};
	}

	/** build the circuit. Essentially doing point multiplication of
		(hX,hY)^s and take the x-coordinate*/
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaComputeY zcp = new ZaComputeY(curve, zg);
		ZaPointMul zm = new ZaPointMul(curve, zg);
		Wire hX = arrWitness[0];
		Wire s = arrWitness[1];
		Wire [] ew = new Wire [] {};
		zcp.build_circuit(ew, new Wire [] {hX});
		Wire hY = zcp.getOutputWires()[0];
		zm.build_circuit(ew, new Wire [] {hX, hY, s});
		Wire [] pt = zm.getOutputWires();	
		return new Wire [] {pt[0]};
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		More exactly arrWitness = {hX, s}.
		Here hX is a valid random point's x-coordinate and s
		is a valid exponent allowed by curve */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger [] pt = curve.getRandomPoint(n);
		BigInteger s = curve.getRandomExponent(n, true); 
		BigInteger [][] res = new BigInteger [][]{
			new BigInteger [] {},
			new BigInteger [] {pt[0], s}
		};
		return res;
	}

	
}
