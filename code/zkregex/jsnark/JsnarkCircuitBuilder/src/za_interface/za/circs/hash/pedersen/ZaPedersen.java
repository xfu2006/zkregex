/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/10/202
* ***************************************************/

/** **************************************************
This implements Pedersen hash (using Pedersen commit
as a hash). Given a curve setting (see za_interface/za/circ/curves/Curve.java),
it applies Pedersen commitment g^x h^r where x is the
number fo commit to and r is a random nonce generated at run time.
Notice that x must be in the range of curve.input_bits (e.g.,
for the curve25519 customized for libsnark, this is about 
253 bits and for the curve25519 customized for spartan this is about
251 bits.

*** note if the "x" and "r" are out of range, the "x%2^input_bits"
will be applied ***

*** Implemented by calling PedersonHashFull
* ***************************************************/
package za_interface.za.circs.hash.pedersen;

import java.math.BigInteger;
import java.util.HashMap;
import circuit.structure.Wire;
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
Output: ONLY x-coordinate of g^x h^y (for the full point use ZaPedersenFull)
*/

public class ZaPedersen extends ZaHash2{
	// *** Data Members ***
	protected ZaPedersenFull full;
	protected Curve curve;

	// ** Operations **
	public ZaPedersen(ZaConfig config_in, ZaGenerator zg){
		//1. set up curve
		super(config_in, "Pedersen", zg);
		this.curve = Curve.createCurve(config_in);
		this.full = new ZaPedersenFull(config_in, zg);
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
	/** check if x is a valid element that could be hashed */
	public boolean isValidElement(BigInteger x){
		BigInteger order = this.curve.subgroup_order;
		return x.compareTo(order)>=0;
	}

	/** logical operation. Generate point g^x h^r, and 
	return its x-coordinate */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] arr = this.full.logical_eval(arrPubInput, arrWitness);
		return new BigInteger [] {arr[0]};
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		this.full.check_generator();
		Wire [] res = this.full.build_circuit_worker(arrPubInput, arrWitness);
		return new Wire [] {res[0]}; //only the x-coord
	}

	/** Overrwrite ZaHash's random function to limit the exponent in range */
	@Override
	public BigInteger[][] genRandomInput(int n){
		return this.full.genRandomInput(n);
	}

}
