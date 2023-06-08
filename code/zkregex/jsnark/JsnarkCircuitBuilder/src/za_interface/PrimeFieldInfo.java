/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
  This class defines a number of SUPPORTED prime field platforms
* *************************************************************/
package za_interface;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;
import java.io.Serializable;

public class PrimeFieldInfo implements Serializable{
	public String name;
	public BigInteger order;
	
	public PrimeFieldInfo(String name, BigInteger order){
		this.name = name;
		this.order = order;
	}

	// --------- A NUMBER OF PUBLIC AVAILABLE GLOBAL VARS
	public final static PrimeFieldInfo LIBSNARK = new PrimeFieldInfo("LIBSNARK", new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")); //the default ec_pp's prime order (bn128)
	public final static PrimeFieldInfo LIBSPARTAN = new PrimeFieldInfo("SPARTAN", new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")); //curve 25519
	public final static PrimeFieldInfo AURORA = new PrimeFieldInfo("AURORA", new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")); //curve alt_bn128  Fr
	public final static PrimeFieldInfo Bls381= new PrimeFieldInfo("Bls381", new BigInteger("52435875175126190479447740508185965837690552500527637822603658699938581184513")); //Bls12-381 (255-bit Fr order)
}

