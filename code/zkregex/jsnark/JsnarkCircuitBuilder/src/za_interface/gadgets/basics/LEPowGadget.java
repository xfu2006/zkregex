/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/
package za_interface.gadgets.basics;

import java.math.BigInteger;
import java.util.Arrays;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.ConstantWire;
import examples.gadgets.math.LongIntegerModGadget;

/**
 * This gadget provides operation of g^x mod r
 * It constructs a circuit which takes x as an n-bit input, and caclualtes
 * g^x mod r.
 * Note that this is a TEMPLATE class for POW16, POW64, POW2048.
 * where g is a prefixed STATIC base, which can be reset by calling
 * reset base. "x" is treated as a n-bit integer, where the n is
 * provided in the constructor. 
 * Here: g and r are STATIC (can be reset). the bitwidth of exponent
 * is prefixed. 
 * If needs to support LARGER exponent, change BIT_LIMIT (the upper limit of
 * the bitwidth of exponent ).
 */
public class LEPowGadget extends Gadget {
	//STATIC members that needs to be set
	protected static BigInteger g; //base
	protected static BigInteger r; //modulus
	protected static int BIT_LIMIT = 3072; //if needed, change it
	protected static int G_BITS = 2048; //the bitwidth of g and r
	protected static BigInteger [] arrGPow; //array of g^2^i mod r of BIT_LIMIT elements, g^1, g^2, g^4, g^8, g^16, g^32, g^64, .... mod r.

	//INSTANCE data members
	protected int n; //bit-width of x (<= BIT_LIMIT and also <=G_BITS)
	protected LongElement x; //the exponent for g^x mod r (input)
	protected LongElement res; //the result g^x mod r
	LongElement leR; //remainder, will be set in buildcircuit
	LongElement [] arrLeGPow; //correspoding to arrGPow
	

	// --- STATIC OPERATIONS FOR SET UP
	/**
		Set up the static members base: g and modulus r. All instances
	will use the same setting for building up the circuit.
	*/
	public static void setup(BigInteger gInput, BigInteger rInput, int g_bits){
		if(!isPowOfTwo(g_bits)){
			System.err.println("g_bits should be power of 2");
			System.exit(400);
		}
		g = gInput;
		r = rInput;
		G_BITS = g_bits;
		arrGPow = new BigInteger[BIT_LIMIT];
		arrGPow[0] = g.mod(r);
		for(int i=1; i<arrGPow.length; i++){
			arrGPow[i] = arrGPow[i-1].multiply(arrGPow[i-1]).mod(r); 
		} 	
	}

	/** return true if n is a power of 2 */
	private static boolean isPowOfTwo(int n){
		if(n==0) return false;
		while(n!=1){
			if(n%2==1) return false;
			n = n/2;
		}
		return true;
	}

	/** return log2, assumption n is already power of 2 */
	private static int log2(int n){
		int x = 0;
		while(n>1){
			x = x + 1;
			n = n/2;
		}
		return x;
	}


	/* constructor. Treat exponent (input) x as a exp_bitwidth integer.
		For convenience of implement, we require exp_bitwidth to be
		a power of 2
	*/
	public LEPowGadget(int exp_bitwidth, LongElement x){
		if(!isPowOfTwo(exp_bitwidth)){
			System.err.println("Expecting exp_bitwidth power of 2!");
			System.exit(300);
		}
		if(g==null || r==null){
			System.err.println("LEPowGadget error: g and r not set yet! Call static function setup() first.");
			System.exit(200);
		}
		this.n = exp_bitwidth;
		this.x = x;
		buildCircuit();
	}


	private void buildCircuit() {
		//0. split x into bitwires
		Wire [] arrx = x.getBits(n).asArray();

		//1. set up the arr of powers and remainder LongElement
		int unit = LongElement.CHUNK_BITWIDTH;
		int num_segs = G_BITS/LongElement.CHUNK_BITWIDTH;
		this.leR = new LongElement(Util.split(r, num_segs, unit));
		this.arrLeGPow = new LongElement [arrGPow.length];
		for(int i=0; i<arrLeGPow.length; i++){
			arrLeGPow[i] = new LongElement(Util.split(arrGPow[i], num_segs, unit));
		}

		//2. result is the multiproduct of
		// PRODUCT_I (g^2^i * x_i + 1-x_i)
		//2.1 build the sequence of products takes log2(n) passes
		LongElement [] arr_inputs = new LongElement[n];
		for(int i=0; i<n; i++){
			Wire not_x = arrx[i].xorBitwise(1l, 1);
			LongElement xi = new LongElement(arrx[i], 1);
			LongElement nxi = new LongElement(not_x, 1);
			LongElement arrgpi = arrLeGPow[i];
			arr_inputs[i] = arrgpi.mul(xi).add(nxi);
		}

		//2.2 use a loop to build the final result log2(n) rounds
		int rounds = log2(n);
		for(int round=0; round<rounds; round++){
			LongElement [] arr_out = new LongElement[arr_inputs.length/2];
			for(int i=0; i<arr_out.length; i++){
				LongElement leTemp = arr_inputs[i].mul(
					arr_inputs[i+arr_out.length]);
				LongIntegerModGadget lm = new LongIntegerModGadget(
					leTemp, leR, true);	
				arr_out[i] = lm.getRemainder();
			}
			arr_inputs = new LongElement[arr_out.length];
			for(int i=0; i<arr_out.length; i++){
				arr_inputs[i] = arr_out[i];
			}
		}

		//3. set up
		this.res = arr_inputs[0];
	}

	@Override
	public Wire[] getOutputWires() {
		return this.res.getArray();
	}


}
