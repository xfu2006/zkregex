/*******************************************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 10/11/2021
Revised: 10/14/2021. Based on LePowGadget
 *******************************************************************************/
/** **************************************************
This is a Pow of 2048-bit exponentiation operation.
In constructor, one can specify the bits of exponents.
* ***************************************************/
package za_interface.za.circs.basicops;

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

import za_interface.za.ZaCirc;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.Utils;
import za_interface.gadgets.basics.LEPowGadget;


/**
 * Perform calculation: g^x mod r (g and r are already fixed):
 * Constructor: takes "bits" as the exponent bits.
 * The input "x" will be mod with 2^bits.
 */
public class ZaPow extends ZaCirc{
	/* Data Members */
	//the bits of x
	private int x_bits;
	//base g
	private BigInteger g;
	//modulus r, expected result is g^x mod r
	private BigInteger r;
	protected static final int BITS = 2048;
	protected static final int UNIT = LongElement.CHUNK_BITWIDTH;

	/* constructor.  */
	public ZaPow(ZaConfig config_in, ZaGenerator zg,
		int exp_bitwidth){
		super(config_in, "ZaPow_" + exp_bitwidth, zg);
		this.x_bits = exp_bitwidth;

		//2. set up the g and r for Pow exponent
		String s1 = "30dac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		String s2 = "203ac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		g = new BigInteger(s1, 16);
		r = new BigInteger(s2, 16);
		LEPowGadget.setup(new BigInteger(s1, 16), new BigInteger(s2, 16), 2048);

	}


	/* NO public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/* x_bits/CHUNK SIZE  + 1 (for all inputs < 2^64, will be 1)*/
	public int getNumWitnessInputs(){
		return this.x_bits/UNIT + 1;
	}
	
	/* 2048bits/CHUNK SIZE */
	public int getNumOutputs(){ 
		return BITS/UNIT;
	}

	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. merge input into LongElement
		int [] cb1= new int [getNumWitnessInputs()]; 
		for(int i=0; i<cb1.length; i++){
			cb1[i] = UNIT;
		}
		LongElement x = new LongElement(arrWitness, cb1);

		//3. build two long elements
		LEPowGadget leg = new LEPowGadget(this.x_bits, x);
		Wire [] wout = leg.getOutputWires();
		return wout;	
	}

	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger x = Util.group(arrWitness, UNIT);
		BigInteger r1 = g.modPow(x, r);
		BigInteger [] res = Util.split(r1, BITS/UNIT, UNIT);
		return res;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	public BigInteger[][] genRandomInput(int n){
		BigInteger x = Utils.randbi(this.x_bits, 0, n);
		BigInteger [] arrX = Util.split(x, this.getNumWitnessInputs(), UNIT);
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			arrX
		};
		return ret;
	}

}
