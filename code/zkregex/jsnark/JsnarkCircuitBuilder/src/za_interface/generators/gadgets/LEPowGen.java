/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	2048 bit base and modulus, exponent is the GIVEN bit
    This is a template class for Pow16 and Pow32 and other 
	gadgets for convenience
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import circuit.auxiliary.LongElement;
import java.math.BigInteger;
import za_interface.gadgets.basics.*;

public class LEPowGen extends CircuitGenerator {

	//inputs: two LongElement: one for x and one for expected res
	private Wire[] inputs; 
	//the bits of x
	private int x_bits;
	//base g
	private BigInteger g;
	//modulus r, expected result is g^x mod r
	private BigInteger r;


	//sname is used by Pow16, Pow32, ...
	public LEPowGen(String sname, int x_bits_inp) {
		super(sname);
		this.x_bits = x_bits_inp;
	}

	protected static final int BITS = 2048;
	protected static final int UNIT = LongElement.CHUNK_BITWIDTH;

	@Override
	protected void buildCircuit() {
		//1. declare input array to accomodate TWO long elements.
		// The first is the exponent and the second is the EXPECTED output.
		inputs = createInputWireArray(2*BITS/UNIT); 
		Wire [] w1 = new Wire [BITS/UNIT];
		Wire [] w2 = new Wire [BITS/UNIT];
		int [] cb1= new int [BITS/UNIT]; 
		int [] cb2= new int [BITS/UNIT]; 
		int [] cb3= new int [BITS/UNIT]; 
		for(int i=0; i<cb1.length; i++){
			w1[i] = inputs[i];
			w2[i] = inputs[i+BITS/UNIT];
			cb1[i] = UNIT;
			cb2[i] = UNIT;
			cb3[i] = UNIT;
		}
		LongElement x = new LongElement(w1, cb1);
		LongElement expRes = new LongElement(w2, cb2);

		//2. set up the g and r for Pow exponent
		String s1 = "30dac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		String s2 = "203ac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		g = new BigInteger(s1, 16);
		r = new BigInteger(s2, 16);
		LEPowGadget.setup(new BigInteger(s1, 16), new BigInteger(s2, 16), 2048);

		//3. build two long elements
		LEPowGadget leg = new LEPowGadget(this.x_bits, x);
		Wire [] wout = leg.getOutputWires();
		LongElement lout = new LongElement(wout, cb3);
		lout.assertEquality(expRes);
		
		//3. get output bits
		for(int i=0; i<wout.length; i++){
			makeOutput(wout[i]);
		}
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
	  try{
		//1. calculate the x value
		String sx_template = "511589bead28bd863406f8b6e6d6c8325e2975e4fe406dfd70bbfc8bb933b1a78049c44dcdfaf9576adef01f2513800150e79c658cde983652e15cd6f479d65ae2cff77fc83ef61daf40fc7865e29872802eda5019d64bda17f060e8b5284bc2a31e4fbd04562f656b33c15d4fae5454ddfc6e2c1c8d7ef8f160ae79202870156fd8259c4e55075548c9f0298114160651c322a71fdf55ba46d5c21753976a4bbf13b4b22318f4f70c3d8380bc132ece85f85a117b00da6e2bce05b3f54692347c99eed6aa8df24fc0cf650384bbb8344363f624f11a7364f9400a428956155ae821b862d7afd3a5fcbc18f420502048a97d384d87868fbb27dc0896d0192796";//2048 bit
		BigInteger sx_wide = new BigInteger(sx_template, 16);
		BigInteger pow2 = new BigInteger("2");
		pow2 = pow2.pow(this.x_bits);
		BigInteger x = sx_wide.mod(pow2);
		BigInteger expRes = g.modPow(x, r);

		//2. calculate the expected value
		LongEleUtil.setLongInputWires(evaluator, inputs, 0, x, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT, expRes, BITS);
	  }catch(Exception exc){
		System.err.println(exc);
		System.exit(100);
	  }
	}

}
