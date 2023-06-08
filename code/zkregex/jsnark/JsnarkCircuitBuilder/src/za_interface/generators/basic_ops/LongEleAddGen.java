/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	Simple Add Generator + Equality Comparison for LongElement (2048 bits)
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import circuit.auxiliary.LongElement;
import java.math.BigInteger;

public class LongEleAddGen extends CircuitGenerator {

	private Wire[] inputs;

	public LongEleAddGen() {
		super("LongEleAdd");
	}

	protected static final int BITS = 2048;
	//protected static final int BITS = 64;
	protected static final int UNIT = LongElement.CHUNK_BITWIDTH;
	@Override
	protected void buildCircuit() {
		//1. declare input array to accomodate two long elements.
		//3.g., when BITS = 2048, each long element (2048 bits)
		// has 2048/32 = 64 segments (each segment 32 bits)
		//Thus need 64*2 = 128 input wires (to accomodate 2 long elements)
		inputs = createInputWireArray(BITS/UNIT*2); 
		Wire [] w1 = new Wire [BITS/UNIT];
		Wire [] w2 = new Wire [BITS/UNIT];
		int [] cb1= new int [BITS/UNIT]; //note needs separate copies
		int [] cb2= new int [BITS/UNIT];
		for(int i=0; i<BITS/UNIT; i++){
			w1[i] = inputs[i];
			w2[i] = inputs[i+BITS/UNIT];
			cb1[i] = UNIT;
			cb2[i] = UNIT;
		}

		//2. build two long elements
		LongElement l1 = new LongElement(w1, cb1);
		LongElement l2 = new LongElement(w2, cb2);
		LongElement l3 = l1.add(l2);

		//3. get output bits
		Wire []wout = l3.getArray();	
		for(int i=0; i<wout.length; i++){
			makeOutput(wout[i]);
		}
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
	  try{
		//64-bit version
		//String s1 = "12341234FABBCCDD";
		//String s2 = "CCCCDDDD1122CCDD";
		//2048 bit version
		String s1 = "30dac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		String s2 = "203ac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c93cb"; //2048 bit
		LongEleUtil.setLongInputWires(evaluator, inputs, 0, s1, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT, s2, BITS);
	  }catch(Exception exc){
		System.err.println(exc);
		System.exit(100);
	  }
	}

}
