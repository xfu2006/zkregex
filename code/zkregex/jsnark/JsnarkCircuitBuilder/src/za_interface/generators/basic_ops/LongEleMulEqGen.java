/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	Simple Mul Generator for LongElement (2048 bits)
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import circuit.auxiliary.LongElement;
import java.math.BigInteger;

public class LongEleMulEqGen extends CircuitGenerator {

	private Wire[] inputs;

	public LongEleMulEqGen() {
		super("LongEleMulEq");
	}

	protected static final int BITS = 2048;
	//protected static final int BITS = 64;
	protected static final int UNIT = LongElement.CHUNK_BITWIDTH;
	@Override
	protected void buildCircuit() {
		//1. declare input array to accomodate three long elements.
		//3.g., when BITS = 2048, each long element (2048 bits)
		// has 2048/32 = 64 segments (each segment 32 bits)
		//Thus need 64*4 = 256 input wires (to accomodate 3 long elements)
		// THIS IS BECAUSE THE PRODUCT TAKES TWICE THE SPACE!!!
		inputs = createInputWireArray(BITS/UNIT*4); 
		Wire [] w1 = new Wire [BITS/UNIT];
		Wire [] w2 = new Wire [BITS/UNIT];
		Wire [] w3 = new Wire [BITS/UNIT*2]; //product of w1 and w2
		int [] cb1= new int [BITS/UNIT]; //note needs separate copies
		int [] cb2= new int [BITS/UNIT];
		int [] cb3= new int [BITS/UNIT*2];
		for(int i=0; i<BITS/UNIT; i++){
			w1[i] = inputs[i];
			w2[i] = inputs[i+BITS/UNIT];
			w3[i] = inputs[i+BITS/UNIT*2];
			w3[i+BITS/UNIT] = inputs[i+BITS/UNIT*3];
			cb1[i] = UNIT;
			cb2[i] = UNIT;
			cb3[i] = UNIT;
			cb3[i+BITS/UNIT] = UNIT;
		}

		//2. build two long elements
		LongElement l1 = new LongElement(w1, cb1);
		LongElement l2 = new LongElement(w2, cb2);
		LongElement l3 = new LongElement(w3, cb3);
		LongElement l3_2 = l1.mul(l2);
		l3.assertEquality(l3_2);

		//3. get output bits
		Wire []wout = l3_2.getArray();	
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
		String s3 = "6268fbea33e74fe47590004194cf67fbecd1d8d2f68bce67cc00cd1cd10101fde96da751ebcbd825743a178088cabe6161534790637149177af9d0d4083fca7f97994d9147db63ee4158d81ebcd0bead694d2858a6719b747ffbce9e10e662415fb641041464f60c8a50c745d66dd59ff47ca900ecd9ede8ff0a0a709a680be2bc2699730db71a3052a0704ec4d6b0f7cd5d5fed19e8215e86471dbaf852d0bccef328aad96f4ed03e79a8d185aa455de3054e6f0e0dc39e506253563299e08006674cb192fd3aba671786197e9867d126dfc69dd68a41ec0dad6719f6558accb16c82624996c5c4f0eb104ad33589ed69fea4010a24a3eeb29fe1bbbd9ffa90347ece674d42de6eeef5d3d919698a218c2c24ba1f78002cf827b52281be034b64e9aee00dcebd4cca87c4b92ae0f5bae59972f1039bdc2b7960f893ac6c08b5786d7ad283b85c430aaacfa54bd0201ca8326ec964225aa856de8a44d66b303ef25eeff4c44aa0aa53b09fb913c5bba47491b199ca0683e5eccd6b84deb9280f3669961ca2debaaa7fb2843b90e3025825beebe161aa32cf156d729b39dba772dfa7b78a502b605f9a1d5974e874440350f7e19b930c2de41bccf176d2d5ca65b8d392bbe29a170e298dc10d7a689bcd58ed827d48dea9136211127e7368feae10f49a6dca66c66a036dcbe60a770ef016368b79eba211275bb29a5205ac2f9";//4096 bit
		LongEleUtil.setLongInputWires(evaluator, inputs, 0, s1, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT, s2, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT*2, s3, BITS*2);
	  }catch(Exception exc){
		System.err.println(exc);
		exc.printStackTrace();
		System.exit(100);
	  }
	}

}
