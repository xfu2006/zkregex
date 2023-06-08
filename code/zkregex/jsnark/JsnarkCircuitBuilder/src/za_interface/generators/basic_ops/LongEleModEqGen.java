/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	Simple ModEq Generator + Eq comparison for LongElement (2048 bits)
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import circuit.auxiliary.LongElement;
import examples.gadgets.math.LongIntegerModGadget;
import java.math.BigInteger;

public class LongEleModEqGen extends CircuitGenerator {

	private Wire[] inputs;

	public LongEleModEqGen() {
		super("LongEleModEq");
	}

	protected static final int BITS = 2048;
	//protected static final int BITS = 64;
	protected static final int UNIT = LongElement.CHUNK_BITWIDTH;
	@Override
	protected void buildCircuit() {
		//1. declare input array to accomodate three long elements.
		//3.g., when BITS = 2048, each long element (2048 bits)
		// has 2048/32 = 64 segments (each segment 32 bits)
		//Thus need 64*3 = 192 input wires (to accomodate 3 long elements)
		inputs = createInputWireArray(BITS/UNIT*3); 
		Wire [] w1 = new Wire [BITS/UNIT];
		Wire [] w2 = new Wire [BITS/UNIT];
		Wire [] w3 = new Wire [BITS/UNIT]; //sum of w1 and w2
		int [] cb1= new int [BITS/UNIT]; //note needs separate copies
		int [] cb2= new int [BITS/UNIT];
		int [] cb3= new int [BITS/UNIT];
		for(int i=0; i<BITS/UNIT; i++){
			w1[i] = inputs[i];
			w2[i] = inputs[i+BITS/UNIT];
			w3[i] = inputs[i+BITS/UNIT*2];
			cb1[i] = UNIT;
			cb2[i] = UNIT;
			cb3[i] = UNIT;
		}

		//2. build two long elements
		LongElement l1 = new LongElement(w1, cb1);
		LongElement l2 = new LongElement(w2, cb2);
		LongIntegerModGadget g3 = new LongIntegerModGadget(l1, l2, true);	
		LongElement l3 = new LongElement(w3, cb3);
		LongElement l3_2 = g3.getRemainder();
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
		String s1 = "511589bead28bd863406f8b6e6d6c8325e2975e4fe406dfd70bbfc8bb933b1a78049c44dcdfaf9576adef01f2513800150e79c658cde983652e15cd6f479d65ae2cff77fc83ef61daf40fc7865e29872802eda5019d64bda17f060e8b5284bc2a31e4fbd04562f656b33c15d4fae5454ddfc6e2c1c8d7ef8f160ae79202870156fd8259c4e55075548c9f0298114160651c322a71fdf55ba46d5c21753976a4bbf13b4b22318f4f70c3d8380bc132ece85f85a117b00da6e2bce05b3f54692347c99eed6aa8df24fc0cf650384bbb8344363f624f11a7364f9400a428956155ae821b862d7afd3a5fcbc18f420502048a97d384d87868fbb27dc0896d0192796";//2048 bit
		String s2 = "203ac4df56945ec31a037c5b736b64192f14baf27f2036feb85dfe45dc99d8d3c024e226e6fd7cabb56f780f9289c000a873ce32c66f4c1b2970ae6b7a3ceb2d7167fbbfe41f7b0ed7a07e3c32f14c3940176d280ceb25ed0bf830745a9425e1518f27de822b17b2b599e0aea7d72a2a6efe37160e46bf7c78b0573c9014380ab7ec12ce272a83aaa464f814c08a0b0328e191538fefaadd236ae10ba9cbb525df89da59118c7a7b861ec1c05e09976742fc2d08bd806d3715e702d9faa3491a3e4cf76b5546f927e067b281c25ddc1a21b1fb12788d39b27ca0052144ab0aad7410dc316bd7e9d2fe5e0c7a1028102454be9c26c3c347dd93ee044b680c"; //2048 bit
		String s3 = "f80d804199a96ade1b387d7c3eeee71eb8d7822ef01de002c1e10b47862ce2c398474eb90d821ba4f6edfa68800e91bbbcc591a891b2140cb57b98361a4a0379fe945a12ef319104bc28cacfe719c0baa86ce4e1880d8ca6b698b6302f1e5810b2c3e952b97a6496f5588968854fa9d48afd484cbac1872f21057a24213a09eef50bf5616f3539196f4b3ab0b4fcfc29d9c888a1cba4c8217888edb574045d09169fc6dacb616925488f8be4772113791f934d8282a0ce8c5cc75b21403c18b2684179412ecc94422b10730bbbe594c8480b9e70f1409ad293a95e751cf0558699b55e23178552096ca6d7885a4727569ce15175e071978c2b2e686aefa"; //2048 bit
		LongEleUtil.setLongInputWires(evaluator, inputs, 0, s1, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT, s2, BITS);
		LongEleUtil.setLongInputWires(evaluator, inputs, BITS/UNIT*2, s3, BITS);
	  }catch(Exception exc){
		System.err.println(exc);
		System.exit(100);
	  }
	}

}
