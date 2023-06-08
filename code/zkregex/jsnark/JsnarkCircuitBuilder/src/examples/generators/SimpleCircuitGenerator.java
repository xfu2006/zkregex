/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/

/* ************
  Modified by CorrAuthor
*/
package examples.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;

public class SimpleCircuitGenerator extends CircuitGenerator {

	private Wire[] inputs;

	public SimpleCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		// declare input array of length 2.
		inputs = createInputWireArray(3);

		WireArray wa = new WireArray(inputs);
		Wire r1 = wa.packAsBits();

		// mark the wire as output
		makeOutput(r1);

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		for (int i = 0; i < 3; i++) {
			circuitEvaluator.setWireValue(inputs[i], (i+1)%2);
		}
	}

	public static void resetFieldOrder(BigInteger new_field_order){
		Config.FIELD_PRIME= new_field_order;
		Config.LOG2_FIELD_PRIME = Config.FIELD_PRIME.toString(2).length();
		System.out.println("RESET field order to " + Config.FIELD_PRIME);
	}

	public static void main(String[] args) throws Exception {
		resetFieldOrder(new BigInteger("17"));
		SimpleCircuitGenerator generator = new SimpleCircuitGenerator("simple_example");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
		System.out.println("============ R1CS Generated! ==========\n");
	}

}
