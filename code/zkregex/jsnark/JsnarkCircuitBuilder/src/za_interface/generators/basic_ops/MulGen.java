/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	Simple Multiplication Generator for ONE multplication
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;

public class MulGen extends CircuitGenerator {

	private Wire[] inputs;
	private Wire[] witness;

	public MulGen() {
		super("Mul");
	}

	@Override
	protected void buildCircuit() {
		inputs = createInputWireArray(1);
		witness = new Wire [1];
		witness[0] = createProverWitnessWire("w1");
		Wire r1 = inputs[0].mul(witness[0]);
		makeOutput(r1);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		for (int i = 0; i < 1; i++) {
			circuitEvaluator.setWireValue(inputs[i], (i+101));
			circuitEvaluator.setWireValue(witness[i], (i+102));
		}
	}

}
