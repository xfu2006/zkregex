/*******************************************************************************
 * Author: CorrAuthor
 *******************************************************************************/


/*************************************************************
	Simple Zerop Generator (to test if
   a number is non-zero)
* *************************************************************/
package za_interface.generators.basic_ops;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;

public class ZeropGen extends CircuitGenerator {

	private Wire[] inputs;
	private Wire[] witness;

	public ZeropGen() {
		super("Zerop");
	}

	@Override
	protected void buildCircuit() {
		inputs = createInputWireArray(1);
		Wire r1 = inputs[0].checkNonZero();
		makeOutput(r1);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		for (int i = 0; i < 1; i++) {
			circuitEvaluator.setWireValue(inputs[i], (i+101));
		}
	}

}
