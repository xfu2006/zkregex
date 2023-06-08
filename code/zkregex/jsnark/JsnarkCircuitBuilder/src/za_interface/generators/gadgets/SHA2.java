/*******************************************************************************
s *
  Dr. CorrAuthor.
  Simplified from examples/generators/hash/Sha2Generator.java
  Original Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package za_interface.generators.gadgets;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

public class SHA2 extends CircuitGenerator {

	private Wire[] inputWires;
	private SHA256Gadget sha2Gadget;

	public SHA2() {
		super("SHA2");
	}

	@Override
	protected void buildCircuit() {
		// assuming the circuit input will be 64 bytes
		inputWires = createInputWireArray(64);
		// this gadget is not applying any padding.
		sha2Gadget = new SHA256Gadget(inputWires, 8, 64, false, false);
		Wire[] digest = sha2Gadget.getOutputWires();
		makeOutputArray(digest, "digest");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		for (int i = 0; i < inputWires.length; i++) {
			evaluator.setWireValue(inputWires[i], inputStr.charAt(i));
		}
	}
}
