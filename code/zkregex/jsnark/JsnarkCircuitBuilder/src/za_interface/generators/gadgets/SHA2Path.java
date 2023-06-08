/*******************************************************************************
s *
  Dr. CorrAuthor.
  Apply N SHA-path, simulating a Merkle tree path
  To prove that the prover knows the secret N messages
  along the sequence of N SHA2Path operations that generate
  the output
 *******************************************************************************/
package za_interface.generators.gadgets;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

public class SHA2Path extends CircuitGenerator {

	private int N = 16;
	private Wire[][] inputWires;
	private SHA256Gadget sha2Gadget;

	public SHA2Path() {
		super("SHA2Path");
	}

	@Override
	protected void buildCircuit() {
		// assuming the circuit input will be 64 bytes
		inputWires = new Wire[N][];
		for(int i=0; i<N; i++){
			inputWires[i] = new Wire[512]; //bit wire
			int size = i==0? 512: 256; //the other 256 bits
			for(int j=0; j<size; j++){
				inputWires[i][j] = createProverWitnessWire();
			}
		}
		SHA256Gadget sha2Gadget  = null;
		for(int i=0; i<N; i++){
			if(i>0){//set up the rest
				Wire [] lastOut = sha2Gadget.getOutputWires(); //256 bits
				for(int j=0; j<256; j++){
					inputWires[i][j+256] = lastOut[j];
				}
			}
			sha2Gadget = new SHA256Gadget(inputWires[i], 1, 64, true, false); //binary output
		}
		Wire[] digest = sha2Gadget.getOutputWires(); //256 of them
		makeOutputArray(digest, "digest");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		for(int k=0; k<N; k++){
			int size = k==0? 512: 256;
			for (int i = 0; i < size; i++) {
				evaluator.setWireValue(inputWires[k][i], i%2);
			}
		}
	}
}
