/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/19/2021
* ***************************************************/

/** ************************************************
 This is the wrapper generator of a ZaCircuit class,
used for evaluation.

Note: because of one-time wire ID assignment, it can
be ONLY used once. The gadget should only be evaluated
or integrated once. 
* ***************************************************/

package za_interface.za;
import za_interface.PrimeFieldInfo;
import java.math.BigInteger;
import circuit.structure.Wire;
import circuit.structure.CircuitGenerator;
import circuit.eval.CircuitEvaluator;
import za_interface.za.Utils;
import java.io.Serializable;

/**
  Wrapper generator of a ZaCirc object.
  Can be only used once and the ZaCirc can only be used once
*/
public class ZaGenerator extends CircuitGenerator implements Serializable{
	// *** Data Members ***
	protected ZaCirc circ;
	protected Wire [] arrPublicInputs;
	protected Wire [] arrWitnessInputs;
	protected Wire [] arrOutputs;

	public ZaCirc getCirc(){ return this.circ;}

	/* for setting the SPECIFIC input when genRandomInput()
	is called */
	public BigInteger [] presetArrPublicInputs;
	/* for setting the SPECIFIC input when genRandomInput()
	is called */
	public BigInteger [] presetArrWitnessInputs;

	// *** Operations ****
	/**
		Constructor: needs a circ as input
	*/
	public ZaGenerator(){
		super("UNKNOWN YET");
		this.circ = null; //to be set by onetimeSetCirc
	}

	/** this method can ONLY be called once. It should be called
	on the 'top/root' level ZaCirc and all subcomponents circ
	will have a generator member pointing to this ZaCirc instance */
	public void onetimeSetCirc(ZaCirc circ){
		if(this.circ!=null) throw new UnsupportedOperationException("this function should be called ONLY ONCE. circ is already set!");
		this.circ = circ;
		this.circuitName = circ.getName() + "_" + circ.getConfig().toString(); 
	}

	/** MAKE sure you know when you call it */
	public void force_onetimeSetCirc(ZaCirc circ){
		this.circ = circ;
		this.circuitName = circ.getName() + "_" + circ.getConfig().toString(); 
	}

	/**
		set the presetArrPublicInputs and presetArrWitnessInputs.
		It should be CALLED before the genRandomInput().
	*/
	public void setPresetInputs(BigInteger [] arrPubInputs, BigInteger [] arrWitnessInputs){
		this.presetArrPublicInputs = arrPubInputs;
		this.presetArrWitnessInputs = arrWitnessInputs;
	}

	/**
		build the circuit. Call circ.getNumInputs()... to 
	create the input array and set up the input/output wires
	of the circuit. The circuit is essentially a wrapper of
	the given circuit.
	*/
	@Override
	protected void buildCircuit() {
		this.arrPublicInputs = new Wire[circ.getNumPublicInputs()];	
		for(int i=0; i<arrPublicInputs.length; i++){
			this.arrPublicInputs[i] = createInputWire();
		}
		this.arrWitnessInputs = new Wire[circ.getNumWitnessInputs()];
		for(int i=0; i<arrWitnessInputs.length; i++){
			this.arrWitnessInputs[i] = createProverWitnessWire("w" +i);
		}
		this.circ.build_circuit(this.arrPublicInputs, this.arrWitnessInputs);
		this.arrOutputs = this.circ.getOutputWires();
		for(int i=0; i<this.arrOutputs.length; i++){
			makeOutput(this.arrOutputs[i]);
		}
	}
	/**
		Note: it's actually NOT random. The input is given
		in the presetInput arrays, the presetInput()
		should be called before this call */
	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		if(this.presetArrPublicInputs==null){
			BigInteger [][] rands = circ.genRandomInput(1); 
			this.presetArrPublicInputs = rands[0];
			this.presetArrWitnessInputs = rands[1]; 
		}

		//1. get the sample input 
		if(presetArrPublicInputs.length!=this.arrPublicInputs.length){
			Utils.fail("presetArrPublicInputs.length != this.arrPubInputs.length!: " + presetArrPublicInputs.length + " vs. " + arrPublicInputs.length);
		}
		if(presetArrWitnessInputs.length!=this.arrWitnessInputs.length){
			Utils.fail("presetArrWitnessInputs.length != this.arrWitnessInputs.length!: " + presetArrWitnessInputs.length + " vs. " + arrWitnessInputs.length);
		}
		//2. set up the wires	
		for(int i=0; i<presetArrPublicInputs.length; i++){
			evaluator.setWireValue(this.arrPublicInputs[i], presetArrPublicInputs[i]);
		}
		for(int i=0; i<presetArrWitnessInputs.length; i++){
			evaluator.setWireValue(this.arrWitnessInputs[i], presetArrWitnessInputs[i]);
		}
	}
}
