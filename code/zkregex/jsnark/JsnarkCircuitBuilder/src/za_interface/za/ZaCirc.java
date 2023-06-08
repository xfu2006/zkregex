/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/17/2021

Refined: 12/29/2022 -> Added Connector Points for Modular Verification
* ***************************************************/

/** **************************************************
This is the basic class for all Arithmetic Circuits
related to zero audit (r1cs version).
All circuits are DETERMINISTIC. That is, given
the input, the output is determined.
Each is required to provide an eval() function
for unit testing purpose.

** All arithmetic will be DETERMINED on the FIELD_ORDER
of the config class  **
* ***************************************************/

package za_interface.za;
import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.CircuitGenerator;
import circuit.eval.CircuitEvaluator;
import java.io.Serializable;
/*
import java.util.Arrays;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.eval.Instruction;
import circuit.structure.ConstantWire;
import examples.gadgets.math.LongIntegerModGadget;
*/

import circuit.operations.Gadget;

/**
  Base class of all circuits (gadgets) related to zero_audit
*/
public abstract class ZaCirc extends Gadget implements Serializable{
	// ** Data Members **
	/* needs to be set in constructor */
	protected ZaConfig config; 
	/* A circ is only evaluated ONCE due to wiring problem. */ 
	protected boolean bEvaluated = false;
	/* A circ can only be built once */
	protected boolean bBuilt = false;
	/* Circuit name */
	protected String name;
	/* output wires, to be set by build_circuit */
	protected Wire [] outwires;

	/* connecting points for modular verification */
	protected int [] connector_wire_ids; //can be null

	// ** Operations **

	public int [] get_connector_wire_ids(){
		return connector_wire_ids;
	}

	public void set_connector_wire_ids(int [] inp_ids){
		this.connector_wire_ids = inp_ids;
	}

	/** needs the config to determine prime field size ,
		NOTE will reset the base protected field generator
		regardless.
	*/
	public ZaCirc(ZaConfig config_in, String name, ZaGenerator zg){
		this.config = config_in;
		this.name = name;
		if(zg==null){
			zg = new ZaGenerator();
			zg.onetimeSetCirc(this);
		}
		this.generator = zg;
	}

	/** ONLY call it in genvars_fast. DO NOT CALL IT ANYWHERE ELSE! */ 
	public void force_setGenerator(ZaGenerator zg){
		this.generator = zg;
	}

	//defualt constructor for Serializable
	public ZaCirc(){
	}

	/** regurn the generator */
	public ZaGenerator getGenerator(){
		return (ZaGenerator) this.generator;
	}

	/** return the config */
	public ZaConfig getConfig(){
		return this.config;
	}

	@Override
	public Wire [] getOutputWires(){
		return outwires;
	}

	/** return the circuit name */
	public String getName(){
		return this.name;	
	}

	/** Deterministic evaluation. Note all randoms should be
		assed as arrWitness and this should be addressed in
		circuit design. The evaluation is done through
		system evaluator. Wires will be assigned with IDs,
		and the circuit can NOT be re-used in integration
		with other circs, or another evaluation. Should
		be called ONLY ONCE.
	*/
	public BigInteger [] eval(BigInteger [] arrPublic, 
	BigInteger [] arrWitness){
		if(bEvaluated){ Utils.fail("eval() can only be called once!"); }
		this.bEvaluated = true;
		//1. create the circuit generator
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		CircuitGenerator.setActiveCircuitGenerator(zg);
		zg.setPresetInputs(arrPublic, arrWitness);

		//2. reset the field order from config
		this.config.apply_config();

		//3. run the eval
		zg.generateCircuit();
		zg.evalCircuit();

		//4. collect values
		Wire [] arrOutWires = this.getOutputWires();
		BigInteger [] arrOut = new BigInteger[arrOutWires.length];
		CircuitEvaluator ev = zg.getCircuitEvaluator();
		for(int i=0; i<arrOutWires.length; i++){
			arrOut[i] = ev.getWireValue(arrOutWires[i]);
		}	

		return arrOut;
	}

	/* if build_circuit_worker is directly called, should
		call it */
	public void check_generator(){
		//1. do the polymoric call of _worker
		//FIX generator
		ZaGenerator azg = (ZaGenerator) CircuitGenerator.getActiveCircuitGenerator();
		if(azg==null) throw new RuntimeException("Active Circuit Generator is null!");
		if(this.generator!=azg){
			System.out.println("WARNING: this generator not equal to active generator. Reset it: " + this);
			this.generator = azg;
		}
	}

	/** A wrapper function, which performs the check of inputs
		and then call the build_circuit_worker function, which
		performs the real building circuit operation.

		This operation can be only called once.
	*/
	public void build_circuit(Wire [] arrPubInput, 
			Wire [] arrWitnessInput){
		//0. inputs check
		if(bBuilt) Utils.fail("ZaCirc can only be built once!");
		this.bBuilt = true;
		if(arrPubInput.length!=this.getNumPublicInputs()){
			Utils.fail("arrPubInput.length: " + arrPubInput.length + " does not match getNumPublicInputs(): "  + this.getNumPublicInputs());
		}
		if(arrWitnessInput.length!=this.getNumWitnessInputs()){
			Utils.fail("arrWitnessInput.length: " + arrWitnessInput.length + " does not match getNumWitnessInputs(): "  + this.getNumWitnessInputs());
		}
		this.check_generator();
		this.outwires = this.build_circuit_worker(arrPubInput, arrWitnessInput);

	}

	//** ABSTRACT operations to be overriden **
	/** return the number of public input wires */
	abstract public int getNumPublicInputs();
	/** return the number of witness/private input wires */
	abstract public int getNumWitnessInputs();
	/** return the number of output wires */
	abstract public int getNumOutputs(); 
	/** "logically" evaluate the input, without
		calling the eval() on the internal wires. Used
		for unit_testing purpose, e.g., to call the real sha256()
		and compare the result with the circuilt eval results.
		The number of input/witness/output should be
		consistent with the getNum() series.
	
		Note: unlike the eval() function which needs to
		assign values to internal wires, this function can be
		called many times. The result should be consistent
		with eval()l
	*/
	abstract public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness);

	/** build the circuit. Needs to supply the input wires, and
		return the array of outputwires */
	abstract public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness);
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions */ 
	abstract public BigInteger[][] genRandomInput(int n);
		
}
