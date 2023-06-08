/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package circuit.structure;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;

import circuit.auxiliary.LongElement;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.WireLabelInstruction;
import circuit.operations.WireLabelInstruction.LabelType;
import circuit.operations.primitive.AssertBasicOp;
import circuit.operations.primitive.BasicOp;
import circuit.operations.primitive.MulBasicOp;
import circuit.operations.primitive.ConstMulBasicOp;

import za_interface.PrimeFieldInfo;

//Added by CorrAuthor ----------- for serialization
import java.io.Serializable;
import java.util.stream.Stream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileReader;
// -----------------------------

public abstract class CircuitGenerator implements Serializable{

	private static ConcurrentHashMap<Long, CircuitGenerator> activeCircuitGenerators = new ConcurrentHashMap<>();
	private static CircuitGenerator instance;

	protected int currentWireId;
	protected LinkedHashMap<Instruction, Instruction> evaluationQueue;

	protected Wire zeroWire;
	protected Wire oneWire;

	protected ArrayList<Wire> inWires;
	protected ArrayList<Wire> outWires;
	protected ArrayList<Wire> proverWitnessWires;

	//Added by CorrAuthor -------------
	/** the default segment ID of a witness wire. For supporting
		2-stage Groth'16 system */
	protected int DEFAULT_WITNESS_SEGMENT_ID = 0; 
	protected int num_segments = 1;
	protected int [] segment_size;
	//Added by CorrAuthor ------------- ABOVE

	//Added by CorrAuthor 01/18/2023
	// --maps from wireid to arrWitness location (index) 
	protected HashMap<Integer,Integer> wireid_2_position = new HashMap<>();
	//-----------------Added by CorrAuthor Above --

	protected String circuitName;

	protected HashMap<BigInteger, Wire> knownConstantWires;

	private int numOfConstraints;
	private CircuitEvaluator circuitEvaluator;

	// ----- Added by CorrAuthor ------------
	public CircuitGenerator(){
		this.circuitName = "Unknown";
	}
	public void setDefaultWitnessSegmentID(int id){
		this.DEFAULT_WITNESS_SEGMENT_ID = id;
	}
	public void setSegments(int segs){
		this.num_segments = segs;
	}
	public int getDefaultWitnessSegmentID(){
		return this.DEFAULT_WITNESS_SEGMENT_ID;
	}
	/** set the values of segment_size for each segment,
		and REARRANGE witness wires's order by segments  */
	public void setupSegments(){
		//1. collect the segement size
		System.out.println("DEBUG USE 333330: num_segments: " + num_segments);
		segment_size = new int [num_segments];
		for(int i=0; i<this.num_segments; i++) segment_size[i] = 0;
		for(Wire witwire: this.proverWitnessWires){
			int segid = witwire.segment_id;
			this.segment_size[segid] += 1;
		}
		int [] seg_idx = new int [num_segments];
		seg_idx[0] = 0;
		int total = 0;
		for(int i=1; i<this.num_segments; i++){
			seg_idx[i] = seg_idx[i-1] + segment_size[i-1];
			total += segment_size[i-1];
		} 
		this.segment_size[num_segments-1] = currentWireId - total - 
			this.inWires.size()- this.outWires.size();
		for(int i=0; i<num_segments; i++){
			System.out.println("DEBUG USE 101: seg " + i + " size: " + 
				segment_size[i] + ", idx: " + seg_idx[i]);
		}

		//System.out.println("DEBUG USE 104: BEFORE re-arrange");
		int idx = 0;
		for(Wire witwire: this.proverWitnessWires){
			//System.out.println("WITNESS " + idx + ": " + witwire);
			idx++;
		}
		//2. re-arrange the wires
		ArrayList<Wire> new_wits = new ArrayList<Wire>();
		for(int i=0; i<proverWitnessWires.size(); i++){
			new_wits.add(proverWitnessWires.get(0)); //will be reset later
		}
		for(Wire witwire: this.proverWitnessWires){
			int segid = witwire.segment_id;
			new_wits.set(seg_idx[segid], witwire);
			seg_idx[segid] += 1;
		}
		
		//System.out.println("DEBUG USE 105: AFTER re-arrange");
		//3. switch
		this.proverWitnessWires = new_wits;
		idx = 0;
		for(Wire witwire: this.proverWitnessWires){
			//System.out.println("WITNESS " + idx + ": " + witwire);
			idx++;
		}
		//throw new RuntimeException("STOP HERE 5001");

		//4. set up the map information
		for(int i=0; i<proverWitnessWires.size(); i++){
			int wireid = proverWitnessWires.get(i).wireId;
			wireid_2_position.put(wireid, i);
		}
	}
	// ----- Added by CorrAuthor ------------ ABOVE

	public CircuitGenerator(String circuitName) {

		this.circuitName = circuitName;

		//COMMENTED OUT BY CorrAuthor - call setActiveCircuitGenerator
		//instance = this;
		//-------ABOVE COMMENTED OUT BY CorrAuthor ----------

		inWires = new ArrayList<Wire>();
		outWires = new ArrayList<Wire>();
		proverWitnessWires = new ArrayList<Wire>();
		evaluationQueue = new LinkedHashMap<Instruction, Instruction>();
		knownConstantWires = new HashMap<BigInteger, Wire>();
		currentWireId = 0;
		numOfConstraints = 0;

		if (Config.runningMultiGenerators) {
			activeCircuitGenerators.put(Thread.currentThread().getId(), this);
		}
	}

	//Added by CorrAuthor -------------
	public static void setActiveCircuitGenerator(CircuitGenerator cg){
		System.out.println("CURRENT active generator is: " + getActiveCircuitGenerator() + ", new generator to set: " + cg);
		if (!Config.runningMultiGenerators){
			instance = cg;
		}else{
			activeCircuitGenerators.put(Thread.currentThread().getId(), cg);
		}

	}
	//Added by CorrAuthor ------------- ABOVE

	public static CircuitGenerator getActiveCircuitGenerator() {
		if (!Config.runningMultiGenerators)
			return instance;
		else {

			Long threadId = Thread.currentThread().getId();
			CircuitGenerator currentGenerator = activeCircuitGenerators.get(threadId);
			if (currentGenerator == null) {
				throw new RuntimeException("The current thread does not have any active circuit generators");
			} else {
				return currentGenerator;
			}
		}
	}
	//Added by CorrAuthor -----------------
	public int getCurrentWireId(){
		return this.currentWireId;
	}
	//Added by CorrAuthor ----------------- ABOVE


	protected abstract void buildCircuit();

	public final void generateCircuit() {
		
		System.out.println("Running Circuit Generator for < " + circuitName + " >");
		initCircuitConstruction();
		buildCircuit();
		//Added by Dr. CorrAuthor ----	
		this.setupSegments();
		//Added by Dr. CorrAuthor ----ABOVE
		System.out.println("Circuit Generation Done for < " + circuitName + " >  \n \t Total Number of Constraints :  " + getNumOfConstraints() + "\n");
	}

	public String getName() {
		return circuitName;
	}

	public abstract void generateSampleInput(CircuitEvaluator evaluator);

	public Wire createInputWire(String... desc) {
		Wire newInputWire = new VariableWire(currentWireId++);
		addToEvaluationQueue(new WireLabelInstruction(LabelType.input, newInputWire, desc));
		inWires.add(newInputWire);
		return newInputWire;
	}

	public Wire[] createInputWireArray(int n, String... desc) {
		Wire[] list = new Wire[n];
		for (int i = 0; i < n; i++) {
			if (desc.length == 0) {
				list[i] = createInputWire("");
			} else {
				list[i] = createInputWire(desc[0] + " " + i);
			}
		}
		return list;
	}

	public LongElement createLongElementInput(int totalBitwidth,  String... desc){
		int numWires = (int) Math.ceil(totalBitwidth*1.0/LongElement.CHUNK_BITWIDTH);
		Wire[] w = createInputWireArray(numWires, desc);
		int[] bitwidths = new int[numWires];
		Arrays.fill(bitwidths, LongElement.CHUNK_BITWIDTH);
		if (numWires * LongElement.CHUNK_BITWIDTH != totalBitwidth) {
			bitwidths[numWires - 1] = totalBitwidth % LongElement.CHUNK_BITWIDTH;
		}
		return new LongElement(w, bitwidths);	
	}
	
	public LongElement createLongElementProverWitness(int totalBitwidth, String... desc){
		int numWires = (int) Math.ceil(totalBitwidth*1.0/LongElement.CHUNK_BITWIDTH);
		Wire[] w = createProverWitnessWireArray(numWires, desc);
		int[] bitwidths = new int[numWires];
		Arrays.fill(bitwidths, LongElement.CHUNK_BITWIDTH);
		if (numWires * LongElement.CHUNK_BITWIDTH != totalBitwidth) {
			bitwidths[numWires - 1] = totalBitwidth % LongElement.CHUNK_BITWIDTH;
		}
		return new LongElement(w, bitwidths);	
	}
	
	public Wire createProverWitnessWire(String... desc) {

		Wire wire = new VariableWire(currentWireId++);
		addToEvaluationQueue(new WireLabelInstruction(LabelType.nizkinput, wire, desc));
		proverWitnessWires.add(wire);
		return wire;
	}

	public Wire[] createProverWitnessWireArray(int n, String... desc) {

		Wire[] ws = new Wire[n];
		for (int k = 0; k < n; k++) {
			if (desc.length == 0) {
				ws[k] = createProverWitnessWire("");
			} else {
				ws[k] = createProverWitnessWire(desc[0] + " " + k);
			}
		}
		return ws;
	}

	public Wire[] generateZeroWireArray(int n) {
		Wire[] zeroWires = new ConstantWire[n];
		Arrays.fill(zeroWires, zeroWire);
		return zeroWires;
	}

	public Wire[] generateOneWireArray(int n) {
		Wire[] oneWires = new ConstantWire[n];
		Arrays.fill(oneWires, oneWire);
		return oneWires;
	}

	public Wire makeOutput(Wire wire, String... desc) {
		
		Wire outputWire = wire;
		if(proverWitnessWires.contains(wire)) {
			// The first case is allowed for usability. In some cases, gadgets provide their witness wires as intermediate outputs, e.g., division gadgets,
			// and the programmer could choose any of these intermediate outputs to be circuit outputs later.
			// The drawback of this method is that this will add one constraint for every witness wire that is transformed to be a circuit output.
			// As the statement size is usually small, this will not lead to issues in practice.
			// The constraint is just added for separation. Note: prover witness wires are actually variable wires. The following method is used
			// in order to introduce a different variable.
			outputWire = makeVariable(wire, desc);
			// If this causes overhead, the programmer can create the wires that are causing the bottleneck
			// as input wires instead of prover witness wires and avoid calling makeOutput().
		} else if(inWires.contains(wire)) {
			System.err.println("Warning: An input wire is redeclared as an output. This leads to an additional unnecessary constraint.");
			System.err.println("\t->This situation could happen by calling makeOutput() on input wires or in some cases involving multiplication of an input wire by 1 then declaring the result as an output wire.");
			outputWire = makeVariable(wire, desc);
		} else if (!(wire instanceof VariableWire || wire instanceof VariableBitWire)) {
			wire.packIfNeeded();
			outputWire = makeVariable(wire, desc);
		} else {
			wire.packIfNeeded();
		}

		outWires.add(outputWire);
		addToEvaluationQueue(new WireLabelInstruction(LabelType.output, outputWire, desc));
		return outputWire;

	}

	protected Wire makeVariable(Wire wire, String... desc) {
		Wire outputWire = new VariableWire(currentWireId++);
		Instruction op = new MulBasicOp(wire, oneWire, outputWire, desc);
		Wire[] cachedOutputs = addToEvaluationQueue(op);
		if(cachedOutputs == null){
			return outputWire;
		}
		else{
			currentWireId--;
			return cachedOutputs[0];
		}
	}

	public Wire[] makeOutputArray(Wire[] wires, String... desc) {
		Wire[] outs = new Wire[wires.length];
		for (int i = 0; i < wires.length; i++) {
			if (desc.length == 0) {
				outs[i] = makeOutput(wires[i], "");
			} else {
				outs[i] = makeOutput(wires[i], desc[0] + "[" + i + "]");
			}
		}
		return outs;
	}

	public void addDebugInstruction(Wire w, String... desc) {
		w.packIfNeeded();
		addToEvaluationQueue(new WireLabelInstruction(LabelType.debug, w, desc));
	}

	public void addDebugInstruction(Wire[] wires, String... desc) {
		for (int i = 0; i < wires.length; i++) {
			wires[i].packIfNeeded();
			addToEvaluationQueue(
					new WireLabelInstruction(LabelType.debug, wires[i], desc.length > 0 ? (desc[0] + " - " + i) : ""));
		}
	}

	public void writeCircuitFile() {
		try {
			PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(getName() + ".arith")));
		
			Instruction [] arr_wit_e = new Instruction [wireid_2_position.size()];	
			int num_added = 0;

			printWriter.println("total " + currentWireId);
			for (Instruction e : evaluationQueue.keySet()) {
				//Modified 01/13/2023, need to print WitnessWires 
				//in the ORDER in side the arrWitnessWires but not how
				//they were added in the circuit
				if (e.doneWithinCircuit()) {
					printWriter.print(e + "\n");
				}
			}
			if (num_added<arr_wit_e.length) {
				throw new RuntimeException("num_added: " + num_added + "< arr_with_e.length: " + arr_wit_e.length);
			}
			printWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void printCircuit() {

		for (Instruction e : evaluationQueue.keySet()) {
			if (e.doneWithinCircuit()) {
				System.out.println(e);
			}
		}

	}

	 private void initCircuitConstruction() {
		oneWire = new ConstantWire(currentWireId++, BigInteger.ONE);
		knownConstantWires.put(BigInteger.ONE, oneWire);
		addToEvaluationQueue(new WireLabelInstruction(LabelType.input, oneWire, "The one-input wire."));
		inWires.add(oneWire);
		zeroWire = oneWire.mul(0);
	}

	public Wire createConstantWire(BigInteger x, String... desc) {
		return oneWire.mul(x, desc);
	}

	public Wire[] createConstantWireArray(BigInteger[] a, String... desc) {
		Wire[] w = new Wire[a.length];
		for (int i = 0; i < a.length; i++) {
			w[i] = createConstantWire(a[i], desc);
		}
		return w;
	}

	public Wire createConstantWire(long x, String... desc) {
		return oneWire.mul(x, desc);
	}

	public Wire[] createConstantWireArray(long[] a, String... desc) {
		Wire[] w = new Wire[a.length];
		for (int i = 0; i < a.length; i++) {
			w[i] = createConstantWire(a[i], desc);
		}
		return w;
	}

	public Wire createNegConstantWire(BigInteger x, String... desc) {
		return oneWire.mul(x.negate(), desc);
	}

	public Wire createNegConstantWire(long x, String... desc) {
		return oneWire.mul(-x, desc);
	}

	/**
	 * Use to support computation for prover witness values outside of the
	 * circuit. See Mod_Gadget and Field_Division gadgets for examples.
	 * 
	 * @param instruction
	 */
	public void specifyProverWitnessComputation(Instruction instruction) {
		addToEvaluationQueue(instruction);
	}

	public final Wire getZeroWire() {
		return zeroWire;
	}

	public final Wire getOneWire() {
		return oneWire;
	}

	public LinkedHashMap<Instruction, Instruction> getEvaluationQueue() {
		return evaluationQueue;
	}

	public int getNumWires() {
		return currentWireId;
	}

	public Wire[] addToEvaluationQueue(Instruction e) {
		if (evaluationQueue.containsKey(e)) {
			if (e instanceof BasicOp) {
				return ((BasicOp) evaluationQueue.get(e)).getOutputs();
			}
		}
		if (e instanceof BasicOp) {
			numOfConstraints += ((BasicOp) e).getNumMulGates();
		}
		evaluationQueue.put(e, e);
		return null;  // returning null means we have not seen this instruction before
	}

	public void printState(String message) {
		System.out.println("\nGenerator State @ " + message);
		System.out.println("\tCurrent Number of Multiplication Gates " + " :: " + numOfConstraints + "\n");
	}

	public int getNumOfConstraints() {
		return numOfConstraints;
	}

	public ArrayList<Wire> getInWires() {
		return inWires;
	}

	public ArrayList<Wire> getOutWires() {
		return outWires;
	}

	public ArrayList<Wire> getProverWitnessWires() {
		return proverWitnessWires;
	}

	/**
	 * Asserts an r1cs constraint. w1*w2 = w3
	 * 
	 */
	public void addAssertion(Wire w1, Wire w2, Wire w3, String... desc) {
		if (w1 instanceof ConstantWire && w2 instanceof ConstantWire && w3 instanceof ConstantWire) {
			BigInteger const1 = ((ConstantWire) w1).getConstant();
			BigInteger const2 = ((ConstantWire) w2).getConstant();
			BigInteger const3 = ((ConstantWire) w3).getConstant();
			if (!const3.equals(const1.multiply(const2).mod(Config.FIELD_PRIME))) {
				throw new RuntimeException("Assertion failed on the provided constant wires .. ");
			}
		} else {
			w1.packIfNeeded();
			w2.packIfNeeded();
			w3.packIfNeeded();
			Instruction op = new AssertBasicOp(w1, w2, w3, desc);
			addToEvaluationQueue(op);
		}
	}

	public void addZeroAssertion(Wire w, String... desc) {
		addAssertion(w, oneWire, zeroWire, desc);
	}

	public void addOneAssertion(Wire w, String... desc) {
		addAssertion(w, oneWire, oneWire, desc);
	}

	public void addBinaryAssertion(Wire w, String... desc) {
		Wire inv = w.invAsBit(desc);
		addAssertion(w, inv, zeroWire, desc);
	}

	public void addEqualityAssertion(Wire w1, Wire w2, String... desc) {
		if(!w1.equals(w2))
			addAssertion(w1, oneWire, w2, desc);
	}

	public void addEqualityAssertion(Wire w1, BigInteger b, String... desc) {
		addAssertion(w1, oneWire, createConstantWire(b, desc), desc);
	}

	public void evalCircuit() {
		circuitEvaluator = new CircuitEvaluator(this);
		generateSampleInput(circuitEvaluator);
		circuitEvaluator.evaluate();
	}

	public void prepFiles() {
		writeCircuitFile();
		if (circuitEvaluator == null) {
			throw new NullPointerException("evalCircuit() must be called before prepFiles()");
		}
		circuitEvaluator.writeInputFile();
	}

	//------------------------------------------------------
	// Added by CorrAuthor. Add a directory container path  and the platform
	// name. pname - platform name
	public void prepFiles(String dirpath, String pname) {
		writeCircuitFile(dirpath, pname);
		if (circuitEvaluator == null) {
			throw new NullPointerException("evalCircuit() must be called before prepFiles()");
		}
		circuitEvaluator.writeInputFile(dirpath, pname);
	}
	public void writeCircuitFile(String dirpath, String pname) {
		try {
			PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(dirpath + "/" + getName() + ".arith." + pname)));

			printWriter.println("total " + currentWireId);
			//ADDED by CorrAuthor --------------
			printWriter.println("num_segments " + num_segments); 
			for(int i=0; i<num_segments; i++){
				printWriter.println("segment_size " + segment_size[i]);
			}
			printWriter.println("");
			Instruction [] arr_wit_e = new Instruction [wireid_2_position.size()];	
			int num_added = 0;
			for (Instruction e : evaluationQueue.keySet()) {
				//Modified 01/13/2023, need to print WitnessWires 
				//in the ORDER in side the arrWitnessWires but not how
				//they were added in the circuit
				if (e.doneWithinCircuit()) {
					if(e instanceof WireLabelInstruction){
						//1. insert int into arr_wit_e
						WireLabelInstruction we = (WireLabelInstruction) e;
						if(we.getType()!=LabelType.nizkinput){
							 printWriter.print(e + "\n");
							 continue;
						}
						int wire_id = we.getWire().getWireId();
						int idx = wireid_2_position.get(wire_id);
						arr_wit_e[idx] = e;
						num_added ++;
		
						//2. if full, print them all
						if (num_added==arr_wit_e.length){
							for(int i=0; i<arr_wit_e.length; i++){
								Instruction e_to_prt = arr_wit_e[i];
								printWriter.print(e_to_prt + "\n");
							}
						}
					}else{
						printWriter.print(e + "\n");
					}
				}
			}
			if (num_added<arr_wit_e.length) {
				throw new RuntimeException("num_added: " + num_added + "< arr_with_e.length: " + arr_wit_e.length);
			}
			printWriter.close();
			//ADDED by CorrAuthor -------------- Above
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	//-----------Added by CorrAuthor Above -------------

	public void runLibsnark() {

		try {
			Process p;
			p = Runtime.getRuntime()
					.exec(new String[] { Config.LIBSNARK_EXEC, circuitName + ".arith", circuitName + ".in" });
			p.waitFor();
			System.out.println(
					"\n-----------------------------------RUNNING LIBSNARK -----------------------------------------");
			String line;
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			StringBuffer buf = new StringBuffer();
			while ((line = input.readLine()) != null) {
				buf.append(line + "\n");
			}
			input.close();
			System.out.println(buf.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//-----------------------------------
	// ADDED BY CorrAuthor 
	// Generate R1CS by calling libsnark to dump R1CS
	// for the arithmetic circuit
	// Need the PrimeFieldInfo to decide the prime order for
	// operations such as inverse(), and mul()
	// ---------------------------------
	public void genR1cs(PrimeFieldInfo info){
		genR1cs(info, "circuits/", true);
	}
	/** Read the array list from the file. Each number per line. 
	*/
	protected int [] read_arr_int(String fpath){
		//1. get the number of lines
		int lines = 0;
		Path path = Paths.get(fpath);
		try(Stream<String> sm= Files.lines(path, StandardCharsets.UTF_8)){
  			lines= (int) sm.count();
		}catch(IOException exc){
			System.err.println(exc.toString());
			System.exit(1);
		}
		int [] res = new int [lines];

		//2. process al lines
		BufferedReader reader;
		try{
			reader = new BufferedReader(new FileReader(fpath));
			for(int i=0; i<lines; i++){
				String line = reader.readLine();
				int val = Integer.parseInt(line);
				res[i] = val;
			}
			reader.close();
		}catch(IOException exc){
			System.err.println(exc.toString());
			System.exit(1);
		}
		return res;
 	}

	//Added CorrAuthor 12/28/2022
	//when conn_wires is null, regard as no connectors
	//otherwise generates connector_vars.txt
	//THIS FUNCTION IS NEVER CALLED ANYMORE!
	public void genVars(PrimeFieldInfo info, String path, int [] conn_wires){
		String fpath = path + "/" + "vars.txt";
		try{
			//1. read the variables map
			String pname = info.name;
			String map_fpath = path + circuitName + ".in." + pname + ".varmap";
			int [] map_raw = read_arr_int(map_fpath);
			int max_wire_id = 0;
			int max_var_id = 0;
			for(int i=0; i<map_raw.length; i+=2){
				if(map_raw[i]>max_wire_id) {max_wire_id = map_raw[i];}
				if(map_raw[i+1]>max_var_id) {max_var_id = map_raw[i+1];}
			}

			//2. process the map information (2 elements for a map entry)
			// in map_raw it's wire_id -> var_id (we'll reverse the map)
			int [] var_to_wire = new int [max_var_id+1];
			int [] wire_to_var = new int [max_wire_id+1];
			for(int i=0; i<max_var_id+1; i++) {var_to_wire[i] = -1;}
			for(int i=0; i<max_wire_id+1; i++) {wire_to_var[i] = -1;}
			for(int i=0; i<map_raw.length; i+=2){
				int wire_id = map_raw[i];
				int var_id = map_raw[i+1];
				var_to_wire[var_id] = wire_id;
				wire_to_var[wire_id] = var_id;
			}
			for(int i=0; i<max_var_id+1; i++){
				if(var_to_wire[i]==-1){
					throw new RuntimeException("VAR: " + i + " not mapped!");
				}
			}

			//3. process the variables map
			PrintWriter printWriter = new PrintWriter(new BufferedWriter(
				new FileWriter(fpath)));
			printWriter.println("assignments: " + (max_var_id+1));
			int id = 0;
			for(int i=0; i<max_var_id+1; i++){
				BigInteger value = circuitEvaluator.
					getWireValueByID(var_to_wire[i]);
				printWriter.println(i + " " + value);
			}
			printWriter.close();


			//4. generate the connector_vars
			String fvarpath = path + "/conn_vars.txt";
			PrintWriter pw = new PrintWriter(new BufferedWriter(
					new FileWriter(fvarpath)));
			if(conn_wires!=null && conn_wires.length>0){
				int [] conn_vars= new int [conn_wires.length];
				for(int i=0; i<conn_wires.length; i++){
					int wire_id = conn_wires[i];
					int var_id = wire_to_var[wire_id];
					if(var_id==-1) {
						throw new RuntimeException("INVALID var id for wire: " + wire_id + ", at index: " + i);
					}
					conn_vars[i] = var_id;
				}
				for(int i=0; i<conn_wires.length; i++){
					pw.println(conn_vars[i]);
System.out.println("REMOVE 109: conn_var " + i + ": " + conn_vars[i]);
				}
				 
			}
			pw.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/// write the VAR IDs of connector vars (6 of them) for CircACDFA
	/// to conn_vars.txt
	
	public void genConnVars(PrimeFieldInfo info, String path, int [] conn_wires){
		try{
			//1. read the variables map
			String pname = info.name;
			String map_fpath = path + circuitName + ".in." + pname + ".varmap";
			int [] map_raw = read_arr_int(map_fpath);
			int max_wire_id = 0;
			int max_var_id = 0;
			for(int i=0; i<map_raw.length; i+=2){
				if(map_raw[i]>max_wire_id) {max_wire_id = map_raw[i];}
				if(map_raw[i+1]>max_var_id) {max_var_id = map_raw[i+1];}
			}

			//2. process the map information (2 elements for a map entry)
			// in map_raw it's wire_id -> var_id (we'll reverse the map)
			int [] var_to_wire = new int [max_var_id+1];
			int [] wire_to_var = new int [max_wire_id+1];
			for(int i=0; i<max_var_id+1; i++) {var_to_wire[i] = -1;}
			for(int i=0; i<max_wire_id+1; i++) {wire_to_var[i] = -1;}
			for(int i=0; i<map_raw.length; i+=2){
				int wire_id = map_raw[i];
				int var_id = map_raw[i+1];
				var_to_wire[var_id] = wire_id;
				wire_to_var[wire_id] = var_id;
			}
			for(int i=0; i<max_var_id+1; i++){
				if(var_to_wire[i]==-1){
					throw new RuntimeException("VAR: " + i + " not mapped!");
				}
			}

			//3. generate the connector_vars
			String fvarpath = path + "/conn_vars.txt";
			PrintWriter pw = new PrintWriter(new BufferedWriter(
					new FileWriter(fvarpath)));
			if(conn_wires!=null && conn_wires.length>0){
				int [] conn_vars= new int [conn_wires.length];
				for(int i=0; i<conn_wires.length; i++){
					int wire_id = conn_wires[i];
					int var_id = wire_to_var[wire_id];
					if(var_id==-1) {
						throw new RuntimeException("INVALID var id for wire: " + wire_id + ", at index: " + i);
					}
					conn_vars[i] = var_id;
				}
				for(int i=0; i<conn_wires.length; i++){
					pw.println(conn_vars[i]);
				}
				 
			}
			pw.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public void genR1cs(PrimeFieldInfo info, String path, boolean bInfo) {
		try {
			String pname = info.name;
			String arithPath = bInfo? 
				path + circuitName + ".arith." + pname:
				path + circuitName + ".arith";
			String inPath = bInfo?
				path + circuitName + ".in." + pname:
				path + circuitName + ".in";
			String r1csPath = bInfo?
				path + circuitName + ".r1cs." + pname:
				path + circuitName + ".r1cs";
			Process p;
			p = Runtime.getRuntime()
					.exec(new String[] { 
						Config.LIBSNARK_EXEC_GEN_R1CS, 
						arithPath,
						inPath,
						r1csPath,
						pname
					});
			System.out.println("Run: " + 
				Config.LIBSNARK_EXEC_GEN_R1CS + " " 
				+ arithPath + " "  + inPath + " " +  r1csPath + " " +  pname);
			String line;
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while ((line = input.readLine()) != null) {
				System.out.println(line);
				if(line.contains("Terminating")){
					System.err.println("\n!!!!!!!!!!!!!!!!!!!!!!!\ngenR1cs FAILED!\nTERMINATING DUE TO ERROR!\n!!!!!!!!!!!!!!!!!!!!!!!!\n");
					System.out.println("Cmd: " + 
						Config.LIBSNARK_EXEC_GEN_R1CS + " " 
						+ arithPath + " "  + inPath + " " +  
						r1csPath + " " +  pname);
					System.exit(123);
				}
			}
			input.close();
			//System.out.println(buf.toString());
			p.waitFor();
			System.out.println("genR1cs completed!");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	//-----------------------------------


	public CircuitEvaluator getCircuitEvaluator() {
		if (circuitEvaluator == null) {
			throw new NullPointerException("evalCircuit() must be called before getCircuitEvaluator()");
		}
		return circuitEvaluator;
	}

}
