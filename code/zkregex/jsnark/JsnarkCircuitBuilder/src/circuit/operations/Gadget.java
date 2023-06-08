/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package circuit.operations;

import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
//---------------------
//ADDED By CorrAuthor --- for serialization
import java.io.Serializable;
//----------------------
public abstract class Gadget implements Serializable {

	protected CircuitGenerator generator;
	protected transient String description;

	public Gadget(String...desc) {
		this.generator = CircuitGenerator.getActiveCircuitGenerator();
		if(desc.length > 0)
			this.description = desc[0];
		else
			this.description = "";
	}

	// -- ADDED By CorrAuthor --- for serialization
	public Gadget(){
	}
	// ------------------------

	public abstract Wire[] getOutputWires();
	
	public String toString() {
		return  getClass().getSimpleName() + " " + description;
	}
	
	public String debugStr(String s) {
		return this + ":" + s;
	}
}
