
/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/25/2021
* ***************************************************/

/** **************************************************
This is the class wrapping Performance Data.
It is parsed from json output from the data generation
in the Rust packages
* ***************************************************/
package za_interface.za.circs.zero_audit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class CircuitPerfData{
	class PerfData{
		/** time in milli-seconds */
		public long time_ms; 
		/** space consumption in bytes */
		public long space;
	
		@Override		
		public String toString(){
			return "time_ms: " + time_ms + ", space: " + space;
		}

		public PerfData add(PerfData other){
			PerfData cp = new PerfData();
			cp.time_ms = this.time_ms + other.time_ms;
			cp.space = this.space + other.space;
			return cp;
		}
	} 

	//** PUBLIC DATA ***
	/* whether it is successful */
	public boolean b_success;
	/* the size in bytes for crs */
	public long crs_size; 
	/* the size of r1cs */
	public long num_r1cs;
	/* the stats of proof generation */
	public PerfData proof_gen_data;
	/* the cost of setting up*/
	public PerfData setup_data; 
	/* the cost of verification */
	public PerfData verify_data;

	public CircuitPerfData add(CircuitPerfData other){
		CircuitPerfData cp = new CircuitPerfData();
		cp.b_success = this.b_success & other.b_success;
		cp.num_r1cs = this.num_r1cs + other.num_r1cs;
		cp.proof_gen_data = this.proof_gen_data.add(other.proof_gen_data);
		cp.setup_data = this.setup_data.add(other.setup_data);
		cp.verify_data = this.verify_data.add(other.verify_data);
		return cp;	
	}

	// ** PUBLIC operations ****
	@Override
	public String toString(){
		return "b_success: " + b_success + ", crs_size: " + crs_size + 
			", num_r1cs: " + num_r1cs + "\n" + 
			"setup_data: " + setup_data +  "\n" + 
			"gen_data: " + proof_gen_data +  "\n" + 
			"verify_data: " + verify_data + "\n";
		
	}

	/** construct from json string */
	public static CircuitPerfData fromJson(String s){
		GsonBuilder builder = new GsonBuilder();
		builder.setPrettyPrinting();
		Gson gson = builder.create();
		CircuitPerfData cpd = gson.fromJson(s, CircuitPerfData.class);
		return cpd;
	}
}
	
