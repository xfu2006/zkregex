/** Efficient Zero Knowledge Project
	Hybrid Proof (two parts: zkSnark Proof and Sigma Proof)
	Author: Dr. CorrAuthor
	Created: 06/13/2022
*/ 
package cs.Employer.zkregex;
import configuration.Configuration;
import cs.Employer.dizk_driver.*;
import cs.Employer.sigma_driver.*;

public class Proof{
	protected DizkProofInterface dizk_proof;
	protected SigmaProofInterface sigma_proof;

	public Proof(DizkProofInterface dproof, SigmaProofInterface  sproof){
		this.dizk_proof = dproof;
		this.sigma_proof = sproof;
	}

	/** return size in bytes */
	public int size(){
		return dizk_proof.get_size() + sigma_proof.get_size();
	}

	/** serialization */
	public byte [] to_bytes(){
		System.out.println("WARNING: proof.to_bytes() returns a dummy byte arr");
		return new byte [this.size()];
	}
}
