/** Efficient Zero Knowledge Project
	Author: Dr. CorrAuthor 
	Wrapper of Standard DIZK Proof
	Created: 06/12/2022
*/ 

package cs.Employer.dizk_driver.standard;
import cs.Employer.dizk_driver.*;
import zk_proof_systems.zkSNARK.objects.Proof;

public class StandardDizkProof implements DizkProofInterface{
	// **** DATA MEMBERS *****
	Proof proof;
	// **** OPERATIONS *****
	public StandardDizkProof(Proof prf){
		this.proof = prf;
	}
	public int get_size(){
		return proof.gA().bitSize()/8 * 3;
	}
}
