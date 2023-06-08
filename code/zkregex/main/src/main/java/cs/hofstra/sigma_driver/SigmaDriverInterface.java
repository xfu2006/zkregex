/** Efficient Zero Knowledge Project
	Author: Dr. CorrAuthor 
	Interface for a SigmaDriver (Sigma Protocol)
	Created: 06/13/2022
*/ 

package cs.Employer.sigma_driver;
import cs.Employer.ac.AC;
import java.util.ArrayList;
import java.math.BigInteger;

/** interface for sigma protocol prover and verifier */
public interface SigmaDriverInterface{
	/** prove and save all related files to sPrfDir */
	public SigmaProofInterface prove_nonzk(String acDir,
		BigInteger [] set_st, BigInteger r, String sPrfDir);
	/** verify a proof */
	public boolean verify(SigmaProofInterface proof);
}
