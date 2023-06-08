/** Efficient Zero Knowledge Project
	Prover Interface
	Author: Dr. CorrAuthor
	Created: 07/11/2022
*/ 

package cs.Employer.zkregex;
import configuration.Configuration;
import cs.Employer.dizk_driver.*;
import cs.Employer.sigma_driver.*;
import cs.Employer.ac.AC;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Arrays;

/** interface of a prover
*/
public interface ProverInterface {
	/** Assume the DFA.datis located in acDir. Read it and process
	the given binFile and save the proof into prfFilePath
	*/
	public void process(String acDir, String sBinFileToProve, 
		String sPrfDir, Configuration config);
}

	
