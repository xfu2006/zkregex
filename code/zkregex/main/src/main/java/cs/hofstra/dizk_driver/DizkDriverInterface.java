/** Efficient Zero Knowledge Project
	Author: Dr. CorrAuthor 
	Interface for a DizkDriver (note: at this moment we have a standard and
	mofidied Driver)
	Created: 06/12/2022
*/ 

package cs.Employer.dizk_driver;

import cs.Employer.ac.AC;
import java.util.ArrayList;
import java.math.BigInteger;
public interface DizkDriverInterface{
	/** produce a proof. 
		@param ac: the ac who generates the sequence of transitions. It also has the information of bits for encoding states and TERM_CHAR which are used
 for padding purpose.
		@param arrTrans: each transition contains the info of char and
		src, dest states
		r1 and r2 is for computing poly(r_1) * r2.
	 */
	public DizkProofInterface prove(AC ac, ArrayList<AC.Transition> arrTrans,
		BigInteger r1, BigInteger r2);
	/** verify a proof */
	public boolean verify(DizkProofInterface proof);
	/** return the set of states and transitions (digitalized) */
	public BigInteger [] get_st();
}
