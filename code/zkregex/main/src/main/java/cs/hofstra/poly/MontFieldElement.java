/* *****************************************
*	Efficient Zero Knowledge for Regular Expression
*   AbstractFieldElement + MontReduction class 
*	Author: Dr. CorrAuthor
*	Created: 04/26/2022
* *******************************************/
package cs.Employer.poly;

import java.io.Serializable;
import cs.Employer.zkregex.Tools;
import java.math.BigInteger;
import java.lang.RuntimeException;
import algebra.fields.AbstractFieldElementExpanded;
import common.MathUtils;
import common.Utils;

/**  This class extendes the DIZK's FieldElementExpanded class
so that we can take advantage of its FFT framework, but at the same
time provide much faster multi-precision arithmetic, using
Montgomery Reduction.

The FieldElement is ALWAYS stored in the Montgomery reduction form.
By calling back_from_mont() it returns the BigInteger of the
``original" value for display purpose.

In addition, we provide a set of MUTABLE arithmetic functions e.g.,
addWith, which does NOT return a new object but modifies the operands.
This can save the object creation heap cost (measured 800 ms for 10 million
ops usually).
*/


public abstract class MontFieldElement<FieldT extends MontFieldElement<FieldT>>
	 extends AbstractFieldElementExpanded<FieldT> implements Serializable{
	/** return its ORIGINAL value from Montgomery reduction */
	public abstract BigInteger back_from_mont(); 

	/** Mutable change version of mul */
	public abstract void mulWith(final FieldT that); 
	public abstract void mulTo(final FieldT that, FieldT dest); 

	/** Mutable change version of add */
	public abstract void addWith(final FieldT that); 
	public abstract void addTo(final FieldT that, FieldT dest); 

	/** Mutable change version of sub */
	public abstract void subWith(final FieldT that); 
	public abstract void subTo(final FieldT that, FieldT dest); 

	/** Mutable version, change itself*/
	public abstract void squareWith(); 

	/** Mutable version, change itself*/
	public abstract void inverseWith(); 

	/** Mutable version, change itself. Negate itself*/
	public abstract void negateWith(); 

	/** copy from the other */
	public abstract void copyFrom(FieldT other);
}
