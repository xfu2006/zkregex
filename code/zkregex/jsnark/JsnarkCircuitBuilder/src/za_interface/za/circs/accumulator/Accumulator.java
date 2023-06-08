/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/18/2021
* ***************************************************/

/** **************************************************
This is an abstract class for accmulator where
all crypto accmulators will implement. Derived classes
include MerkleTreeAccmulator and RSAAccmulator.
* ***************************************************/
package za_interface.za.circs.accumulator;

import java.math.BigInteger;
import za_interface.za.Utils;
import za_interface.za.ZaGenerator;
//import util.Util;

/** **************************************************
This is an abstract class for accmulator where
all crypto accmulators will implement. Derived classes
include MerkleTreeAccmulator and RSAAccmulator.

An accmulator can be regarded as a set of 
BigIntegers (the real domain is controlled by each
specific accmulator, e.g., some RSA accmulators will
require prime elements).

*** NOTE for the corresponding ZaAccumulatorVerifier:
the structure of witness is always: 1 element to verify, the root_hash,
and then the rest are proof
* ***************************************************/
public abstract class Accumulator{
	/** generate the corresponding verifier */
	public abstract ZaAccumulatorVerifier genVerifier();

	/** add the supplied elements as new elements, at this moment
	we do not allow drop elements */
	public abstract void add_elements(BigInteger [] set);	

	/** return the 'hash' of all elements, which is used
	for verify membership, it may be one or more BigIntegers */
	public abstract BigInteger [] get_hash();

	/** generate the proof for the given element.
	 */
	public abstract BigInteger [] gen_proof(BigInteger element);

	/**
		prepre the witness array for the circ.
		element, hash, proof
	*/
	public BigInteger [] gen_witness(BigInteger element){
		BigInteger [] res = new BigInteger [] {element};
		BigInteger [] hash = this.get_hash();
		res = Utils.concat(res, hash);
		BigInteger [] proof = this.gen_proof(element);
		res = Utils.concat(res, proof);
		return res; 
	}
	

	/** get the size: number of elements */
	public abstract int get_size();

	/** get the log2(capacity) */
	public abstract int get_capacity_log();

	/** return the corresonding ZaAccumulatorVerifier */
	public abstract ZaAccumulatorVerifier genAccumulatorVerifier(ZaGenerator zg);
}
