/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/18/2021
* ***************************************************/

/** **************************************************
This is an abstract class should be extended by all
accmulators.
A circuit responsible for verifying the provided proof
to show that an element is a member of the accmulator.
*** NOTE the structure of witness is always: 1 element to verify, the root_hash,
and then the rest are proof
* ***************************************************/
package za_interface.za.circs.accumulator;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import examples.gadgets.diffieHellmanKeyExchange.ECDHKeyExchangeGadget;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.curve.*;
import util.Util;

/** **************************************************
This is an abstract class should be extended by all
accmulators.
A circuit responsible for verifying the provided proof
to show that an element is a member of the accmulator.
* ***************************************************/
public abstract class ZaAccumulatorVerifier extends ZaCirc{
	/** verify if the given hash of accmulator and the proof is good.
		@param element - the element of some accmulator
		@param hash - the global 'hash' of that accmulator, e.g.,
			root of a Merkle tree.
		@param proof - the proof (e.g., the verification path)
			which reaches that element from merkle tree
	 */
	public abstract boolean verify(BigInteger element, BigInteger [] hash,
		BigInteger [] proof);

	// ** Operations **
	public ZaAccumulatorVerifier(ZaConfig config_in, String name, ZaGenerator zg){
		super(config_in, name, zg);
	
	}

	
}
