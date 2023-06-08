/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/30/2021
* ***************************************************/

/** **************************************************
This is a base class for all two 1-operand commit.
It takes one prime field element as the input,
RANDOMLY generate some random nonce and generates the commit.

Derived Classes: HashCommit, PedersenCommit
They need to implement: build_circuit_worker() and
logical_eval()
* ***************************************************/
package za_interface.za.circs.commit;

import java.math.BigInteger;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;

/**
  Base class for all 2-inputs hashers such as SHA2-256, 
Poseidon, and PedersenHash. Note: all DERIVED CLASSES
need to use the protected data member *** nonce *** to generate
the commitment. 
*/
public abstract class ZaCommit extends ZaCirc{
	// ** data member **
	/* the nonce used for commitment. All derived class have to use it */
	protected BigInteger nonce; 
	

	// ** Operations **
	public ZaCommit(ZaConfig config_in, String name, ZaGenerator zg){
		super(config_in, name, zg);
		this.nonce = Utils.randpf(config_in);
	}

	/** based on the choice of config, create the corresponding
		commit component */
	public static ZaCommit new_commit(ZaConfig config_in, ZaGenerator zg){
		//! AT this moment, only supports Hash based commitments
		//! including {PedersonHash, SHA256, Poseidon)
		//! To be extended later.
		ZaCommit zc = new ZaHashCommit(config_in, zg);
		return zc;
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** ONE prime field element to commit to */
	public int getNumWitnessInputs(){
		return 1;
	}

	/** return one 256-bit prime field element */
	public int getNumOutputs(){ 
		return 1;
	}

	/** Generate the commitment, assumption a < prime_field_order */
	public BigInteger commit(BigInteger a){
		BigInteger modulus = this.config.getFieldOrder();
		a = a.mod(modulus);
		BigInteger [] arrPubInput = new BigInteger [] {};
		BigInteger [] arrWitness = new BigInteger [] {a};
		//polymorphic call
		BigInteger [] res = this.logical_eval(arrPubInput, arrWitness);
		return res[0];	
	}


	//TO BE OVERRIDEN by child class
	//public BigInteger [] logical_eval(BigInteger [] arrPubInput, BigInteger [] arrWitness);

	//TO BE OVERRIDEN by child class
	//public Wire [] build_circuit_worker(Wire [] arrPubInput, Wire [] arrWitness);

	//TO BE OVERRIDEN by child class
	//public BigInteger [][] genRandomInput(int n)
		
}
