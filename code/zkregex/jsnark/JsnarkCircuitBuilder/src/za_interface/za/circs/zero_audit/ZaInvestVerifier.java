/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/28/2021
* ***************************************************/

/** **************************************************
This is a verifier for an investment operation:
client invests x shares in a fund. It is essentially
a verifier for a new cert.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.WireArray;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.range.*;
import util.Util;

/** **************************************************
This is a verifier for an investment operation:
client invests x shares in a fund. It is essentially
a verifier for a new cert.
* ***************************************************/
public class ZaInvestVerifier extends ZaCirc{
	// *** data members ***
	protected Cert cert; //for the new cert (the sid is a fund ID)
	protected Client client; //the client

	// *** Operations ***
	/** constructor: to certify the newly created cert by client.
		The other attributes retrieved from the
		the cert and client
	*/
	public ZaInvestVerifier(ZaConfig config_in, Client client, Cert cert, ZaGenerator zg){
		super(config_in, "InvestVerifier", zg);
		this.cert= cert;
		this.client = client;
	}

	/** returns 5. 
		client_id, fund_id, shares, ts, cert_root
	*/
	public int getNumPublicInputs(){
		return 5;
	}

	/**
		3: nonce_for_cert, sid1 (of client), sid2  
	*/
	public int getNumWitnessInputs(){
		return 3;
	}

	/**
		Either 1 or 0 for yes or no
	*/	
	public int getNumOutputs(){ 
		return 1;
	}

	/** 
		@arrPubInput - expect to be an empty
		@arrWitness - [0] element to prove, [1] hash, [2-n+1]
			the proof
	*/	
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//0. data set up
		BigInteger [] pi = arrPubInput;
		BigInteger [] aw = arrWitness;
		BigInteger one = Utils.itobi(1);
		BigInteger zero= Utils.itobi(0);
		common cm = new common();
		ZaGenerator zg = (ZaGenerator) this.generator;
		BigInteger res = Utils.itobi(1);

		//1. check the validity of client_id given witness
		BigInteger cid2 = cm.logical_hash(aw[1], aw[2], config, zg);
		res = res.and(cm.logical_checkVal(pi, 0, cid2, "client_id"));
		
		//2. check the validity of cert
		ZaCertVerifier zv = new ZaCertVerifier(config, cert, null);
		BigInteger res2 = zv.logical_eval(
			new BigInteger [] {}, new BigInteger [] {
				pi[0], zero, aw[0], pi[1], pi[2], pi[3], pi[4]}
		)[0];
		res = res.and(cm.logical_checkTrue(res2, "certverify"));

		return new BigInteger [] {res};
	}


	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		pk, counter, nonce, SID, q, ts, root
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//0. data set up
		Wire [] pi = arrPubInput;
		Wire [] aw = arrWitness;
		ZaGenerator zg = (ZaGenerator) this.generator;
		Wire one = zg.createConstantWire(1);
		Wire zero= zg.createConstantWire(0);
		Wire res = one;
		common cm = new common();

		//1. check the validity of client_id given witness
		Wire cid2 = cm.hash(aw[1], aw[2], config, zg);
		res = res.and(cm.checkVal(pi, 0, cid2, "client_id"));
		
		//2. check the validity of cert
		ZaCertVerifier zv = new ZaCertVerifier(config, cert, zg);
		zv.build_circuit(
			new Wire [] {}, new Wire [] {
				pi[0], zero, aw[0], pi[1], pi[2], pi[3], pi[4]}
		);
		Wire res2 = zv.getOutputWires()[0];
		res = res.and(cm.checkTrue(res2, "certverify"));

		return new Wire [] {res};
	}
	
	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		Note: regardless of n, it only generates the input based on
		the data member client and cert. If need a random cert, call
		the genRandCert() function of the Cert class */
	public BigInteger[][] genRandomInput(int n){
		BigInteger [] arrwit = new BigInteger [] {
			cert.pk,
			cert.counter,
			cert.nonce,
			cert.SID,
			cert.q,
			cert.ts,
			cert.root
		};
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {
				client.client_id,
				cert.SID,
				cert.q,
				cert.ts,
				cert.getRoot()	
			},
			new BigInteger [] {
				cert.nonce,
				client.sk1,
				client.sk2
			}	
		};
		return ret;
	}
	
}
