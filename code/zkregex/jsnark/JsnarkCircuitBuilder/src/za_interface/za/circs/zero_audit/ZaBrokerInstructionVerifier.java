/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/18/2021
* ***************************************************/

/** **************************************************
This is a verifier circuit for Broker Instruction.
Logially: a broker instruction consists of
<64-bit sid, 63-bit quantity, and 1-bit buy_decision>
This 128-bit info is feed to the DH-CSpec module
for encryption and generates 2 64-bit blocks as
the encrypted result. The circuit verify that the
three witness inputs supplied indeed generates 
the output (the 2 64-bit block) [which is listed in
the public input]. The output line is a 1-bit boolean
output (meaning whether the verification is successful).

input: 2 64-bit words of encryption output
witness: 64-bit sid, 63-bit quantity, 1 bit buy-decision
output: 1-bit yes/no.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import za_interface.za.circs.accumulator.*;
import java.math.BigInteger;
import java.util.Random;
import circuit.structure.Wire;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.range.*;
import za_interface.za.circs.encrypt.hybrid.*;
import util.Util;

/** **************************************************
This is a verifier circuit for Broker Instruction.
Logially: a broker instruction consists of
<64-bit sid, 63-bit quantity, and 1-bit buy_decision>
This 128-bit info is feed to the DH-CSpec module
for encryption and generates 2 64-bit blocks as
the encrypted result. The circuit verify that the
three witness inputs supplied indeed generates 
the output (the 2 64-bit block) [which is listed in
the public input]. The output line is a 1-bit boolean
output (meaning whether the verification is successful).

input: 2 64-bit words of encryption output
witness: 64-bit sid, 63-bit quantity, 1 bit buy-decision
output: 1-bit yes/no.
* ***************************************************/
public class ZaBrokerInstructionVerifier extends ZaCirc{
	// *** data members ***
	protected ZaHybridDHSpeck crypt;
	protected BigInteger hX; //DH co-eff
	protected BigInteger s;  //DF co-eff (secret)

	// *** Operations ***
	public ZaBrokerInstructionVerifier(ZaConfig config_in,  ZaGenerator zg){
		super(config_in, "BrokerInstructionVerifier", zg);
		crypt = new ZaHybridDHSpeck(config_in, 128, zg);
		BigInteger [][] c_inp = crypt.genRandomInput(0);
		hX = c_inp[1][0]; //this can be randomized, fixed right now
		s = c_inp[1][1];
	}

	/** returns 2. 
		2 64-bit words representing the output */
	public int getNumPublicInputs(){
		return 2;
	}

	/**
		3: 64-bit sid, 64-bit quantity and 1-bit buy_decision (1 for buy)
	*/
	public int getNumWitnessInputs(){
		return 3;
	}

	/**
		Either 1 or 0 for yes or no. No for all
	invalid intput/witness, e.g., buy_decision out-of-range (not a boolean)
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
		BigInteger res = Utils.itobi(1);
		//1. get input 
		BigInteger sid = arrWitness[0];
		BigInteger q= arrWitness[1];
		BigInteger bBuy = arrWitness[2];
		BigInteger [] ciphertext = arrPubInput;

		//2. check in range
		res = res.and(logical_checkInRange(sid,64, "sid")); 
		res = res.and(logical_checkInRange(q,63, "q")); 
		res = res.and(logical_checkInRange(bBuy,1, "bBuy")); 

		//3. encode input first
		BigInteger enc_inp = logical_encode(sid, q, bBuy);
		BigInteger [] bits_inp = Utils.split(enc_inp, 128);

		//4. feed to encryptor
		BigInteger [] arrWit = new BigInteger [] {hX, s};
		arrWit = Utils.concat(arrWit, bits_inp);
		BigInteger [] c2 = crypt.logical_eval(new BigInteger []{}, arrWit);
		res = res.and(logical_eq(ciphertext[0], c2[0], "ciphertext[0]"));
		res = res.and(logical_eq(ciphertext[1], c2[1], "ciphertext[1]"));

		return new BigInteger [] {res};
	}


	/** build the circuit. Needs to supply the input wires
		the input format same as logical_eval:
		pk, counter, nonce, SID, q, ts, root
	 */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. get input 
		Wire sid = arrWitness[0];
		Wire q= arrWitness[1];
		Wire bBuy = arrWitness[2];
		Wire [] ciphertext = arrPubInput;

		//2. check in range
		Wire res = checkInRange(sid,64, "sid"); 
		res = res.and(checkInRange(q,63, "q")); 
		res = res.and(checkInRange(bBuy,1, "bBuy")); 

		//3. encode input first
		Wire enc_inp = encode(sid, q, bBuy);
		Wire [] bits_inp = enc_inp.getBitWires(128).asArray();

		//4. feed to encryptor
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		Wire hX = zg.createConstantWire(this.hX);
		Wire s = zg.createConstantWire(this.s);
		Wire [] arrWit = new Wire [] {hX, s};
		arrWit = Utils.concat(arrWit, bits_inp);
		//reset crypt because it needs a fresh instance of zg
		this.crypt = new ZaHybridDHSpeck(config, 128, zg);
		crypt.build_circuit(new Wire []{}, arrWit);
		Wire [] c2 = crypt.getOutputWires();
		res = res.and(eq(ciphertext[0], c2[0], "ciphertext[0]"));
		res = res.and(eq(ciphertext[1], c2[1], "ciphertext[1]"));

		return new Wire [] {res};
	}

	/** assume all inputs are in range, n is the random seed */
	public BigInteger [][] genInput(BigInteger sid, BigInteger q, BigInteger bBuy, int n){
		BigInteger plaintext = logical_encode(sid, q, bBuy);
		BigInteger [][] crypt_inp = crypt.genRandomInput(n);
		BigInteger enc_inp = logical_encode(sid, q, bBuy);
		BigInteger [] bits_inp = Utils.split(enc_inp, 128);
		BigInteger [] arrWit = new BigInteger [] {hX, s};
		arrWit = Utils.concat(arrWit, bits_inp);
		BigInteger [] pi = crypt.logical_eval(new BigInteger [] {}, arrWit);

		//3. build the input array	
		BigInteger [][] ret= new BigInteger [][] {
			pi,
			new BigInteger [] {sid, q, bBuy}
		};
		return ret;
	}
	
	/** 
		Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
	*/
	public BigInteger[][] genRandomInput(int n){
		n = n + 3;
		BigInteger sid = Utils.randbi(64, n, 5);  //5 is just a rand pick
		BigInteger q = Utils.randbi(63, n, 7); 
		q = q.mod(Utils.itobi(100)); //for testing purpose
		BigInteger bBuy = Utils.randbi(1, n, 3); 

		return genInput(sid, q, bBuy, n);

	}

	// ----------------- Assisting Functions -------------------
	//check if val is given-bit non-negative int
	protected BigInteger logical_checkInRange(BigInteger val, int bits, String item){
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		ZaRange zr = new ZaRange(config, bits, zg);
		BigInteger res = zr.logical_eval(new BigInteger [] {}, 
			new BigInteger [] {val})[0];
		if(res.equals(Utils.itobi(0))){
			Utils.log(Utils.LOG1, "WARNING: failed range check for: " + item);
		}
		return res; 
	}

	//check if val is given bits non-negative int
	protected Wire checkInRange(Wire val, int bits, String item_not_used){
		ZaGenerator zg = (ZaGenerator) this.getGenerator();
		ZaRange zr = new ZaRange(config, bits, zg);
		zr.build_circuit(new Wire [] {}, new Wire [] {val});
		Wire res = zr.getOutputWires()[0];
		return res; 
	}

	/** encode. Assumption the three elements is already in range */
	public BigInteger logical_encode(BigInteger sid, BigInteger q,
		BigInteger bBuy){
		BigInteger plaintext = sid.shiftLeft(64).add(q.shiftLeft(1).add(bBuy));
		return plaintext;
	}

	/** encode. Assumption the three elements is already in range */
	public Wire encode(Wire sid, Wire q, Wire bBuy){
		int bits = config.getFieldOrder().bitLength();
		Wire plaintext = sid.shiftLeft(bits, 64).add(q.shiftLeft(bits, 1).add(bBuy));
		return plaintext;
	}

	/** check if the two integers are equal to each other */
	public BigInteger logical_eq(BigInteger a, BigInteger b, String msg){
		if(a.equals(b)){
			return Utils.itobi(1);
		}else{
			Utils.log(Utils.LOG1, "WARNING: a: " + a + "!= b: " + b + 
				", for: " + msg);
			return Utils.itobi(0);
		}
	}

	/** check if the two integers are equal to each other */
	public Wire eq(Wire a, Wire b, String msg){
		return a.isEqualTo(b);
	}
	
}
