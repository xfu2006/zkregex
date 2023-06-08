/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 10/05/2021
* ***************************************************/

/** **************************************************
This is essentially a wrapper of the 
	*** examples/generators/rsa/RSAEncryptionCircuitGenerator.java ***
Input is a 3-byte message (but padded to 2048bit-256 bytes). 
It essentially calls the RSAEncryptionV1_5 gadget for 
performing the encryption (using public exponent 0x10001, 
by doing LongElement mul 17 times).
* note we are lasy here and do not provide a separate check of logical_eval
* ***************************************************/
package za_interface.za.circs.encrypt.pubkey;

import java.math.BigInteger;
import java.util.Random;
import java.util.Arrays;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.WireArray;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.curve.*;
import za_interface.za.circs.encrypt.block.*;
import util.Util;

import circuit.eval.CircuitEvaluator;
import examples.gadgets.rsa.RSAEncryptionV1_5_Gadget;
import circuit.eval.Instruction;
import circuit.auxiliary.LongElement;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import examples.generators.rsa.RSAUtil;

/** 
Input: 64-lines (each line is a byte) - all are secret input 
	It's the message to encrypt
Output: 2048 lines (2048-bit)
*/
public class ZaRSA extends ZaCirc{
	protected int plainTextLength = 3; //3 bytes, will be padded to 2048 bit
	protected int rsaKeyLength = 2048; //2048 bit
	protected String msg; //the plaintext 3-bytes but will be padded
	protected BigInteger modulus; //2048-bit modulus
	protected Wire [] inputMessage; //3 elements
	protected LongElement rsaModulus; //modulus encoded as wire
	protected byte [] cipherText;
	protected byte [] sampleRandomness; //extracted from Java.sec, see constructor

	// ** Operations **
	public ZaRSA(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "RSA", zg);
		this.msg = ""; //can be randomized later
		for (int i = 0; i < plainTextLength; i++) {
			msg = msg + (char) ('a' + i%26);
		}

		try {//use standard java
			//FIXED random for debugging (if needed enable it)
			//SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        	//random.setSeed("12345".getBytes("us-ascii"));
			SecureRandom random = new SecureRandom();
			KeyPairGenerator secgen = KeyPairGenerator.getInstance("RSA");
			secgen.initialize(rsaKeyLength, random);
			KeyPair pair = secgen.generateKeyPair();
			Key pubKey = pair.getPublic();
			this.modulus = ((RSAPublicKey) pubKey).getModulus();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			Key privKey = pair.getPrivate();
			cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
			this.cipherText = cipher.doFinal(msg.getBytes());

			byte[] cipherTextPadded = new byte[cipherText.length + 1];
			System.arraycopy(cipherText, 0, cipherTextPadded, 1, cipherText.length);
			cipherTextPadded[0] = 0;

			byte[][] result = RSAUtil.extractRSARandomness1_5(cipherText,
					(RSAPrivateKey) privKey);
			// result[0] contains the plaintext (after decryption)
			// result[1] contains the randomness


			boolean check = Arrays.equals(result[0], msg.getBytes());
			if (!check) {
				throw new RuntimeException(
						"Randomness Extraction did not decrypt right");
			}
			this.sampleRandomness = result[1];
		} catch (Exception e) {
			System.err
					.println("Error while generating sample input for circuit");
			e.printStackTrace();
		}

	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 3 lines (1-byte each) */
	public int getNumWitnessInputs(){
		return plainTextLength;
	}

	/** 256 lines */
	public int getNumOutputs(){ 
		return 256;
	}

	/** Logicla eval for unit testing (the result is already built in 
	constructor */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger [] ciphertext = new BigInteger[this.getNumOutputs()];
		for(int i=0; i<cipherText.length; i++){//somehow needs reverse order
			int val = cipherText[cipherText.length-i-1];
			if(val<0){val = 256 + val;}
			ciphertext[i] = Utils.itobi(val);
		}
		return ciphertext;
	}


	/** build the circuit. plaintext - arrWitness,  no public input
	output: 2048-bits */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. create wires and RSA gadget
		CircuitGenerator.setActiveCircuitGenerator(generator);
		this.inputMessage = arrWitness;
		for(int i=0; i<inputMessage.length;i++){
						inputMessage[i].restrictBitLength(8);
		}
		this.rsaModulus = this.generator.createLongElementInput(rsaKeyLength);
		Wire [] randomness = this.generator.
			createProverWitnessWireArray(RSAEncryptionV1_5_Gadget
				.getExpectedRandomnessLength(rsaKeyLength, plainTextLength));
	
		//2. set up values
		generator.specifyProverWitnessComputation(new Instruction() {
                public void evaluate(CircuitEvaluator evaluator) {
					for (int i = 0; i < inputMessage.length; i++) {
						evaluator.setWireValue(inputMessage[i], (int) (msg.charAt(i)));
					}
					for (int i = 0; i < randomness.length; i++) {
						evaluator.setWireValue(randomness[i], (sampleRandomness[i]+256)%256);
					}
					evaluator.setWireValue(rsaModulus, modulus, 
						LongElement.CHUNK_BITWIDTH);

				}
		});
				
		RSAEncryptionV1_5_Gadget rsaEncryptionV1_5_Gadget = 
						new RSAEncryptionV1_5_Gadget(rsaModulus, inputMessage,
							randomness, rsaKeyLength);
		rsaEncryptionV1_5_Gadget.checkRandomnessCompliance();

		//3. generate 256 output lines in bytes (2048 bits)
		Wire[] cipherTextInBytes = rsaEncryptionV1_5_Gadget.getOutputWires(); 
		return cipherTextInBytes;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The input is directy determined by the "msg" attribute (not by n)
		*/ 
	public BigInteger[][] genRandomInput(int n){
		Random rand = new Random(n);
		BigInteger [] inputs = new BigInteger[plainTextLength];
		for(int i=0; i<plainTextLength; i++){
			int val= this.msg.charAt(i);
			inputs[i] = Utils.itobi(val);
		}
		BigInteger [][] res = new BigInteger [][]{
			new BigInteger [] {},
			inputs
		};
		return res;
	}
	
}
