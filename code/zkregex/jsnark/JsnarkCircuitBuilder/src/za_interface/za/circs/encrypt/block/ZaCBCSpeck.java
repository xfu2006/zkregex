/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/14/2021
* ***************************************************/

/** **************************************************
This is essentially a wrapper of the SymmetricEncryptionCBCGadget.java
coming with the JSnark.
We refactored the code to add unit testing.  It works for CBCSpeck only.
* ***************************************************/
package za_interface.za.circs.encrypt.block;

import java.util.Arrays;
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
import za_interface.za.circs.curve.*;
import za_interface.za.circs.encrypt.block.*;
import util.Util;

/** 
This is essentially a wrapper of the SymmetricEncryptionCBCGadget.java
coming with the JSnark.
We refactored the code to add unit testing.  It works for CBCSpeck only.
Input: first 128-bits key bits, next 128-bit IV (initial vector) bits,
rest are 128xblocks bits. The gadget will
perform padding if necessary when rest are not multiples of 128
Output: 128-bits * number_of_blocks where number_of_blocks is the
ceil(num_plaintext_bits/128).
*/
public class ZaCBCSpeck extends ZaCirc{
	// *** data members ***
	protected int plaintext_length;
	protected int num_blocks;

	// ** Operations **
	public ZaCBCSpeck(ZaConfig config_in, int plaintext_length, ZaGenerator zg){
		super(config_in, "CBCSpeck", zg);
		this.plaintext_length = plaintext_length;
		this.num_blocks = plaintext_length/128;
		if(plaintext_length%128!=0) num_blocks++;
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 128-bit keybits, 128-bit IV bits, plaintext_length bits */
	public int getNumWitnessInputs(){
		return 128 + 128 + plaintext_length;
	}

	/** 128 * number_blocks */
	public int getNumOutputs(){ 
		return 128*num_blocks;
	}

	/** Logicla eval for unit testing
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. prepare the key
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaSpeck128 zp128 = new ZaSpeck128(this.config, zg);
		int blockSize = 128;
		BigInteger [] keyBits = new BigInteger [blockSize];
		for(int i=0; i<blockSize; i++) keyBits[i] = arrWitness[i];
		BigInteger[] preparedKey;
		BigInteger[] packedKey = Utils.packBitsIntoWords(keyBits, 64);
		preparedKey = zp128.logical_expandKey(packedKey);
		BigInteger [] ivBits = new BigInteger [blockSize];
		for(int i=0; i<blockSize; i++) ivBits[i] = arrWitness[i+blockSize];

		//2. prepare the plaintext
		BigInteger [] plaintext = new BigInteger [plaintext_length];
		for(int i=0; i<plaintext_length; i++){
			 plaintext[i] = arrWitness[i+2*blockSize];
		}
		BigInteger [] plaintextBits = new BigInteger [num_blocks*blockSize];
		for(int i=0; i<plaintextBits.length; i++){
			plaintextBits[i] = i<plaintext.length?plaintext[i]: Utils.itobi(0);
		}
		BigInteger [] prevCipher = ivBits;

		//3. processing 
		BigInteger [] ciphertext = new BigInteger[2*num_blocks];
		for (int i = 0; i < num_blocks; i++) {
			BigInteger [] msgBlock = new BigInteger [blockSize];
			BigInteger [] xored = new BigInteger [blockSize];
			for(int j=0; j<blockSize; j++){
				msgBlock[j] = plaintextBits[i*blockSize+j];
				xored[j] = msgBlock[j].xor(prevCipher[j]);
			}
			BigInteger [] tmp = Utils.packBitsIntoWords(xored, 64);
			ZaSpeck128 zp = new ZaSpeck128(this.config, zg);
			BigInteger [] arrwit = new BigInteger [] {
				tmp[0], tmp[1], preparedKey[0], preparedKey[1]
			};
			BigInteger [] outputs = zp.logical_eval(
				new BigInteger [] {}, arrwit);
			prevCipher = Utils.getBits(outputs, 64);
			ciphertext[i*2] = outputs[0];
			ciphertext[i*2+1] = outputs[1];
		}
		return ciphertext;


	}


	/** build the circuit. 128-bit key, 128-bit IV, the rest inputs */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. prepare the key
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaSpeck128 zp128 = new ZaSpeck128(this.config, zg);
		int blockSize = 128;
		Wire [] keyBits = new Wire [blockSize];
		for(int i=0; i<blockSize; i++) keyBits[i] = arrWitness[i];
		Wire[] preparedKey;
		Wire[] packedKey = new WireArray(keyBits).packBitsIntoWords(64);
		preparedKey = zp128.expandKey(packedKey);
		Wire [] ivBits = new Wire [blockSize];
		for(int i=0; i<blockSize; i++) ivBits[i] = arrWitness[i+blockSize];

		//2. prepare the plaintext
		Wire [] plaintext = new Wire [plaintext_length];
		for(int i=0; i<plaintext_length; i++) plaintext[i] = arrWitness[i+2*blockSize];
		Wire [] plaintextBits = new WireArray(plaintext).
			adjustLength(num_blocks* blockSize).asArray();
		WireArray prevCipher = new WireArray(ivBits);

		//3. processing 
		Wire [] ciphertext = new Wire[0];
		for (int i = 0; i < num_blocks; i++) {
			WireArray msgBlock = new WireArray(
					Arrays.copyOfRange(
						plaintextBits, i*blockSize, (i+1) * blockSize)
			);
			Wire[] xored = msgBlock.xorWireArray(prevCipher).asArray();
			Wire[] tmp = new WireArray(xored).packBitsIntoWords(64);
			ZaSpeck128 zp = new ZaSpeck128(this.config, zg);
			Wire [] arrwit = new Wire [] {
				tmp[0], tmp[1], preparedKey[0], preparedKey[1]
			};
			zp.build_circuit(new Wire [] {}, arrwit);
			Wire[] outputs = zp.getOutputWires(); //2 64-bit numbers
			prevCipher = new WireArray(outputs).getBits(64);
			ciphertext = Util.concat(ciphertext, 
				prevCipher.packBitsIntoWords(64));
		}
		return ciphertext;

	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		*/ 
	public BigInteger[][] genRandomInput(int n){
		Random rand = new Random(n);
		int blocksize = 128;
		int len = this.plaintext_length + 2*blocksize;
		BigInteger [] arrwit = new BigInteger [len];
		for(int i=0; i<len; i++){
			int ri = rand.nextInt(100000)%2;
			ri = ri>0? ri: 0-ri;
			arrwit[i] = Utils.itobi(ri);
		}
		BigInteger [][] res = new BigInteger [][]{
			new BigInteger [] {}, arrwit
		};
		return res;
	}
	
}
