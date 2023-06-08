/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/13/2021
* ***************************************************/

/** **************************************************
This is essentially a wrapper of the Speck128
coming with the JSnark.
We refactored the code to add unit testing. It takes a 64-bit
key and then expands it into the cipher key.
* ***************************************************/
package za_interface.za.circs.encrypt.block;

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
This is essentially a wrapper of the Speck128
coming with the JSnark.
Input: 4 lines: first two are 2 64-bit input, 3rd-4th is 2 64-bit key words
  the key will be expanded in the circuit
Output: 2 lines: 2 64-bit
*/
public class ZaSpeck128 extends ZaCirc{

	// ** Operations **
	public ZaSpeck128(ZaConfig config_in, ZaGenerator zg){
		super(config_in, "Speck128", zg);
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** 4 lines: input1(64-bit),  input2(64-bit), key (64-bit, 64-bit) */
	public int getNumWitnessInputs(){
		return 4;
	}

	/** 2 lines: output1(64-bit), output2(64-bit) */
	public int getNumOutputs(){ 
		return 2;
	}

	/** Logicla eval for unit testing
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		BigInteger x, y;
		x = arrWitness[1];
		y = arrWitness[0];
		BigInteger k1 = arrWitness[2];
		BigInteger k2 = arrWitness[3];
		BigInteger [] expandedKey = logical_expandKey(new BigInteger[] {k1, k2});
		
		BigInteger [] ciphertext = new BigInteger[2];
		for (int i = 0; i <= 31; i++) {
			x = Utils.rotate_right_bi(x,64, 8).add(y);
			x = Utils.trimBits(x, 64);
			x = Utils.xorBitwise(x, expandedKey[i], 64);
			y = Utils.xorBitwise(Utils.rotate_left_bi(y,64, 3), x, 64);
		}
		ciphertext[1] = x;
		ciphertext[0] = y;
		return ciphertext;
	}

	/**
	 * From Kosba's original implementation of Speck128CipherGadget.java 
	 * @param key
	 *            : 2 64-bit words
	 * @return 32 64-bit words
	 */
	public Wire[] expandKey(Wire[] key) {
		ZaGenerator generator = (ZaGenerator) this.generator;
		Wire[] k = new Wire[32];
		Wire[] l = new Wire[32];
		k[0] = key[0];
		l[0] = key[1];
		for (int i = 0; i <= 32 - 2; i++) {
			l[i + 1] = k[i].add(l[i].rotateLeft(64, 56));
			l[i + 1] = l[i + 1].trimBits(65, 64);
			l[i + 1] = l[i + 1].xorBitwise(generator.createConstantWire(i), 64);
			k[i + 1] = k[i].rotateLeft(64, 3).xorBitwise(l[i + 1], 64);
		}
		return k;
	}

	/** Structurely simulate the Wire implementation,
		all wires replaced by 64-bit BigIntegers */
	public static BigInteger [] logical_expandKey(BigInteger [] key){
		BigInteger[] k = new BigInteger[32];
		BigInteger[] l = new BigInteger[32];
		k[0] = key[0];
		l[0] = key[1];
		for (int i = 0; i <= 32 - 2; i++) {
			l[i + 1] = k[i].add(Utils.rotate_left_bi(l[i],64, 56));
			l[i + 1] = Utils.trimBits(l[i + 1], 64);
			l[i + 1] = Utils.xorBitwise(l[i +1], Utils.itobi(i), 64);
			k[i + 1] = Utils.xorBitwise(Utils.rotate_left_bi(k[i],64, 3),
							l[i + 1], 64);
		}
		return k;
	}

	/** build the circuit. plaintext - arrWitness[0,1],
	key - arrWitess[2,3], output: two 64-bit numbers */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire x, y;
		x = arrWitness[1];
		y = arrWitness[0];
		Wire k1 = arrWitness[2];
		Wire k2 = arrWitness[3];
		Wire [] expandedKey = expandKey(new Wire [] {k1, k2});
		
		Wire [] ciphertext = new Wire[2];
		for (int i = 0; i <= 31; i++) {
			x = x.rotateRight(64, 8).add(y);
			x = x.trimBits(65, 64);
			x = x.xorBitwise(expandedKey[i], 64);
			y = y.rotateLeft(64, 3).xorBitwise(x, 64);
		}
		ciphertext[1] = x;
		ciphertext[0] = y;
		return ciphertext;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		More exactly arrWitness = {hX, s}.
		Here hX is a valid random point's x-coordinate and s
		is a valid exponent allowed by curve */ 
	public BigInteger[][] genRandomInput(int n){
		Random rand = new Random(n);
		int i1 = rand.nextInt();
		int i2 = rand.nextInt();
		int key = rand.nextInt();
		int key2 = rand.nextInt();
		i1 = i1<0? 0-i1: i1;
		i2 = i2<0? 0-i2: i2;
		key = key<0? 0-key: key;
		key2 = key2<0? 0-key2: key2;
		BigInteger bi1 = Utils.itobi(i1);
		BigInteger bi2 = Utils.itobi(i2);
		BigInteger bikey = Utils.itobi(key);
		BigInteger bikey2 = Utils.itobi(key2);
		BigInteger [][] res = new BigInteger [][]{
			new BigInteger [] {},
			new BigInteger [] {bi1, bi2, bikey, bikey2}
		};
		return res;
	}
	
}
