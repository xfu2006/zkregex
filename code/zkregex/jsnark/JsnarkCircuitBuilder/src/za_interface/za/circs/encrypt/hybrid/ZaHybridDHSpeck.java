/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/14/2021
* ***************************************************/

/** **************************************************
This is essentially a wrapper of the HybridSymmetricEntryption.java
coming with the JSnark, with the following exception:
the DH Exchange (80-bit) is replaced with curve based
DH exchange (128-bit), and the HASH alghorithm is cutomizable (by
Pedersen hash or SHA512), depending on the hash algorithm
specifified in config.  We refactored the code to add unit testing. 
* ***************************************************/
package za_interface.za.circs.encrypt.hybrid;

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
import za_interface.za.circs.exchange.*;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.encrypt.block.*;
import util.Util;

/** 
This is essentially a wrapper of the HybridSymmetricEntryption.java
coming with the JSnark, with the following exception:
the DH Exchange (80-bit) is replaced with curve based
DH exchange (128-bit), and the HASH alghorithm is cutomizable (by
Pedersen hash or SHA512), depending on the hash algorithm
specifified in config.  We refactored the code to add unit testing. 

Input: hX (for DH exchange, public component of the other party).
, s (for DH exchange) - see exchange/ZaECDH.java,
and then the bits of plaintext (128-bit per block, padding is provided).
Output: 2*num_blocks  (64-per bit)
*/
public class ZaHybridDHSpeck extends ZaCirc{
	//** data members **
	protected int plaintext_width;
	protected int num_blocks;

	// ** Operations **
	public ZaHybridDHSpeck(ZaConfig config_in, int plaintext_width, ZaGenerator zg){
		super(config_in, "HybridDHSpeck", zg);
		this.plaintext_width = plaintext_width;
		this.num_blocks = plaintext_width/128;
		if(plaintext_width%128>0) num_blocks++;
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** hX, s, bits of plaintext */
	public int getNumWitnessInputs(){
		return 2 + this.plaintext_width;
	}

	/** 2*n lines: 64-bit numers */
	public int getNumOutputs(){ 
		return 2*num_blocks;
	}

	/** Logicla eval for unit testing
	*/
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		//1. set up the input
		BigInteger hX = arrWitness[0];
		BigInteger s = arrWitness[1];
		BigInteger [] plaintext = new BigInteger [plaintext_width];
		for(int i=0; i<plaintext.length; i++) plaintext[i] = arrWitness[2+i];

		//2. DH exchange
		BigInteger [] ae = new BigInteger [] {};
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaECDH ze = new ZaECDH(config, zg); 
		BigInteger shared_secret = ze.logical_eval
			(ae, new BigInteger [] {hX, s})[0];
		//split it into actually two 128 bits numbers
		//so for some Pedersen hash, bit-range is not going to be issue
		BigInteger [] arr_sec = Utils.packBitsIntoWords(Utils.split(shared_secret, 256), 128);
		if(arr_sec.length!=2) throw new UnsupportedOperationException("arr_sec legnth is not 2: " + arr_sec.length);
		BigInteger  sec0 = arr_sec[0];
		BigInteger  sec1 = arr_sec[1];

		//3. Hash to get the secret key
		ZaHash2 zh = ZaHash2.new_hash(config, zg);
		//hash the shared secret
		BigInteger [] session_key = zh.logical_eval(ae, new BigInteger [] {sec0, sec1}); 
		BigInteger [] bits_session = Utils.split(session_key[0], 256);
		if(bits_session.length!=256) throw new UnsupportedOperationException("bits-session legnth incorrect!");
		BigInteger [] key = Arrays.copyOfRange(bits_session, 0, 128);
		BigInteger [] iv = Arrays.copyOfRange(bits_session, 128, 256);
		
		//4. Speck to encrypt 
		ZaCBCSpeck zcbc = new ZaCBCSpeck(config, plaintext_width, zg);
		BigInteger [] arrwit = new BigInteger [256+plaintext_width];
		for(int i=0; i<128; i++){
			arrwit[i] = key[i];
			arrwit[i+128] = iv[i];
		}
		for(int i=0; i<plaintext_width; i++){
			arrwit[i+256] = plaintext[i];
		}
		BigInteger [] ciphertext = zcbc.logical_eval(ae, arrwit);
		return ciphertext;

	}


	/** build the circuit. hX, s - arrWithess[0], [1].
	Rest of arrWitness are plaintext bits.
	Return 2*n 64-bit numbers */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		//1. set up the input
		Wire hX = arrWitness[0];
		Wire s = arrWitness[1];
		Wire [] plaintext = new Wire [plaintext_width];
		for(int i=0; i<plaintext.length; i++) plaintext[i] = arrWitness[2+i];

		//2. DH exchange
		Wire [] ae = new Wire [] {};
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaECDH ze = new ZaECDH(config, zg); 
		ze.build_circuit(ae, new Wire [] {hX, s});
		Wire shared_secret = ze.getOutputWires()[0];  //256 bits
		//split it into actually two 128 bits numbers
		//so for some Pedersen hash, bit-range is not going to be issue
		Wire [] arr_sec = new WireArray(new Wire [] {shared_secret}).getBits(256).packBitsIntoWords(128); 
		if(arr_sec.length!=2) throw new UnsupportedOperationException("arr_sec legnth is not 2: " + arr_sec.length);
		Wire  sec0 = arr_sec[0];
		Wire  sec1 = arr_sec[1];

		//3. Hash to get the secret key
		ZaHash2 zh = ZaHash2.new_hash(config, zg);
		//hash the shared secret
		zh.build_circuit(ae, new Wire [] {sec0, sec1}); 
		Wire [] session_key = zh.getOutputWires(); //just 1 256-bit element
		Wire [] bits_session = new WireArray(session_key).getBits(256).asArray();
		if(bits_session.length!=256) throw new UnsupportedOperationException("bits-session legnth incorrect!");
		Wire [] key = Arrays.copyOfRange(bits_session, 0, 128);
		Wire [] iv = Arrays.copyOfRange(bits_session, 128, 256);

		//4. Speck to encrypt 
		ZaCBCSpeck zcbc = new ZaCBCSpeck(config, plaintext_width, zg);
		Wire [] arrwit = new Wire [256+plaintext_width];
		for(int i=0; i<128; i++){
			arrwit[i] = key[i];
			arrwit[i+128] = iv[i];
		}
		for(int i=0; i<plaintext_width; i++){
			arrwit[i+256] = plaintext[i];
		}
		zcbc.build_circuit(ae, arrwit);
		Wire [] ciphertext = zcbc.getOutputWires(); //2n 64-bit outputs
		return ciphertext;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions.
		More exactly arrWitness = {hX, s}.
		Here hX is a valid random point's x-coordinate and s
		is a valid exponent allowed by curve */ 
	public BigInteger[][] genRandomInput(int n){
		//1. generate the hX and s first
		ZaGenerator zg = (ZaGenerator) this.generator;
		ZaECDH ze = new ZaECDH(config, zg);
		BigInteger [][] recdh = ze.genRandomInput(n);
		BigInteger hX = recdh[1][0];
		BigInteger s = recdh[1][1];

		//2. generate the random input
		Random rand = new Random(n);
		BigInteger [] arrwit = new BigInteger [plaintext_width+2];
		arrwit[0] = hX;
		arrwit[1] = s;
		for(int i=0; i<plaintext_width; i++){
			int i1 = rand.nextInt()%2;
			i1 = i1<0? 0-i1: i1;
			arrwit[i+2]= Utils.itobi(i1);
		}
		BigInteger [][] res = new BigInteger [][]{
			new BigInteger [] {},
			arrwit
		};
		return res;
	}
	
}
