/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/28/2021
Fixed: 04/29/2021
* ***************************************************/

/** **************************************************
A sequence of Sha2 components for testing performance.
It takes n secret inputs (where n >=2) and generates
one output line. It is built upon n-1 Sha2 components.
* ***************************************************/
package za_interface.za.circs.hash.sha;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;
import za_interface.za.ZaCirc;
import za_interface.za.Utils;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.ZaHash2;
import za_interface.za.circs.hash.sha.ZaSha2;
import util.Util;

/**
	It takes n inputs (thus built upon n-1 ZaSha2Path)
*/
public class ZaSha2Path extends ZaCirc{
	// ** data members **
	int n;

	// ** Operations **
	public ZaSha2Path(ZaConfig config_in, int n, ZaGenerator zg){
		super(config_in, "Sha2Path", zg);
		this.n = n;
	}

	/** no public input */
	public int getNumPublicInputs(){
		return 0;
	}

	/** n prime field elements regarded as private witness */
	public int getNumWitnessInputs(){
		return n;
	}

	/** return one 256-bit prime field element, value always
	less than prime field order */
	public int getNumOutputs(){ 
		return 1;
	}


	/** logical operation. Hash the n elements one by one */
	public BigInteger [] logical_eval(BigInteger [] arrPubInput, 
			BigInteger [] arrWitness){
		ZaSha2 zs = new ZaSha2(this.config, (ZaGenerator) this.generator);
		BigInteger [] arr = arrWitness;
		BigInteger a = arr[0];
		BigInteger b = arr[1];
		for(int i=0; i<n-1; i++){
			b = arr[i+1];
			a = zs.hash2(a, b);
		}	

		BigInteger [] arrout = new BigInteger [1];
		arrout[0] = a;
		return arrout;
	}

	/** build the circuit. Needs to supply the input wires */
	public Wire [] build_circuit_worker(Wire [] arrPubInput, 
			Wire [] arrWitness){
		Wire [] arr = arrWitness;
		Wire a = arr[0];
		Wire b = arr[1];
		Wire zero = arr[n-1];
		for(int i=0; i<n-1; i++){
			b = arr[i+1];
			ZaSha2 zs = new ZaSha2(this.config, (ZaGenerator) this.generator);
			zs.build_circuit(new Wire [] {}, new Wire [] {a, b});
			a = zs.getOutputWires()[0];
		}	

		Wire [] arrout = new Wire [1];
		arrout[0] = a;
		return arrout;
	}

	/** Generate the random inputs, used for unit testing. ret[0] should be 
		arrPubInput, and ret[1] should be arrWitness[]
		The dimension should match that of getNum() functions,
		@param: num: the random id sequence
	 */ 
	public BigInteger[][] genRandomInput(int randid){
		BigInteger modulus = this.config.getFieldOrder();
		BigInteger [] arr2 = new BigInteger [n];
		if(randid==0){//simple case FIXED case [0, 1, 2, ...]
			for(int i=0; i<n; i++){
				arr2[i] = Utils.itobi((i+1)*1371).mod(modulus);
			}	
		}else{
			for(int i=0; i<n; i++){
				arr2[i] = Utils.randbi((i+1)*1371).mod(modulus);
			}	
		}
		BigInteger [][] ret = new BigInteger [][] {
			new BigInteger [] {},
			arr2
		};
		return ret;
	}

	
}
