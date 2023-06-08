/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/19/2021
* ***************************************************/

/** **************************************************
This class implements MerkleTree (implements accmulator)
* ***************************************************/
package za_interface.za.circs.accumulator.merkle;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import za_interface.za.circs.accumulator.*;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.hash.*;
import za_interface.za.Utils;


/** **************************************************
This class implements MerkleTree (implements accmulator).
Note that the Hashing algorithm is parameterized by the config.
The elements that can be accmulated is determined by the
hash algorithm.
* ***************************************************/
public class MerkleAccumulator extends Accumulator implements Serializable{
	//** data members **
	/** number of layers, the capacity of accmulator 2^n */
	protected int n; 
	/** all nodes, bottom layer are the leaf (value) nodes */
	ArrayList<ArrayList<BigInteger>> layers;
	/** config */
	protected ZaConfig config;
	/** ZaGenerator */
	protected ZaGenerator zg;
	/** number of elements */
	protected int size;
	/** map element to index */
	protected HashMap<BigInteger, BigInteger> map;
	/** hash alg */
	protected ZaHash2 hash;

	//** operations **
	/** construct a accmulator with the given capacity 
		@param log2_capacity - log2(desired_capacity). for given
		10, it allows to accomodate 2^10 elements.
		@config_in - the ZaConfig which specifies the hashing algorithm
	*/
	public MerkleAccumulator(int log2_capacity, ZaConfig config_in, ZaGenerator zg){
		this.n = log2_capacity;
		this.config = config_in;
		this.zg = zg;
		this.size = 0;
		this.layers = new ArrayList<ArrayList<BigInteger>>();
		this.map = new HashMap<BigInteger, BigInteger>();
		for(int i=0; i<n+1; i++){//note n+1 layers for 2^n capacity
			ArrayList<BigInteger> ab = new ArrayList<BigInteger>();
			this.layers.add(ab);
		}
		this.hash = ZaHash2.new_hash(config, zg);
	}

	/** load from system */
	public static MerkleAccumulator create(int log2_capacity, ZaConfig config_in, ZaGenerator zg){
		String fname = get_ser_filename(log2_capacity, config_in);
		MerkleAccumulator mc = new 
			MerkleAccumulator(log2_capacity, config_in, zg);
		return mc;
	}

	/** get the serialization file name */
	private static String get_ser_filename(int log2_capacity, ZaConfig config){
		String fname = "run_dir/MerkleAccumualator_"+log2_capacity+"_"+config.toString()+".dump";
		return fname;
	}

	/** get the size: number of elements */
	public int get_size(){
		return this.size;
	}

	/** get the log2(capacity) */
	public int get_capacity_log(){
		return this.n;
	}

	/** call hash to generate a random element */
	private BigInteger rand_ele(){
		Random rand = new Random();
		int rn = rand.nextInt();
		BigInteger fake = hash.genRandomInput(rn)[1][0];
		return fake;
	}

	/** generate the corresponding verifier */
	public ZaAccumulatorVerifier genVerifier(){
		return new ZaMerkleAccVerifier(config, this, zg);  
	};

	/** add one element */
	protected void add_element(BigInteger ele){
		//1. validity check
		if(this.map.containsKey(ele)){
			throw new RuntimeException("Element: " + ele + " is already contained in the accmulator!");
		}

		//2. append (if the current size is ODD, then the last element is
		//padded as a random nonce)
		if(this.size%2==0){//append two elements (the 2nd one is a FAKE)
			BigInteger fake = this.rand_ele();
			this.layers.get(n).add(ele);
			this.layers.get(n).add(fake);
		}else{//reset the LAST element (rewrite the nonce)
			this.layers.get(n).set(this.size, ele);
		}
		this.size++;

		//3. update the root idx
		this.update_for_leaf(this.size-1);
		this.map.put(ele, BigInteger.valueOf(this.size-1));
	}

	/** update the hash chain for leaf at the given index */
	public void update_for_leaf(int idx){
		int cur_idx = idx/2;
		for(int layer_idx=n-1; layer_idx>=0; layer_idx--){
			//1. compute hash
			ArrayList<BigInteger> layer = this.layers.get(layer_idx);
			ArrayList<BigInteger> last_layer = this.layers.get(layer_idx+1);
			int len = layer.size();
			BigInteger x1 = last_layer.get(cur_idx*2);
			if(cur_idx*2+1==last_layer.size()){
				BigInteger fake = this.rand_ele();
				last_layer.add(fake);
			}
			
			BigInteger x2 = last_layer.get(cur_idx*2+1);
			BigInteger new_val = hash.hash2(x1, x2);

			//2. update the layer node
			if(len<cur_idx){
				throw new UnsupportedOperationException("len: " + len + "<cur_idx-1: " + (cur_idx-1));
			}else if(len==cur_idx){//append the element
				layer.add(new_val);
			}else{
				layer.set(cur_idx, new_val);
			}
			cur_idx = cur_idx/2;

		}
	}

	/** add the supplied elements as new elements, at this moment
	we do not allow drop elements */
	public void add_elements(BigInteger [] set){	
		for(BigInteger x: set){
			this.add_element(x);
		}
	}

	/** return the 'hash' of all elements, which is used
	for verify membership, it may be one or more BigIntegers */
	public BigInteger [] get_hash(){
		BigInteger [] arr = new BigInteger [] {
			this.layers.get(0).get(0)
		};
		return arr;
	}

	/** generate the proof for the given element. Return n+1 elements.
		arr[0] - packed bits of position (0 for left and 1 for right).
		e.g., 0 means arr[1] is used as a left sibling.
		arr[1 to n] - the nodes along the verification path	
	 */
	public BigInteger [] gen_proof(BigInteger element){
		//1. both arrays are kind of reversed order from layer n+1 to 1
		BigInteger [] bits = new BigInteger [n];
		BigInteger [] sibs = new BigInteger [n];
		if(!this.map.containsKey(element)){
			throw new UnsupportedOperationException("element not exist! Element: " + element);
		}
		int idx = this.map.get(element).intValue();	

		//2. build up the layers
		for(int i=0; i<n; i++){
			int layer_id = n - i;
			ArrayList<BigInteger> layer = this.layers.get(layer_id);
			BigInteger sib = idx%2==0? layer.get(idx+1): layer.get(idx-1);
			BigInteger bit = idx%2==0? Utils.itobi(1): Utils.itobi(0);
			bits[i] = bit;
			sibs[i] = sib;
			idx = idx/2;
		}
		
		//3. build result
		BigInteger [] res = new BigInteger [n+1];
		res[0] = Utils.pack(bits);
		for(int i=1; i<n+1; i++){
			res[i] = sibs[i-1];
		}
		return res;
	}

	public ZaAccumulatorVerifier genAccumulatorVerifier(ZaGenerator zg){
		return new ZaMerkleAccVerifier(config, this, zg);
	}

}
