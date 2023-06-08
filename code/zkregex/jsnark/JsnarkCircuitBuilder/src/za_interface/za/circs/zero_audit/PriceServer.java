/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/25/2021
Revised: 10/22/2021 -> add a CAP to the stock ID even though
the tree can be in any height
* ***************************************************/

/** **************************************************
This is the logical class of a PriceServerer.
A price server is a collection of PriceTrees (at this moment
MerkleTreeAccumulator).
It provides logical functions such as
getPrice, getRoot, and get Day.
Whenever, built, PriceServer is fixed to a FIXED pseudo-random
price pair. All prices are limited to 16 bits (2^16 unsigned int, though
this is not a hard restriction).
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import java.util.Random;
import za_interface.za.ZaConfig;
import za_interface.za.ZaGenerator;
import za_interface.za.circs.accumulator.merkle.*;
import za_interface.za.circs.hash.*;
import za_interface.za.Utils;
import java.io.Serializable;

/** **************************************************
This is the logical class of a PriceServerer.
A price server is a collection of PriceTrees (MerkleTreeAccmulator)
[this later can be improved to allow any accumulator]
It provides logical functions such as
getPrice, getRoot, and get Day.
Whenever, built, PriceServer is fixed to a FIXED pseudo-random
price pair. All prices are limited to 16 bits (2^16 unsigned int, though
this is not a hard restriction).

Its corresponding verifier is: ZaPriceVerifier
* ***************************************************/
public class PriceServer implements Serializable{
	// ** data members **
	/** how many timestamps */
	public int n_tss; 
	/** log2_stocks, number of stocks = 2^log_stocks-1, with 0 reserved for cash */
	public int log2_stocks; 
	/** config */
	public ZaConfig config;
	/** hash algorithm */
	public ZaHash2 hash;
	/** accumulators */
	public MerkleAccumulator [] accs;
	/** need zg for generating a new hash alg, will need to get
		the one from ZaPriceVerifier */
	public ZaGenerator zg;
	public static int MAX_SID = 128; //that's how many we will generate
	//the others will be dummy leaf leaves 


	// ** operations **
	public static PriceServer create(int ntss, int log2stocks, ZaConfig config, ZaGenerator zg){
		String fname = "run_dir/serialize/PriceServer_" + ntss + "_" + log2stocks + "_" + 
			config.toString()+ ".dump";
		PriceServer ps = null;
		if(Utils.file_exists(fname) ){
			ps = (PriceServer) Utils.deserialize_from(fname);
		}else{
			ps = new PriceServer(ntss, log2stocks, config, zg);
			Utils.serialize_to(ps, fname);
		}
		ps.config = config;
		ps.zg = zg;
		return ps;
		
	}

	public PriceServer(int ntss, int log2stocks, ZaConfig config, ZaGenerator zg){
		//0. set up the generator
		this.config = config;
		this.zg = zg;

		//1. create ntss of accumulators
		this.n_tss = ntss;
		this.log2_stocks = log2stocks;
		this.accs = new MerkleAccumulator [n_tss];
		this.hash = ZaHash2.new_hash(config, zg);

		//2. add sample prices for stocks to accumulators
		int num_stocks = 1<<log2_stocks;
		num_stocks = num_stocks>MAX_SID? MAX_SID: num_stocks;
		for(int i=0; i<n_tss; i++){
			Utils.log(Utils.LOG2, "--- Adding stocks for ts: " + i);
			accs[i] = new MerkleAccumulator(log2_stocks, config, zg);
			BigInteger [] data = new BigInteger [num_stocks];
			for(int sid=0; sid<num_stocks && sid<MAX_SID; sid++){
				data[sid] = genPriceRecord(i, sid);
				Utils.log(Utils.LOG2, "---+++ Adding stocks " + sid + " of " + num_stocks);
			}
			accs[i].add_elements(data);
		}
	}

	/** generate the merkle tree leaf for that ts and stock id */
	protected BigInteger genPriceRecord(int ts, int sid){
		int price = getPrice(ts, sid); 
		BigInteger leaf = hash.hash2(Utils.itobi(sid), 
			Utils.itobi(price));
		return leaf;
	}

	/** get the price of the ts, this is a psedu-random num
		generator */
	public int getPrice(int ts, int sid){
		if(sid==0) return 1; //for cash entity
		if(sid>=MAX_SID) throw new RuntimeException("ERROR: sid>MAX_SID");
		int res = (sid *3791 + ts*2311)%9743*10;
		return res;
	}

	/** get tree root of given ts */
	public BigInteger getRoot(int ts){
		return accs[ts].get_hash()[0];
	}

	/** generate the proof */
	public BigInteger [] gen_proof(int ts, int sid){
		BigInteger rec = genPriceRecord(ts, sid);
		MerkleAccumulator acc = accs[ts];
		BigInteger [] proof = acc.gen_proof(rec);
		return proof;	
	}


}
