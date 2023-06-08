/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 05/22/2021
* ***************************************************/

/** **************************************************
This is the logical class of a Certificate. It is the
hash of the following:
[serial_id, SID, q, ts]
serial_id: the spending ID
SID: stock/entity ID (see zero audit paper)
q: quantity
ts: timestamp
All are 256 bit field elements
serial_id is used as spending ID, it is the hash of
[pk of owner, counter, random nonce]
where counter and random nonce is 128 bit each
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import java.util.Random;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.*;
import za_interface.za.Utils;

/** **************************************************
This is the logical class of a Certificate. It is the
hash of the following:
[serial_id, SID, q, ts]
serial_id: the spending ID
SID: stock/entity ID (see zero audit paper)
q: quantity
ts: timestamp
All are 256 bit field elements
serial_id is used as spending ID, it is the hash of
[pk of owner, counter, random nonce]
where counter and random nonce is 128 bit each
* ***************************************************/
public class Cert{
	// ** data members **
	/** config */
	protected ZaConfig config;
	/** hash algorithm */
	protected ZaHash2 hash;
	/** public key of owner */
	protected BigInteger pk; 
	/** counter of the cert for SID of the owner*/
	protected BigInteger counter; 
	/** randon nounce */
	protected BigInteger nonce;
	/** SID: stock id */
	protected BigInteger SID;
	/** quanitty should be limited to [0,2^64] */
	protected BigInteger q;
	/** timestamp */
	protected BigInteger ts;
	/** serial id */
	protected BigInteger serial_no;
	/** cert root */
	protected BigInteger root;

	/** check bits of the given variable */
	private void checkBits(BigInteger var, String varname, int bitsLimit){
		if(var.bitLength()>bitsLimit){
			throw new RuntimeException(varname + "'s bits > " + bitsLimit);
		}
	}
	/** constructor all elements are 256-bit prime field elements
	permitted by the hash algorithm, note that for some hash such as
	pedersen hash it's slightly restricted depending on curve */
	public Cert(BigInteger pk, BigInteger counter, BigInteger nonce, BigInteger SID, BigInteger q, BigInteger ts, ZaConfig config){
		//1. set up
		this.pk = pk;
		this.counter = counter;
		this.nonce = nonce;
		this.SID = SID;
		this.q = q;
		this.ts = ts;
		this.config = config;
		this.hash = ZaHash2.new_hash(config, null);			
		BigInteger temp = this.hash.hash2(pk, counter);
		this.serial_no = this.hash.hash2(temp, nonce);

		//2. generate root
		BigInteger b1 = hash.hash2(serial_no, SID);
		BigInteger b2 = hash.hash2(q, ts);
		this.root = hash.hash2(b1, b2);
	}

	public BigInteger getRoot() {return root;}
	public BigInteger getQ() {return q;}

	/** Generate a random cert */
	public static Cert genRandCert(int n, ZaConfig config){
		ZaHash2 hash = ZaHash2.new_hash(config, null);			
		Random rand = new Random(n);
		BigInteger [] r2 = hash.genRandomInput(n)[1];
		BigInteger pk = r2[0];
		BigInteger SID = r2[1];
		BigInteger [] r2_2 = hash.genRandomInput(n)[1];
		BigInteger q = r2_2[0];
		BigInteger ts = r2_2[1];
		BigInteger [] r2_3 = hash.genRandomInput(n)[1];
		BigInteger counter = r2_3[0];
		BigInteger nonce = r2_3[1];
		return new Cert(
			pk, counter, nonce, SID, q, ts, config
		);
	}

}
