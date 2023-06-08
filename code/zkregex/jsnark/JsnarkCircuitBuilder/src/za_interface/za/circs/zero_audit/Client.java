/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 06/28/2021
* ***************************************************/

/** **************************************************
This is the logical class of a Client.
A client invests in funds. Note that unlike funds which 
can make adjustment to the ownership of a stock, a client
can either deposit or redeem (clear to zero) of the ownership of
a fund. Thus, a client can own MULTIPLE certificates of a fund.
Logically, its structure is very similar to fund.
A cliet does not maintain a cash account. Whenever, purchasing
a fund, pay "cash" directly.
* ***************************************************/
package za_interface.za.circs.zero_audit;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import za_interface.za.ZaConfig;
import za_interface.za.circs.hash.*;
import za_interface.za.circs.accumulator.*;
import za_interface.za.Utils;



/** **************************************************
This is the logical class of a Client.
A client invests in funds. Note that unlike funds which 
can make adjustment to the ownership of a stock, a client
can either deposit or redeem (clear to zero) of the ownership of
a fund. Thus, a client can own MULTIPLE certificates of a fund.
Logically, its structure is very similar to fund.
A cliet does not maintain a cash account. Whenever, purchasing
a fund, pay "cash" directly.
* ***************************************************/
public class Client{
	// ** data members **
	/** config */
	protected ZaConfig config;
	/** hash algorithm */
	protected ZaHash2 hash;
	/** secret keys */
	protected BigInteger sk1, sk2;
	/** public key of owner */
	protected BigInteger client_id; 
	/** list of all certs */
	protected ArrayList<Cert> arrCerts;

	public Client(BigInteger sk1, BigInteger sk2, ZaConfig config){
		this.sk1 = sk1;
		this.sk2 = sk2;
		this.config = config;
		this.hash = ZaHash2.new_hash(config, null);			
		this.client_id = this.hash.hash2(sk1, sk2);
		this.arrCerts= new ArrayList<Cert>();
	}

	public static Client genRandClient(ZaConfig config){
		return new Client(Utils.randbi(250), Utils.randbi(250), config);
	}

	public ZaInvestVerifier invest(BigInteger fund_id, BigInteger shares, int ts){
		Cert cert = new Cert(client_id, Utils.itobi(0), Utils.randbi(200),
			fund_id, shares, Utils.itobi(ts), config); 
		this.arrCerts.add(cert);
		ZaInvestVerifier zv = new ZaInvestVerifier(config, this, cert, null);
		return zv;
		
	}

}
