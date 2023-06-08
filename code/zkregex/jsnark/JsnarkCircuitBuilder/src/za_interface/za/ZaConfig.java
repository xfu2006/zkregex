/* ***************************************************
Dr. CorrAuthor
@Copyright 2021
Created: 04/18/2021
* ***************************************************/

/** ************************************************
This is the configuration class for building circuits,
it includes the configuration of prime field size,
choice of hash functions etc.

Note that: it is NOT of singleton pattern. Each
ZaCircuit is Parameterized by a Config. That is, 
when instiating into real circuite wires, the prime field size
and choice of hash functions will be needed.
* ***************************************************/

package za_interface.za;
import za_interface.PrimeFieldInfo;
import java.util.ArrayList;
import circuit.config.Config;
import java.math.BigInteger;
import java.io.Serializable;

/**
  Configuration object for ZaCircuit
*/
public class ZaConfig implements Cloneable, Serializable{
	// *** STATIC CONSTANTS ***
	public static PrimeFieldInfo [] PrimeFields = {
		PrimeFieldInfo.LIBSNARK,	
		PrimeFieldInfo.LIBSPARTAN,	
		PrimeFieldInfo.AURORA,	
	}; 


	public static enum EnumHashAlg {
		Pedersen,
		Sha,
		Poseidon,
		MiMC
	};

	// *** SETTING ***
	public PrimeFieldInfo field_info;	
	public EnumHashAlg hash_alg;	

	// *** PUBLIC OPERATIONS ***
	public ZaConfig(PrimeFieldInfo field_info, EnumHashAlg hash_alg){
		this.field_info = field_info;
		this.hash_alg = hash_alg;
	} 

	public ZaConfig copy(){
		try{
			return (ZaConfig) this.clone();
		}catch(Exception exc){
			Utils.fail(exc.toString());
		}
		return null;
	}

	/**
		Return a default config (LIBSPARTAN)
		Hash: Sha (at this momenet, will be updated to Poseidon)
	*/
	public static ZaConfig defaultConfig(){
		//return new ZaConfig(PrimeFieldInfo.LIBSPARTAN, EnumHashAlg.Sha);	
		return new ZaConfig(PrimeFieldInfo.LIBSNARK, EnumHashAlg.Pedersen);	
	}

	@Override
	public String toString(){
		return this.field_info.name + "_" + this.hash_alg;
	}

	/**
		enumerate all possible zaconfigurations
	*/
	public static ArrayList<ZaConfig> enumAllZaConfigs(){
		ArrayList<ZaConfig> arr = new ArrayList<ZaConfig>();
		EnumHashAlg [] arrHash = new EnumHashAlg [] {
			EnumHashAlg.Sha,
			EnumHashAlg.Pedersen,
			EnumHashAlg.Poseidon
		};
		for(int i=0;i<PrimeFields.length; i++){
			PrimeFieldInfo pfi = PrimeFields[i];
			for(int j=0; j<arrHash.length; j++){
				ZaConfig zc = new ZaConfig(pfi, arrHash[j]);
				arr.add(zc);
			}
		}
		return arr;
	} 
	/* return the field order */
	public BigInteger getFieldOrder(){
		return this.field_info.order;
	}

	/** apply the config */
	public void apply_config(){
		Config.FIELD_PRIME= this.field_info.order;
		Config.LOG2_FIELD_PRIME = Config.FIELD_PRIME.toString(2).length();
		System.out.println("RESET field order to " + Config.FIELD_PRIME);
	}

	/** FOR ZaModulerVerifier only */
	public static ZaConfig new_config_by_curve(String curve_type){
		ZaConfig config = null;
		if(curve_type.equals("BN254")){
			config = new ZaConfig(PrimeFieldInfo.LIBSNARK, ZaConfig.EnumHashAlg.Poseidon);
		}else if (curve_type.equals("Bls381")){
			config = new ZaConfig(PrimeFieldInfo.Bls381, ZaConfig.EnumHashAlg.Poseidon);
		}else{
			throw new RuntimeException("UNSUPPORTED curve type: " + curve_type);
		}
		return config;
	}
}

