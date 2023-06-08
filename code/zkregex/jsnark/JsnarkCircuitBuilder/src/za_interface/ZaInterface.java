/*******************************************************************************
 * Author: CorrAuthor
 * Adapted from ZaInterface
 *******************************************************************************/


/*************************************************************
  Provides the interface that calls the modified libsnark
  to generate the R1CS or circuit file 
  For the extended zero_audit (za) project
* *************************************************************/
package za_interface;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import java.math.BigInteger;
import za_interface.generators.basic_ops.*;
import za_interface.generators.gadgets.*;

public class ZaInterface{
	protected static PrimeFieldInfo [] platforms = {
		PrimeFieldInfo.LIBSPARTAN,
//		PrimeFieldInfo.LIBSNARK, 
//		PrimeFieldInfo.AURORA, 
	};



	public static void main(String[] args) throws Exception {
		System.out.println("============ R1CS Generated! ==========\n");
		int [] circs = GeneratorDriver.LIST_SIMPLE_TEST;
		//int [] circs = GeneratorDriver.LIST_FULL;
		GeneratorDriver gd = new GeneratorDriver();
		for(int i=0; i<platforms.length; i++){
			for(int j=0; j<circs.length; j++){
				gd.genr1cs(circs[j], platforms[i]);
			}	
		}
		 
	}

}
