/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package circuit.config;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Properties;

public class Config {

	static Properties properties = new Properties();

	static{
		try {
			InputStream inStream = new FileInputStream("config.properties");
			properties.load(inStream);
		} catch (FileNotFoundException e) {
			System.err.println("config.properties file not found.");
			e.printStackTrace();
			System.exit(0);
		} catch (IOException e) {
			System.err.println("config.properties not loaded properly.");
			e.printStackTrace();
		}
	}

	//MODIFIED BY XIANG FU -- DROPPED final	
	public static BigInteger FIELD_PRIME = new BigInteger(properties.getProperty("FIELD_PRIME"));
	public static int LOG2_FIELD_PRIME = FIELD_PRIME.toString(2).length();
	public static final String LIBSNARK_EXEC = properties.getProperty("PATH_TO_LIBSNARK_EXEC");
	//-------- ADDED BY XIANG FU -----------
	public static final String LIBSNARK_EXEC_GEN_R1CS = properties.getProperty("PATH_TO_LIBSNARK_EXEC_GEN_R1CS");
	public static final String PATH_TO_SAGE= properties.getProperty("PATH_TO_SAGE");
	public static final String PATH_TO_R1CS_RUNNER= properties.getProperty("PATH_TO_R1CS_RUNNER");
	public static final String PATH_TO_R1CS_DIR= properties.getProperty("PATH_TO_R1CS_DIR");
	//-------- ADDED BY XIANG FU ----------- ABOVE
	
	public static boolean runningMultiGenerators = properties.getProperty("RUNNING_GENERATORS_IN_PARALLEL").equals("1");	
	public static boolean hexOutputEnabled = properties.getProperty("PRINT_HEX").equals("1");
	public static boolean outputVerbose = properties.getProperty("OUTPUT_VERBOSE").equals("1");
	public static boolean debugVerbose = properties.getProperty("DEBUG_VERBOSE").equals("1");

	public static boolean printStackTraceAtWarnings = false;
}
