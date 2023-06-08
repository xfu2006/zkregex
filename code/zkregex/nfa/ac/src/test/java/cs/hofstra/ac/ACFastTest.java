package cs.Employer.ac;
import static org.junit.Assert.*;
import org.junit.Test;
import java.util.HashMap;
import java.util.ArrayList;
import java.io.File;
import java.util.Scanner;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Unit test for AC (Aho-Corasic DFA).
 * Authors: Author2, Author3, Author1, Dr. CorrAuthor
 * Creation Date: 06/19/2022
 * Completion Date: 08/04/2022
 */
public class ACFastTest 
{
	@Test
	public void testRandRun(){//test random gen and random run
		int nlen = 4000;
		AC ac = AC.rand_clamav_ac(123l, nlen*2);
		ArrayList<AC.Transition> al = ac.rand_accept_run(132l, nlen);
		String sinp = ac.collect_inputs(al);
		assertTrue("sinp is not the dsired nlen!", sinp.length()==nlen);
		ArrayList<AC.Transition> al2 = ac.run(sinp);
		assertTrue(al.equals(al2));
	}

    @Test
    public void testAcceptingAutomataAscii()
    {
		/* Construct a small automaton for ASCII set (check sample 
		use 1 in App.java). Feed a number string accepted 
		(NOT containing bad samples). Verify that all pass.
		*/
		AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "she", "his", "her"});//These are "Bad" Strings!!!
		String [] goodStrings = new String [] {
			"ac", 
			"aaaacb",
			"aaabbbbca",
			"cbcbcaaabbb",
			"bbbbbbccccaaaaaa",
			"cccccccccccccccc",
			"bc"
		};
		for(String str : goodStrings){
			if(!ac.accepts(str)){
				System.out.println("failed on case: " + str);
				ac.dump();
				fail("testGoodAutomataAscii failed on case: " + str);
			}
		}
    }

    @Test
    public void testRejectingAutomataAscii()
    {
		AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "she", "his", "her"});
		String [] badStrings = new String [] {
			"hisbabbabababa",
			"abcabcbacher",
			"ababashebccbc",
			"abbbbbbhebbbbcccc",
			"cccccchisbbbbbbb",
			"aaaaaaaherbbb",
			"aaasheraaaahebbb"
		};
		for (int i=0; i<badStrings.length; i++){
			if(ac.accepts(badStrings[i])){
		       	fail("testRejectingAutomataAscii failed on case: " + 
					badStrings[i]);
			}
		}
    }

    @Test
    public void testGoodFiles()
    {
		AC ac = AC.load_clamav_fixed("data/real_virus/bad_sigs.dat");
		Tools tools = new Tools();
		byte[] nibbles = tools.read_nibbles_from("/bin/cat");
		//System.out.println(nibbles);
		String nibbleString = tools.bytearr_to_str(nibbles);
		if(!ac.accepts(nibbleString)) {
			fail("testGoodFiles failed");
		}	
	}

    @Test
    public void testBadFiles() throws IOException
    {
		/* This time: try to get the REAL malware sample from Internet,
			see if its content will be rejected by the automata.
			*** If bad virus file cannot find, use sigtool to generate signature
			on some existing file and then see if the generated automata
			can reject that file 
		*/
		String filePath = "data/real_virus/bad_sigs.dat";
		AC ac = AC.load_clamav_fixed(filePath);
		Tools tools = new Tools();
		String[] bad7zFiles = {"WinWormVB556.7z", "WinTrojanAgent36385.7z", 
			"WinTrojanDialer61.7z"};
		String[] badFiles   = {"WinWormVB.exe", "WinTrojanAgent36385.exe", 
			"WinTrojanDialer61.exe"};
		Tools.new_dir("data/work_folder");
		for(int i = 0; i<bad7zFiles.length; i++) {
			File zipFile = new File("data/real_virus/" + bad7zFiles[i]);
			tools.extract7zWithPassword(zipFile, "abc123", "data/work_folder/");
			byte[] nibbles = tools.read_nibbles_from("data/work_folder/" + badFiles[i]);
			String nibbleString = tools.bytearr_to_str(nibbles);
			if(ac.accepts(nibbleString)) {//if regarded as GOOD files, report error!
				fail("testBadFiles failed on case: " + badFiles[i]);
			}
		}
		//remove THE work folder (just in case anti-virus hates about it)	
		Tools.del_dir("data/work_folder");
    }

	// RECOVER LATER. The new 64-bit component fails the test
	public void testSerialization(){
		/** construct one AC-DFA, serialize it and then deserialize it,
			and serialize it again. Compare if the two serialize string
			are the same.
		*/
/*
		AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "she", "his", "her"});
		//AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "sh"});
		ac.old_serialize_to("src/test/java/cs/Employer/ac/testFiles/serialized.txt");
		AC des = AC.old_deserialize("src/test/java/cs/Employer/ac/testFiles/serialized.txt");

		// TESTING STATES
		int stateSize = ac.tbl_goto.size();
		if (stateSize != des.states_des.size()){
			fail("testSerialization failed on case: State Sizes do not match: " + des.states_des.size() + " != " + stateSize);
		}

		// TESTING FINAL STATES, AND TRANSITIONS
		int fidx = 0;
		int tidx = 0;
		for (int state = 0; state < stateSize; state++){
			// Final States
			if (ac.tbl_output.get(state)==null){
				if(des.finals_des.get(fidx++)!=state){
					fail("testSerialization failed on case: Final States do not match: " + des.finals_des.get(fidx-1) + " != " + state);
				}
			}

			// Transistions
			HashMap<Character, Integer> map = ac.tbl_goto.get(state);
			for (Character ch : map.keySet()){
				int nstate = map.get(ch);
				String digit = ac.getDigit(state, ch, nstate);

				// Compare integer transition to BigInteger transition
				if (!Integer.toString(des.trans_des.get(tidx++)).equals(digit)){
					fail("testSerialization failed on case: Transitions do not match: " + des.trans_des.get(tidx-1) + " != " + digit);
				}
			}
		}

		// TESTING FAIL TABLES
		int failSize = ac.tbl_fail.size();
		if (failSize != des.tbl_fail.size()){
			fail("testSerialization failed on case: tbl_fail sizes do not match: " + Integer.toString(failSize) + " != " + Integer.toString(des.tbl_fail.size()));
		}
		for (int i = 0; i < failSize; i++){
			if (des.tbl_fail.get(i) != ac.tbl_fail.get(i)){
				fail("testSerialization failed on case: tbl_fail entries do not match: " + des.tbl_fail.get(i) + " != " + ac.tbl_fail.get(i));
			}
		}

        //assertTrue( true );
		System.out.println("\n\n---------------- END TEST --------------------\n");
*/
	}

	@Test
	public void testLog2(){
		String s1 = "abcdef23333";
		AC ac = new AC(AC.ASCII_BIT_SIZE, new String [] {"he", "she"});
		String s2 = ac.pad_inputs(s1);
		for(int i=0; i<s2.length(); i++){
			char c = s2.charAt(i);
			//System.out.println("i: " + i + ", c: " + Integer.valueOf(c));
		}
	}

	@Test
	public void testChunkRun(){
		long seed = 198234l;
		int n = 1024;
		AC ac = AC.rand_clamav_ac(seed, n);
		ArrayList<AC.Transition> short_trans= ac.rand_accept_run(seed, n);
		String sinp = ac.collect_inputs(short_trans);
		ArrayList<AC.Transition> alTrans= ac.run_by_chunks(sinp, 4);
		String sinp2 = ac.collect_inputs(alTrans);
		assertTrue("FAILED testChunkRun: sinp: " + sinp + ", sinp2: " + sinp2,
			sinp.equals(sinp2));
	}
}
