/** Efficient Zero Knowledge Project
	Background Thread
	Author: Author1
	Created: 09/09/2022
*/ 
package cs.Employer.zkregex;
import java.lang.Thread;
import java.lang.ProcessBuilder;
import java.io.IOException;
import java.io.File;

/** Class utilized to run shell scripts in background */
public class BackgroundThread extends Thread {
	protected String[] cmds;
	protected String dumpFile;

	BackgroundThread(String[] cmds, String dumpFile){
		this.cmds = cmds;
		this.dumpFile = dumpFile;
	}
	public void run(){
		ProcessBuilder builder = new ProcessBuilder(cmds);
		builder.redirectOutput(new File(dumpFile));
		builder.redirectError(new File(dumpFile+".ERROR"));
		try {
			Process proc = builder.start();
			//System.out.println("PID: " + proc.pid());
		}
		catch (IOException e) {
			System.out.println("BackgroundThread.run() failed: " + e.toString());
		}
	}
}
