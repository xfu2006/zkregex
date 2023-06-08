
/** Efficient Zero Knowledge Project
	NanoSeconds Timer
	Author: Dr. CorrAuthor
	Created: 05/01/2022
*/ 
package cs.Employer.zkregex;

public class NanoTimer{
	long total = 0;
	long start;
	public void clear_start(){
		total = 0;
		start = System.nanoTime();
	}
	public void start(){
		start = System.nanoTime();
	}
	public void end(){
		total = System.nanoTime() - start;
	}
	public long getDuration(){
		return total;
	}
}
