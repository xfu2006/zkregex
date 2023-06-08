/* ***************************************************
Dr. CorrAuthor
@Copyright 2022
Created 12/23/2022
* ***************************************************/
package za_interface.za;
public class Timer{
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
		total += System.nanoTime() - start;
	}
	public long getDuration(){
		return total;
	}
	public void report(String prefix){
		this.end();
		long dur = this.getDuration();
		if(dur<1000000){
			System.out.println(prefix + ": " + dur/1000 + " us");
		}else{
			System.out.println(prefix + ": " + dur/1000000 + " ms");
		}
		this.clear_start();
	}
}
