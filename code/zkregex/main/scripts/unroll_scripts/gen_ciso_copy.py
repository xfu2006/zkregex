# Generator for the CISO algorithm

# generate the System.out.println statement
def printArr(prefix, v, n):
	s =  "System.out.println(\"" + prefix + ": [\"";
	for i in range(n):
		if i==0:
			s2 = "+ \" \"  + ("+v+str(i) + " & 0x0FFFFFFFFL)";  
		else:
			s2 = "+ \" ,\"  + ("+v+str(i) + " & 0x0FFFFFFFFL)";  
		s += s2;
	s += " + \"]\" ); ";
	print(s);

def printV(prefix, v):
	s =  "System.out.println(\"" + prefix + ": \" + Long.toHexString(" + v + ") );";
	print(s);
# MAIN -----------------------


print("long c = 0;");
print("long s = 8;");
print("long val = 0;");
print("long m = 0;");
s = 8;
for i in range(s+2):
	print("long t"+str(i) + " = 0;");
	print("long u"+str(i) + " = 0;");
	print("long n"+str(i) + " = N.d"+str(i) + " & 0x0FFFFFFFFL;");
	print("long A"+str(i) + " = a.d"+str(i) + " & 0x0FFFFFFFFL;");
	print("long B"+str(i) + " = b.d"+str(i) + " & 0x0FFFFFFFFL;");
for i in range(s):
	print("c = 0;");
	for j in range(s):
		print("  val = t"+str(j)+"+A"+str(j)+"*B"+str(i)+" + c;"); 	
		print("  t"+str(j) + " =  val & 0x0FFFFFFFFL;");
		print("  c = (val >>> 32);");
	print("val = t"+str(s) + " + c;");
	print("t"+str(s)+" = val & 0x0FFFFFFFFL;");
	print("t"+str(s+1)+" = (val >>> 32);");

	print("c = 0;");
	print("m = (t0 * INV_N0) & 0x0FFFFFFFFL;"); 
	print("val = (t"+str(0) + "+ m*n"+str(0) + ");");
	print("c = (val >>> 32);");
	for j in range(1,s):
		print("  val = t"+str(j) + "+ m*n"+str(j) + " +c;");
		print("  t"+str(j-1) + " = val & 0x0FFFFFFFFL;");
		print("  c = (val >>> 32);");
	print("val = t"+str(s) + " + c;");
	print("t"+str(s-1) + " = val & 0x0FFFFFFFFL;");
	print("c = (val >>> 32);");
	print("t"+str(s) + " = t"+str(s+1) + " + c;");

print("long B = 0;");
## SWAP the t and u in the code
#for i in range(s):
for i in range(s):
	print("  val = t"+str(i) + " + (NEG_N.d"+str(i) + " &0x0FFFFFFFFL) + B;");
	print("  B = (val >>> 32);");
	print("  u"+str(i) + " = val & 0x0FFFFFFFFL;");
# NO NEED TO TEST ANOTHER LEG COZ N is 254 bit it's two bits away from 256
print("if(B==0){");
for i in range(s):
 	print("  dest.d"+str(i) + " = (int) t"+str(i) + "; ");
print("}else{");
for i in range(s):
	print("  dest.d"+str(i) + " = (int) u"+str(i) + "; ");
print("}");

		
