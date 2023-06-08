# Generator for the Karatsuba Multiplications

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

# print the value of variable
def printV(prefix, v):
	s =  "System.out.println(\"" + prefix + ": \" + Long.toHexString(" + v + ") );";
	print(s);

# generate the instructions for arrDest = arrSrc + arrDest
# carry will the carry out. 
# arrDest will be the array of scalar variables (littlen endian org)
# REQUIRED: arrSrc has the same length as arrDest
def gen_add(arrDest, arrSrc, carry):
	print("val = 0;");
	print(carry + " = 0;");
	n = len(arrDest);
	for i in range(n):
		print("val = (" + arrDest[i] + "&0x0FFFFFFFFL) + (" + 
			arrSrc[i] + "&0x0FFFFFFFFL) + " + carry + ";");
		print(arrDest[i]  + " = (int) val;");
		print(carry + " = (val >>>32); ");

# the same as add but assuming each scalar is of already long
# but containing 32-bit data
# so we skip the &0x0FFFFFFFFL operation
# build the array name
def build_arr_name(prefix, size):
	arr = [];
	for i in range(size):
		arr.append(prefix+str(i));
	return arr;

# generate the function add_8limbs
def gen_add_8limbs():
	a = build_arr_name("this.d", 8);
	b = build_arr_name("b.d", 8);
	gen_add(a, b, "carry");

# generate the NEGATIVE of the given number
# just COMPLEMENT + 1
# NEGATE all limbs in arrSrc and then +1, store results in arrDest
def gen_neg(arrDest, arrSrc):
	gen_net_worker(arrDest, arrSrc, False); 

def gen_neg_worker(arrDest, arrSrc, bReuse):
	n = len(arrDest);
	if bReuse:
		print("val = 0;");
		print("c = 1;");
	else:
		print("long val = 0;");
		print("long c = 1;");
	for i in range(n):
		print("val =  ((~" + arrSrc[i] + ") & 0x0FFFFFFFFL) +  c;");
		print(arrDest[i] +  " = (int) val;");
		print("c = (val >>>32); ");

# generate neg for n limbs
def gen_neg_limbs(n):
	a = build_arr_name("this.d", n);
	gen_neg(a, a);

# generate the subtraction. Assume arrDest and arrSrc has n+1 limbs
# but the actual data is n limbs. The left most are BOTH 0.
# The two numbers are treated as UNSIGNED n-limb numbers
# results stored in arrDest (with left most be sign bit, could be 0xFFFFFFFF)
def gen_sub(arrDest, arrSrc):
	gen_sub_worker(arrDest, arrSrc, False); 

def gen_sub_worker(arrDest, arrSrc, bReuseVar):
	n = len(arrDest)-1;
	if bReuseVar:
		print("val = 0;");
		print("c = 0;");
	else:
		print("long val = 0;");
		print("long c = 0;");

	for i in range(n+1):
		print("c = ("+arrDest[i]+" &0x0FFFFFFFFL) -  ((" + arrSrc[i] + "&0x0FFFFFFFFL) ) +  c;");
		print(arrDest[i] +  " = (int) c;");
		print("c = (c &0x8000000000000000L) >> 63; "); #either 0 or 0xFFF....F
	print("sign = " + arrDest[n] + ">>>63;");

# generate sub for n limbs
def gen_sub_limbs(n):
	a = build_arr_name("this.d", n+1);
	b = build_arr_name("other.d", n+1);
	gen_sub(a, b);

# generate the ABSSOLUTE VALUE of the difference.
# subtraction. Assume arrDest and arrSrc has n+1 limbs
# but the actual data is n limbs. The left most are BOTH 0.
# The two numbers are treated as UNSIGNED n-limb numbers
def gen_abssub(arrDest, arrSrc):
	gen_abssub_worker(arrDest, arrSrc, False);

def gen_abssub_worker(arrDest, arrSrc, bReuseVar):
	gen_sub_worker(arrDest, arrSrc, bReuseVar);
	print("if(sign!=0){");
	gen_neg_worker(arrDest, arrDest, True);
	print("}");

# generate abssub for n limbs
def gen_abssub_limbs(n):
	a = build_arr_name("this.d", n+1);
	b = build_arr_name("other.d", n+1);
	gen_abssub(a, b);

# generate the product given the limbs. All treated as UNSIGNED numbers
# the length of arrDest is TWICE of arrSrc (for storing product)
def gen_mul(arrDest, arrSrc):
	gen_mul_worker(arrDest, arrSrc, False);

def gen_mul_worker(arrDest, arrSrc, bReuseVar):
	n = len(arrSrc);
	if bReuseVar:
		print("val = 0;");
		print("c = 0;");
	else:
		print("long val = 0;");
		print("long c = 0;");

	for i in range(n*2):
		print("long t"+str(i) + " = 0;"); 

	for i in range(n):
		print("c = 0;");
		for j in range(n):
			print("val = t"+str(i+j) + 
				" + ("+arrDest[j]+" &0x0FFFFFFFFL) *  ((" 
				+ arrSrc[i] + "&0x0FFFFFFFFL) ) +  c;");
	
			print("t"+str(i+j) +  " =  val & 0x0FFFFFFFFL;");
			print("c = val >>> 32; "); 
		for j in range(i+n, 2*n):
			print("val = t"+str(j) + " + c;");
			print("t"+str(j) +  " =  val & 0x0FFFFFFFFL;");
			print("c = val >>> 32; "); 
			

	for i in range(n*2):
		print(arrDest[i] + " = (int) t"+str(i) + ";");

def gen_mul_limbs(n):
	a = build_arr_name("this.d", n*2);
	b = build_arr_name("other.d", n);
	gen_mul(a, b);
# generate loop of copy statement
# arrSrc could be a HALF of arrDest
# if arrDest LONGER than arrSrc, clear the higher half
def cp(arrDest, arrSrc):
	for i in range(len(arrSrc)):
		print(arrDest[i] + " = " + arrSrc[i] + ";");
	for i in range(len(arrSrc), len(arrDest)):
		print(arrDest[i] + " = 0;");

# arrDest has TWICE the size of arrSrc. Assuming 2^{k+1} size
# treat operands as 2^k * 2^k -> 2^{k+1} UNSIGNED MUL.
# each element of arrDest and arrSrc treated as 32-bit UNSIGNED
# arrDest will be used for storing result.
def gen_kara_mul(arrDest, arrSrc):
	gen_kara_mul_worker(arrDest, arrSrc, False);

def gen_kara_mul_worker(arrDest, arrSrc, bReuse):
	
	n = len(arrSrc);
	print("val = 0;");
	print("c = 0;");
	#case 1. n == 1
	if n==1:
		print("val = (" + arrDest[0] + " & 0x0FFFFFFFFL) * (" + arrSrc[0] +" & 0x0FFFFFFFFL);");
		print(arrDest[0] +" = (int) val;");
		print(arrDest[1] +"= (int) (val >>> 32);");
	#case 2. call schoolbook mul
	elif n<=1:
		gen_mul_worker(arrDest, arrSrc, True);
	#case 3. recursive call
	else: #RECURSIVE CAES
		#0. declare clear local vars
		if bReuse: 
			for i in range(5*n): print("tmp_"+str(n)+"_"+str(i) + " = 0;");
			print("sign_"+str(n)+"_0 = 0;");
			print("sign_"+str(n)+"_1 = 0;");
			print("zero_"+str(n)+"_0 = 0;");
			print("zero_"+str(n)+"_1 = 0;");
		else: 
			for i in range(5*n): print("long tmp_"+str(n)+"_"+str(i) + " = 0;");
			print("long sign_"+str(n)+"_0 = 0;");
			print("long sign_"+str(n)+"_1 = 0;");
			print("long zero_"+str(n)+"_0 = 0;");
			print("long zero_"+str(n)+"_1 = 0;");
		sign0 = "sign_"+str(n) + "_0";
		sign1 = "sign_"+str(n) + "_1";
		zero0 = "zero_"+str(n) + "_0";
		zero1 = "zero_"+str(n) + "_1";
		

		#1. get x1, y1, x0, y0 and temporary variables
		x1 = arrDest[n//2:n];
		x0 = arrDest[0:n//2];
		y1 = arrSrc[n//2:n];
		y0 = arrDest[0:n//2];
		t = []; # store the result
		t1 = []; #store temporary result
		t0 = []; #store temp result
		t2 = []; # low half of t
		t3 = []; # high half of t
		t4 = []; #anotehr temp array
		for i in range(n):
			t1.append("tmp_"+str(n) + "_" +str(i+n));
			t0.append("tmp_"+str(n) + "_" +str(i));
			t2.append("tmp_"+str(n) + "_" +str(i+2*n));
			t3.append("tmp_"+str(n) + "_" +str(i+3*n));
			t4.append("tmp_"+str(n) + "_" +str(i+4*n));
		t = t2 + t3;
		t1_0 = t1[0:len(t1)//2];
		t1_1 = t1[len(t1)//2: len(t1)];
		t0_0 = t0[0:len(t0)//2];
		t0_1 = t0[len(t0)//2: len(t0)];
		
		#2. ABS (x1-x0)*(y1-y0) -> t1 and SIGN -> sign0
		x1.append(zero0);
		t1_0.append(zero1); #needs n+1 limbs
		cp(t1_0, x1);
		gen_abssub_worker(t1_0, x1, True); 
		print(sign0 + "= sign;"); #sign is global var
		x1.remove(zero0);
		t1_0.remove(zero1);
		print(zero0 + "= 0;");
		print(zero1 + "= 1;");
		
		x0.append(zero0);
		t1_1.append(zero1); #needs n+1 limbs
		cp(t1_1, x0);
		gen_abssub_worker(t1_1, x0, True); 
		print(sign1 + "= sign;"); #sign is global var
		x0.remove(zero0);
		t1_1.remove(zero1);
		print(zero0 + "= 0;");
		print(zero1 + "= 1;");

		cp(t0, t1_1);
		gen_kara_mul_worker(t0, t1_1, False or bReuse);

		#3. x0*y0 -> t2, copy to t0
		cp(t2, x0);
		gen_kara_mul_worker(t2, y0, True);
		cp(t0, t2);

		#3. x1*y1 -> t3, copy to t4
		cp(t3, x1);
		gen_kara_mul_worker(t3, y1, True);
		cp(t3, t4);

		#4. if sign0==sign1, do the sub otherwise do the add
		t0.append(zero0);
		t1.append(zero1);
		print("if("+sign0+"=="+sign1+"){//t0 = t0 + t1");
		gen_add(t0, t1, "c");
		print("}else{//t0 = t0 - t1");
		gen_sub_worker(t0, t1, True);
		print("}");
		t1.remove(zero1);
		print(zero1 + "= 0;");

		#5. t0 = t0 + t4 (add one limb of zero to t4) 
		t4.append(zero1);
		gen_add(t0, t4, "c");

		#6. Now builds up the last segment of add (about 3/4 of t)
		part_t = t[n//2: 2*n];
		for x in t1: print(x + " = 0;");
		for i in range(n//2+1, n):
			t0.append(t1[i]);
		gen_add(part_t, t0, "c");
	

	
def gen_kara_mul_limbs(n):
	a = build_arr_name("this.d", n*2);
	b = build_arr_name("other.d", n);
	gen_kara_mul(a, b);

# MAIN -----------------------
#gen_add_8limbs();
#gen_sub_limbs(8);
#gen_abssub_limbs(8);
#gen_mul_limbs(8);
gen_kara_mul_limbs(4);


# print("long c = 0;");
# print("long s = 8;");
# print("long val = 0;");
# print("long m = 0;");
# s = 8;
# for i in range(s+2):
# 	print("long t"+str(i) + " = 0;");
# 	print("long u"+str(i) + " = 0;");
# 	print("long n"+str(i) + " = N.d"+str(i) + " & 0x0FFFFFFFFL;");
# 	print("long A"+str(i) + " = a.d"+str(i) + " & 0x0FFFFFFFFL;");
# 	print("long B"+str(i) + " = b.d"+str(i) + " & 0x0FFFFFFFFL;");
# for i in range(s):
# 	print("c = 0;");
# 	for j in range(s):
# 		print("  val = t"+str(j)+"+A"+str(j)+"*B"+str(i)+" + c;"); 	
# 		print("  t"+str(j) + " =  val & 0x0FFFFFFFFL;");
# 		print("  c = (val >>> 32);");
# 	print("val = t"+str(s) + " + c;");
# 	print("t"+str(s)+" = val & 0x0FFFFFFFFL;");
# 	print("t"+str(s+1)+" = (val >>> 32);");
# 
# 	print("c = 0;");
# 	print("m = (t0 * INV_N0) & 0x0FFFFFFFFL;"); 
# 	print("val = (t"+str(0) + "+ m*(N.d"+str(0) + "&0x0FFFFFFFFL));");
# 	print("c = (val >>> 32);");
# 	for j in range(1,s):
# 		print("  val = t"+str(j) + "+ m*n"+str(j) + " +c;");
# 		print("  t"+str(j-1) + " = val & 0x0FFFFFFFFL;");
# 		print("  c = (val >>> 32);");
# 	print("val = t"+str(s) + " + c;");
# 	print("t"+str(s-1) + " = val & 0x0FFFFFFFFL;");
# 	print("c = (val >>> 32);");
# 	print("t"+str(s) + " = t"+str(s+1) + " + c;");
# 
# print("long B = 0;");
# # SWAP the t and u in the code
# for i in range(s):
# 	print("  val = t"+str(i) + " + (NEG_N.d"+str(i) + " &0x0FFFFFFFFL) + B;");
# 	print("  B = (val >>> 32);");
# 	print("  u"+str(i) + " = val & 0x0FFFFFFFFL;");
# # NO NEED TO TEST ANOTHER LEG COZ N is 254 bit it's two bits away from 256
# print("if(B==0){");
# for i in range(s):
#  	print("  dest.d"+str(i) + " = (int) t"+str(i) + "; ");
# print("}else{");
# for i in range(s):
#  	print("  dest.d"+str(i) + " = (int) u"+str(i) + "; ");
# print("}");

		
