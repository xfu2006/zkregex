# Generator for the Karatsuba Multiplications

# panic and quit
def panic(s):
	print(s);
	exit();

# print a message
def printMsg(msg):
	print("System.out.println(\"" + msg + "\");");

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

def printVecVar(prefix, arr):
	for i in range(len(arr)):
		print("System.out.println(\"" + prefix + str(i) + ":\""  "+ Long.toHexString(" + arr[i] + " & 0x0FFFFFFFFL));");

# print the value of variable
def printV(prefix, v):
	s =  "System.out.println(\"" + prefix + ": \" + Long.toHexString(" + v + ") );";
	print(s);

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

# z = x + y + carry_in
# x, y, z are all same length
# NOTE y length MAY BE SMALLER!
# x and y treated as UNSIGNED INT
def gen_add_to(x, y, z, carry_in):
	gen_add_to_worker(x, y, z, carry_in, False);

def gen_add_to_worker(x, y, z, carry_in, bConvert):
	print("// gen_add_to: x: ", x,  ", y: " , y, ", z:", z, ", carry_in: ", carry_in);
	print("c = " + carry_in + ";");
	n = len(x);
	for i in range(n):
		if i<len(y):
			print("val = " + x[i] + " + " + y[i] + " + c;");
		else:
			print("val = " + x[i] + " + c;");
		if bConvert:
			print(z[i]  + " =  (int) val;");
		else:
			print(z[i]  + " =  val & 0x0FFFFFFFFL;");
		if i<n-1:
			print("c = (val >>>32); ");

# assume input is 32-bit
# generate the same array and rename them as output convert to 64-bit
# e.g., this.d0 -> x0 but x0 is 64-bit now
def build_64bit_vars(prefix, size, output_prefix):
	arr = [];
	for i in range(size):
		print("long " + output_prefix+str(i) + " = " + prefix+str(i) + " & 0x0FFFFFFFFL;");
		arr.append(output_prefix+str(i));
	return arr;

def gen_var_vec(prefix, n):
	arr = [];
	for i in range(n):
		arr.append(prefix+str(i));
	return arr;

# create an array of long variables
def create_arr_vars(prefix, size):
	arr = [];
	for i in range(size):
		print("long " + prefix + str(i) + " = 0;");
		arr.append(prefix+str(i));
	return arr;
		
	

# generate the function add_8limbs
def gen_add_8limbs():
	a = build_64bit_vars("this.d", 8);
	b = build_64bit_vars("b.d", 8);
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
	a = build_64bit_vars("this.d", n);
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
	a = build_64bit_vars("this.d", n+1);
	b = build_64bit_vars("other.d", n+1);
	gen_sub(a, b);

# z = x - y. Assume all operands are 32-BIT UNSIGNED (although contained
# in 64-bit numbers).
# Do not handle carry, do not handle overflow
def gen_sub_to(x, y, z):
	gen_sub_to_worker(x, y, z, False);

def gen_sub_to_worker(x, y, z, bConvertInt):
	print("// gen_sub_to x: " + str(x) + ", y: "+ str(y) + ", z: "+ str(z));
	n = len(x);
	print("c = 0;");
	for i in range(n):
		print("val = " + x[i] + " - " + y[i] + " +  c;");
		if	bConvertInt:
			print(z[i] + " =  (int) val;");
		else:
			print(z[i] + " = val & 0x0FFFFFFFFL;");
		if i<n-1:
			print("c = (val &0x8000000000000000L) >> 63; "); #either 0 or 0xFFF....F

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
	a = build_64bit_vars("this.d", n+1);
	b = build_64bit_vars("other.d", n+1);
	gen_abssub(a, b);


# z = x * y + carry_in
# len(x)=len(y) = len(z)//2, don't handle carry_out
# some cases len(x)=len(z)=2*len(y) where the upper half of x is
# NOT used as operand. In this case, x is equal to z (store result)
def gen_mul_worker(x, y, t, carry_in, z):
	print("// standard MUL: ");
	print("// " + str(z) + " = " + str(y) + " * " + str(y) + " + " + carry_in);
	n = len(y);
	for i in range(2*n):
		print(t[i] + " = 0;");
	for i in range(n):
		if i==0:
			print("c = " + carry_in + ";");
		else:
			print("c = 0;");

		for j in range(n):
			print("val = "+t[i+j] + 
				" + ("+x[j]+" &0x0FFFFFFFFL) *  ((" 
				+ y[i] + "&0x0FFFFFFFFL) ) +  c;");
			print(t[i+j] +  " =  val & 0x0FFFFFFFFL;");
			print("c = val >>> 32; "); 
		for j in range(i+n, 2*n):
			print("val = "+t[j] + " + c;");
			print(t[j] +  " =  val & 0x0FFFFFFFFL;");
			if j<2*n-1:
				print("c = val >>> 32; "); 
			
	for i in range(n*2):
		print(z[i] + " = (int) "+t[i] + ";");

def gen_mul_limbs(n):
	x = build_64bit_vars("this.d", 2*n, "x");
	y = build_64bit_vars("other.d", n, "y");
	s = create_arr_vars("s", 2*n);
	gen_mul_worker(x, y, s, "0", x);
	cpArr(gen_var_vec("this.d", len(x)), x, " (int) ");

# generate loop of copy statement
# arrSrc could be a HALF of arrDest
# if arrDest LONGER than arrSrc, clear the higher half
def cp(arrDest, arrSrc):
	for i in range(len(arrSrc)):
		print(arrDest[i] + " = " + arrSrc[i] + ";");
	for i in range(len(arrSrc), len(arrDest)):
		print(arrDest[i] + " = 0;");

def cpArr(destArr, srcArr, prefixSrc):
	for i in range(len(destArr)):
		print(destArr[i] + " = " + prefixSrc + " " + srcArr[i] + ";");

# compute (x1+x0)(y1+y0) and store result in z
# x1,x0,y1,y0 are all n-limbs.
# z is 2n+1 limbs with the left most one no larger than 4
# Idea: let sx and sy be the left most limb of x1+x0 and y1+y0
#   sx and sy are both in range [0,1]
#   depending on their value determine if needs to perform additional add 
# s is the scratch array (scratch var will be REUSED/destroyed after return)
# s size should be at least 2*n
def expanded_mul(x1, x0, y1, y0, z, s):
	#0. check input
	n = len(x1);
	if(len(x0)!=n or len(y1)!=n or len(y0)!=n): panic("expanded_mul: len of x1,x0,y1,y0 not equal!");
	if(len(z)!=2*n+1): panic("expanded_mul: len(z)!=2*n+1");
	if(len(s)<get_scratch_needed_exp(n)): panic("expanded_mul: scratch size: " + str(len(s)) + " too small! n: " + str(n) + ", scratch needed: " + str(get_scratch_needed(n)));
	print("// expanded MUL: x1: ", x1, ", x0: ", x0, "y1: ", y1, "y0:", y0, "z: ", z);

	#1. x1 + x0 -> s[0:n+1]. need to append two zeros: s[2n+3], s[2n+4]
	print("// x1 + x0 -> s[0:n+1]");
	z0 = s[2*n+3];
	z1 = s[2*n+4];
	print(z0 + " = 0;");
	print(z1 + " = 0;");
	x1.append(z1);
	x0.append(z0);
	tx = s[0:n+1];
	gen_add_to(x1, x0, tx, "0");
	x1.remove(z1);
	x0.remove(z0);	

	#2. y1 + y0 -> s[n+1:2n+2]
	print("// y1 + y0 -> s[n+1:2n+2]");
	print(z0 + " = 0;");
	print(z1 + " = 0;");
	y1.append(z1);
	y0.append(z0);
	ty = s[n+1: 2*n+2];
	gen_add_to(y1, y0, ty, "0");
	y1.remove(z1);
	y0.remove(z0);

	#3. set prod_signxy. Take s[2n+2]
	print("// prod_signxy = signx * sign y");
	prod_sign = s[2*n+2];
	signx, signy = tx[n], ty[n];
	print(prod_sign + " = " + signx + "*" + signy + ";");
	
	#4. multiply s[0:n] * s[n+1:2n+1] -> z[0:2n]
	gen_kara_mul(s[0:n], s[n+1:2*n+1], z, s[2*n+5: 2*n+5 + get_scratch_needed(n)]);
 	
	#5.  if signnx: z[n:2n+1] + y[exclude_sign] -> z
	# it's like z + y<<2^n(with sign excluded) -> z
	#print("if(" + signx + ">0){");
	gen_add_to(z[n:2*n+1], ty[0:-1] , z[n:2*n+1], "0");
	#print("}");
	#7. if signy: z[n:2n+1]+[0:n]-> z
	#print("if(" + signy + ">0){");
	gen_add_to(z[n:2*n+1], tx[0:-1] , z[n:2*n+1], "0");
	#print("}");
	#8. add the carry: it's either 1*2^{2n} or 0
	print(z[2*n] + " = " + z[2*n] + " + " + prod_sign + ";");

# for karatsuba_mul
def get_scratch_needed(n):
	if n==1: return 0;
	else: return 2*n+5 + get_scratch_needed_exp(n//2);

# for expanded_mul
def get_scratch_needed_exp(n):
	if n==1: return 2*n+5;
	return 2*n+5 + get_scratch_needed(n);

# z = x * y. 
# treat operands as 2^k * 2^k UNSIGNED MULTIPLICATION
# z length should be twice of x and y
# t is the "scratch" temp variables. NOTE: they'll be re-used destroyed
# after the function returns.
def gen_kara_mul(x, y, z, t):
	print("// kara_mul: x: ", x, "y: ", y, "z: ", z);
	n = len(x);
	#case 1. n == 1 (simpliest case)
	if n==1:
		print("val = (" + x[0] + " & 0x0FFFFFFFFL) * (" + y[0] +" & 0x0FFFFFFFFL);");
		print(z[0] +" = val & 0x0FFFFFFFFL;");
		print(z[1] +"=  (val >>> 32);");
	#case 2. call schoolbook mul
	elif n<=2:
		gen_mul_worker(x, y, t[0:2*n+1],  "0", z);
	#case 3. recursive call
	else: #RECURSIVE CAES
		#0. determine input
		x0, x1 = x[0:n//2], x[n//2:n];
		y0, y1 = y[0:n//2], y[n//2:n];
			
		#1. (x1+x0)(y1+y0) -> t[0:n+1]
		s_len = get_scratch_needed_exp(n//2);
		if n+1+s_len>len(t): panic("t length: " + str(len(t)) + " too small");
		expanded_mul(x1, x0, y1, y0, t[0:n+1], t[n+1:n+1+ get_scratch_needed_exp(n//2)]);
		#printMsg("AFTER (x1+x0)(y1+y0) -> t[0:n+1]");
		#printVecVar("t[0:n+1]: ", t[0:n+1]);

		#2. x1*y1 -> z[n:2n]
		gen_kara_mul(x1, y1, z[n:2*n], t[n+1: n+1 + get_scratch_needed(n)]);
		#printMsg("AFTER x1*y1 -> z[n:2n]");
		#printVecVar("z[0:n]: ", z[n:2*n]);

		#3. x0*y0 -> z[0:n]
		gen_kara_mul(x0, y0, z[0:n], t[n+1: n+1 + get_scratch_needed(n)]);
		#printMsg("AFTER x0*y0 -> z[0:n]");
		#printVecVar("z[n:2n]: ", z[n:2*n]);

		#4. z[n:2n] + z[0:n] -> t[n+1:2n+2] (i.e. x1*y1 + x0*y0) - 1 more limb
		# NOTE: taking t[2n+3], t[2n+4]
		z0 = t[2*n+3];
		z1 = t[2*n+4];
		print(z0 + " = 0;");
		print(z1 + " = 0;");
		a = z[0:n] + [z0];
		b = z[n:2*n] + [z1];
		gen_add_to(a, b , t[n+1:2*n+2], "0");
		#printMsg("AFTER x0*y0+x1*y1 -> t[n+1:2*n+2]");
		#printVecVar("t[n+1:2*n+2]: ", t[n+1:2*n+2]);
		
		
		#5.  t[0:n+1] - t[n+1:2n+2] -> t[0:n+1] (i.e., (x1+x0)(y1+y0)-x1y1-x0y0
		#printMsg("BEFORE (x1+x0)(y1+y0)-x1y1-x0y0: ");
		#printVecVar("t[0:n+1]: ", t[0:n+1]);
		#printVecVar("t[n+1:2n+2]: ", t[n+1:2*n+2]);
		gen_sub_to(t[0:n+1], t[n+1:2*n+2], t[0:n+1]);
		#printMsg("AFTER (x1+x0)(y1+y0)-x1y1-x0y0: ");
		#printVecVar("t[0:n+1]: ", t[0:n+1]);

		#6. z[n//2:2n] += t[0:n+1]
		#printMsg("BEFORE z[n//2:2*n] += t[0:n+1]: ");
		#printVecVar("z[n//2: 2*n]: ", z[0: 2*n]);
		#printVecVar("t[0: n+1]: ", t[0: n+1]);
		gen_add_to(z[n//2:2*n], t[0:n+1], z[n//2:2*n], "0");
		#printMsg("AFTER z[n//2:2*n] += t[0:n+1]: ");
		#printVecVar("z[n//2: 2*n]: ", z[0: 2*n]);
		

	
def gen_kara_mul_limbs(n):
	x = build_64bit_vars("this.d", n, "x");
	y = build_64bit_vars("other.d", n, "y");
	z = create_arr_vars("z", 2*n);	
	s = create_arr_vars("s", get_scratch_needed(n));
	gen_kara_mul(x, y, z, s);
	cpArr(gen_var_vec("this.d", len(z)), z, " (int) ");
	
# z = x * y 
# len(x)=len(y) = len(z), don't handle carry_out
# THAT IS: 256-bit * 256-bit --> 256bit (we discard the UPPER HALF)
# z HAS TO BE different FROM x and y
def gen_half_mul_worker(x, y, z):
	print("// HALF MUL: ");
	print("// " + str(z) + " = " + str(y) + " * " + str(y));
	n = len(y);
	for i in range(n):
		print(z[i] + " = 0;");
	for i in range(n):
		print("c = 0;");
		for j in range(n-i):
			print("val = "+z[i+j] + 
				" + ("+x[j]+" &0x0FFFFFFFFL) *  ((" 
				+ y[i] + "&0x0FFFFFFFFL) ) +  c;");
			print(z[i+j] +  " =  val & 0x0FFFFFFFFL;");
			print("c = val >>> 32; "); 
		for j in range(i+n, n):
			print("val = "+z[j] + " + c;");
			print(z[j] +  " =  val & 0x0FFFFFFFFL;");
			if j<n-1:
				print("c = val >>> 32; "); 
			
# e.g., 256bit*256bit -> 256bit
def gen_half_mul_limbs(n):
	x = build_64bit_vars("this.d", 2*n, "x");
	y = build_64bit_vars("other.d", n, "y");
	z = create_arr_vars("z", n);
	gen_half_mul_worker(x, y, z);
	cpArr(gen_var_vec("this.d", len(z)), z, " (int) ");

# ASSUMPTION: the N is 254 bit!!!!
# Add two Montgomery reduction -> one Montomery reduction
# Assuming x,y,z are 8 limbs
# first add them, if bit 255 is 1, minus N
def gen_add_mon(a, b, c):
	n = 8;
	x = build_64bit_vars(a, n, "x");
	y = build_64bit_vars(b, n, "y");
	t = create_arr_vars("t", n);
	gen_add_to(x, y, t, "0");
	print("long sign254 = (t7 >>> 30);");
	print("if (sign254==1){");
	u = build_64bit_vars("this.N.d", n, "u");
	gen_sub_to_worker(t, u, gen_var_vec(c,n), True); 
	print("}else{");
	cpArr(gen_var_vec(c, n), t, " (int) ");
	print("};");
	
# ASSUMPTION: the N is 254 bit!!!!
# Sub two Montgomery reduction -> one Montomery reduction
# Assuming x,y,z are 8 limbs
# first add them, if bit 255 is 1, plus N
def gen_sub_mon(a, b, c):
	n = 8;
	x = build_64bit_vars(a, n, "x");
	y = build_64bit_vars(b, n, "y");
	t = create_arr_vars("t", n);
	gen_sub_to(x, y, t);
	print("long sign255 = (t7 >>> 31);");
	print("if (sign255==1){");
	u = build_64bit_vars("this.N.d", n, "u");
	gen_add_to_worker(t, u, gen_var_vec(c,n), "0", True); 
	print("}else{");
	cpArr(gen_var_vec(c, n), t, " (int) ");
	print("};");

# MAIN -----------------------
#gen_kara_mul_limbs(8);
#gen_mul_limbs(8);
#gen_half_mul_limbs(8);
#gen_add_mon("a.d", "b.d", "dest.d");
gen_sub_mon("a.d", "b.d", "dest.d");


