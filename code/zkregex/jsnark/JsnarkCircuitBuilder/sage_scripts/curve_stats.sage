# ------------------------------------------
# Print and Generate Stats of the given 25529 curve
# Save the curve stats in curves/A where
# A is the value of the A parameter
#
# Pass the A and PrimeFieldSize to genStats
# It will place in folder curves/Mont_fieldSize
# Use run.sh to check curve safety
#
# In Main, call search(A) for a good value of A.
# ------------------------------------------
import os;

def print_num(prefix, num):
	print prefix + "(" + str(num) + ") isPrime: " + str(is_prime(num)) + ", bits: " + str(num.nbits());

def getPointOrder(baseX, ec):
	pt = ec.lift_x(baseX);
	return pt.order();

def write(fname, content):
	sct = str(content);
	f1 = open(fname, "w");
	f1.write(sct);
	print "WRITE TO: " + fname + ", Content: " + sct;
	f1.close();

# ref: https://safecurves.cr.yp.to/disc.html
# baseOrder is a prime factor of p-t+1 where
# t is in range [-2sqrt(p), 2sqrt(p)]
# note that for curve 25519 we want baseOrder to be
# 1/8 of curve order, which is very close to p
# so trace should be:
# p - t + 1 = baseOrder * 8
# ==> t = p + 1 - baseOrder*8
def getTrace(p, baseOrder):
	return p + 1 - baseOrder*8;

def getSet(arr):
	arr2 = [];
	for x in arr:
		if not x in arr2:
			arr2.append(x);
	return arr2;

def getPrimeFactors(n):
	if n<0:
		n = 0 - n;
	if n<2:
		return [];
	if is_prime(n):
		return [n];
	F = factor(n);
	arr = list(F);
	arr2 = [];
	for x in arr:
		p = x[0];
		arr2.append(p);
	arr3 = getSet(arr2);
	return arr3;

# get the initial list for primes
def getAllPrimes_init(p, order, twist_order):
	t = getTrace(p, order//8);
	print "t: " + str(t);

	arrP = getPrimeFactors(p);
	print "arrP: " + str(arrP);
	arrOrder = getPrimeFactors(order);
	print "arrOrder: " + str(arrOrder);
	arrTwistOrder = getPrimeFactors(twist_order);
	print "twistOrder: " + str(arrTwistOrder);
	t24p = t*t-4*p;
	print "generating prime factors for t24p: " + str(t24p);
	arrT24p = getPrimeFactors(t24p);

	arrInit = arrP + arrOrder + arrTwistOrder + arrT24p;
	return arrInit;

# check if set1 contains set2
def contains(set1, set2):
	for x in set2:
		if not x in set1:
			return False;
	return True;

# for each q-1 in the list do it recursively	
def recPrimes(arrPrimes):
	arrPrimes = getSet(arrPrimes);
	print "DEBUG USE recPrimes: " + str(arrPrimes); 
	arr1 = [];
	for q in arrPrimes:
		if q>1:
			arr2 = getPrimeFactors(q-1);
			arr1 += arr2;
	if contains(arrPrimes, arr1):
		return arrPrimes;
	else:
		return getSet(arrPrimes + recPrimes(arr1));

# generate the primes needed by verify.sage	
def getAllPrimes(p, order, twist_order):
	arr1 = getAllPrimes_init(p, order, twist_order);
	arr2 = recPrimes(arr1);
	arr2.sort();
	sPrimes = "";
	for x in arr2:
		sPrimes += str(x) + " ";
	sPrimes = sPrimes[0:len(sPrimes)-1];
	return sPrimes;

# check if n is quadratic residue of p
def is_quadratic_residue(n, p):	
	n_p_1 = power_mod(n, (p-1)//2, p);
	return n_p_1 ==1;

# search A value in [beginA, endA]
# Criteria: curve_order>250 bits, twist_order>250_bits, 
# basept_order=curve_order/8
def searchA(beginA, endA, prime_field_order):
	for A in range(beginA, endA):
		print "---- try A: " + str(A);
		#1. check if A^2-4 is NOT qudratic residue
		A2_4 = A*A -4;
		if is_quadratic_residue(A2_4, prime_field_order):
			print "A^2-4 is quadratic residue";
			continue;
		ec = EllipticCurve(GF(prime_field_order), [0, A, 0, 1, 0]);

		#2. check the curve order
		corder = ec.order();
		corder_8 = corder//8;
		if not is_prime(corder_8):
			print "corder//8 is not prime!";
			continue;
		print "check done"


		#1. check twist order
		twist = ec.quadratic_twist().cardinality();
		twist_4 = twist//4;
		if not is_prime(twist_4):
			print "twist//4 is not prime!";
			continue;


		print "FOUND A: " + str(A);
		return A;

# search the x of base point given curve order//8 (desired point order)
def searchBaseX(ec, point_order):
	for x in range(1, 100):
		try:
			pt = ec.lift_x(x);
			print(pt);
			if pt.order()==point_order:
				return x;
		except:
			# do nothing
			y = 0;
	print "ERROR! FAILED TO LOCATE x";
	return 0;
 
# construct 25519 curve of form: y^2 = x^3 + A^x2 + x
def genStats(A, prime_field_order):
	# generate states
	ec = EllipticCurve(GF(prime_field_order),[0,A,0,1,0])
	corder = ec.cardinality();
	corder_8 = corder//8;
	twist = ec.quadratic_twist().cardinality();
	twist_4 = twist//4;
	basept_order = corder_8;
	baseX = searchBaseX(ec, basept_order);
	bpt = ec.lift_x(baseX);
	y1 = bpt[1];
	print_num("order/8", corder_8);
	print_num("twist/4", twist_4);
	print_num("base point order: ", basept_order);
	sPrimes= getAllPrimes(prime_field_order, corder, twist);

	# write the stats
	x0 = 6;
	genpt = ec.lift_x(x0);
	y0 = genpt[1];
	print "genpt is: " + str(genpt);
	gorder = genpt.order();
	print "genpt order is: " + str(gorder);
	
	dn =  str("curves/Mont_") + str(A);
	if(not os.path.isdir(dn)):
		os.mkdir(dn);
	write(dn+"/p", prime_field_order);
	write(dn+"/l", basept_order);
	write(dn+"/x1", baseX);
	write(dn+"/y1", y1);
	write(dn+"/x0", x0);
	write(dn+"/y0", y0);
	write(dn+"/shape", "montgomery");
	write(dn+"/A", A);
	write(dn+"/B", 1);
#	write(dn+"/primes", " 2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 73 79 83 97 101 103 107 109 113 127 131 139 151 163 173 181 191 223 227 233 239 251 269 307 353 383 419 457 467 479 487 503 727 991 1361 1723 2281 2437 2551 2791 2851 2939 3637 3727 3797 3911 4153 4363 5879 6211 6263 7229 8053 9463 11351 12527 14851 15101 16451 17231 17659 22111 28859 30203 30703 32573 34123 34217 37853 41081 57467 65147 75707 82163 84457 117223 132049 132667 137849 173497 196993 208393 372661 409477 430751 531581 569003 693989 727169 1224481 1923133 5859383 6418733 8574133 14741173 58964693 122232809 150381227 292386187 743104567 1019532643 1110318119 2220636239 2773320623 9374403413 13481018963 72106336199 213441916511 1013266244677 5171003929967 1257559732178653 1919519569386763 6514380687527359 31757755568855353 4434155615661930479 22561162540501040539 243585722668023007729 3044861653679985063343 8312956054562778877481 172054593956031949258510691 198211423230930754013084525763697 75445702479781427272750846543864801 19757330305831588566944191468367130476339 203852586375664218368381551393371968928013 276602624281642239937218680557139826668747 104719073621178708975837602950775180438320278101 83326725728999296701078628838522133333655224556987 27413359092552162435694767700453926735143482401279781 74058212732561358302231226437062788676166966415465897661863160754340907 7237005577332262213973186563042994240857116359379907606001950938285454250989 14474011154664524427946373126085988481603263447650325797860494125407373907997 57896044618658097711785492504343953926634992332820282019728792003956564819949");
	write(dn+"/primes", sPrimes);
	write(dn+"/rigid", "fully rigid");
	
	

# ----------------------------------------
# MAIN program
# ----------------------------------------
#genStats(486662, 2^255-19); #standard curve 25519
#genStats(126932, 21888242871839275222246405745257275088548364400416034343698204186575808495617); #snark friendly for libsnark
genStats(30428, 7237005577332262213973186563042994240857116359379907606001950938285454250989); #snark friendly for curve 25519's group order (field arith order)

# search A for snark-friendly for 25519, 
# prime field is the base point order of curve 25519.
#searchA(486660, 487000, 2^255-19);

# the search for jsnark's curve for libsnark
# see gadgets/example/diffieHellman/ECDH...
#searchA(126900, 1270000, 21888242871839275222246405745257275088548364400416034343698204186575808495617); #JSnark curve for libsnark

# search for the zksnark friendly curve for curve 25519's 
# subgroup order
#searchA(10000, 900000, 7237005577332262213973186563042994240857116359379907606001950938285454250989); 


