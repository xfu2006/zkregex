# simulator for CIOS Montogoery Product
# ------------------Utility Functions ----------------------------
from random import *;
def to_bi(arr, W, s):
	res = 0;
	for x in range(s):
		res = res*W;
		res += arr[s-1-x];
	return res;

def to_arr(n, s, W):
	arr = [0] * s;
	for x in range(s):
		arr[x] = n % W;
		n = n // W;
	return arr;
 
def hex_dump(arr):
	for i in range(8):
		print(str(i) + ": " + hex(arr[i]));

def hex_dump2(prefix, arr):
	print(prefix);
	for i in range(8):
		print(str(i) + ": " + hex(arr[i]));

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x-(b//a)*y,y)

# assumption a and n are coprime
def mod_inverse(a, n):
	g, x, y = egcd(a, n)
	return x % n;

# logical Montgomery Production - slow
# assume a and b are already in Montgomery form: in range [0, N-1]
def logical_MonPro(a, b, R, N):
	INV_R = mod_inverse(R, N);
	T = a * b;
	res = T * INV_R % N;
	return res;

# FASTER implementation
# W is the word size, e.g., 2**32
# s is the number of limbs for numbers, e.g., 8
# It's required that R = W^s
# Ref: https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf
def CISO(a, b, R, N, s):
	W = 2**(R.bit_length()//s);
	print("W is ", W);
	INV_R = mod_inverse(R, N);
	INV_N = mod_inverse(N, R);
	invn = to_arr(INV_N, s, W);
	invn0 = W - invn[0];
	n = to_arr(N, s, W);
	a = to_arr(a, s, W);
	b = to_arr(b, s, W);
	
	# ALGORITHM
	t = [0] * (s+2);
	for i in range(s):
		c = 0;
		for j in range(s):
			val = t[j] + a[j]*b[i] + c;
			t[j] = val%W;
			c = val // W;
		val = t[s] + c;
		t[s] = val % W;
		t[s+1] = val //W;
		print("============i: " + str(i) + "=====");
		print("STAGE 1: ", t);
		c = 0;
		m = (t[0] * invn0) % W;
		print("BEFORE STAGE 2: t[0]: ", hex(t[0]));
		print("BEFORE STAGE 2: n[0]: ", hex(n[0]));
		print("BEFORE STAGE 2: m: ", hex(m));
		val = t[0] + m*n[0];
		c = val // W;
		print("n: ", str(n));
		print("STAGE 2 val: ", hex(val));
		print("STAGE 2 c: ", hex(c));

		#print("c is ", c, "t0:", t[0], "m: ", m, "n[0]", n[0]);
		for j in range(1, s):
			val = t[j] + m*n[j] + c;
			t[j-1] = val % W;
			c = val // W;
		val = t[s] + c;
		t[s-1] = val % W;
		c = val // W;
		t[s] = t[s+1] + c;
		#print("STAGE 2: ", t);
	print("FINAL STEP: T: ", t);
	T = to_bi(t, W, s);
	hex_dump2("T details:", t);
	return T;

#-------------------------------------------------

# ------------- MAIN PROGRAM -------------------


R = 115792089237316195423570985008687907853269984665640564039457584007913129639936;
N = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 
a = randint(0, N);
b = randint(0, N);
a = 1;
b = 1;
res1 = logical_MonPro(a, b, R, N);
res2 = CISO(a, b, R, N, 8);
print("res1: ", res1, "res2:", res2);
