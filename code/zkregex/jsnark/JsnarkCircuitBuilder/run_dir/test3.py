from galois_field.GF import GF, FFElement
from galois_field.fast_polynom import FastPolynom

irr_poly = FastPolynom({0: 1, 1: 1, 3: 1})
ff = GF(2, 3, irr_poly)
e1 = FFElement(ff, FastPolynom({0: 1, 1: 1}))
e2 = FFElement(ff, FastPolynom({0: 1, 1: 1}))
e_res = e1 * e2
print(str(e1));
print(str(e_res));

ff2 = GF(2**255-19, 1);
e1 = FFElement(ff2, FastPolynom({0:9}));
e2 = e1+e1;
e3 = e1.inverse();
enum1 = FFElement(ff2, FastPolynom({0:1}));
m1 = FFElement(ff2, FastPolynom({0:2**255-20})); #-1
e5 = enum1 + m1;
enum4 = FFElement(ff2, FastPolynom({0:4}));

print("e1: " + str(e1));
print("e2: " + str(e2));
print("e3: " + str(e3));
print("enum1: " + str(enum1));

x1 = FFElement(ff2, FastPolynom({0:4}));
A = FFElement(ff2, FastPolynom({0:486662})); 
x3 = (x1*x1+m1);
x4 = enum4*x1*(x1*x1+A*x1+enum1);
xres = x3*x3/x4;
print("x3: " + str(x3));
print("x4: " + str(x4));
print("xres: " + str(xres));

