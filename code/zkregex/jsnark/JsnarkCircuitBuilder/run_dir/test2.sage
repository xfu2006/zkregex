ec = EllipticCurve(GF(2^255-19),[0,486662,0,1,0])
#p1 = ec.lift_x(4,all)[0]
#print(p1)
#p2 = p1 + p1
#print(p2)
print("2^255-19 is: " + str(2^255-19));
forder = ec.order();
print("field-order: " + str(forder));
corder = ec.cardinality();
print("curve-order: " + str(corder));
exp_twist = (2*(2^255-19 + 1) - corder);
p2 = exp_twist/4;
print("expected twist order/4: " + str(p2));
p2_2 = 2^253-55484635554744707071703875581767296995
print("given in paper: " + str(p2_2));
twist = ec.quadratic_twist().cardinality();
t4 = twist//4
print("generated twist/4: " + str(twist/4));
print("num bits of twist/4: " + str(t4.nbits()));
print("t4 is a prime: " + str(is_prime(t4)));


