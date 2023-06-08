for i in range(8):
	print("c = 0;");
	for j in range(8):
		print("val = (d"+str(i)+" & 0x0FFFFFFFFL) * ( other.d"+str(j)+" & 0x0FFFFFFFFL) + c;"); 
		print("row"+str(j) +" = val & 0x0FFFFFFFFL;");
		print("c = (val>>>32);");
	print("row8 = c & 0x0FFFFFFFFL;");
	print("c = 0;");
	for j in range(i, i+9):
		print("val = res"+str(j) + "+row"+str(j-i) + "+c;");
		print("res"+str(j) +"= val & 0x0FFFFFFFFL;");
		print("c = val >>> 32;");

