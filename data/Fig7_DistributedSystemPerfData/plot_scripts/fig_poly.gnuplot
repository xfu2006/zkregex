set term postscript eps color size 16in,4in font 'Verdenta,30'
#set term pdf size 7in,3in 
#set terminal wxt size 1300,600
#set term eps size 1300,600
set output 'output/fig_poly.eps' 
#clear
#reset
set autoscale 
set multiplot layout 1, 4 title ""

#1. FFT
set title "FFT"
set key bottom right 
set border 3
#set output "output/fig_fft.tex"
set xlabel 'Degree'
set ylabel 'Time (sec)' rotate by 90
ntics = 2
set yzeroaxis
set logscale x 2; 
set logscale y 2; 
set format x '2^{%L}'
set format y '2^{%L}'
set grid

plot "raw_data/fft_hpc256.dat" using 1:($2/1000) title '4-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($3/1000) title '8-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($4/1000) title '16-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($5/1000) title '32-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($6/1000) title '64-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($7/1000) title '128-nodes' with linespoints,\
	 "raw_data/fft_hpc256.dat" using 1:($8/1000) title '256-nodes' with linespoints

#2. Mul 
set title "Multiplication"
set key left 
set border 3
#set output "output/fig_fft.tex"
set xlabel 'Degree'
set ylabel 'Time (sec)' rotate by 90
ntics = 1
set yzeroaxis
set logscale x 2; 
set logscale y 2; 
set format x '2^{%L}'
set format y '2^{%L}'
set grid

plot "raw_data/mul_hpc256.dat" using 1:($2/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($3/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($4/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($5/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($6/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($7/1000)   notitle with linespoints,\
	 "raw_data/mul_hpc256.dat" using 1:($8/1000)   notitle with linespoints

#2. Div 
set title "Division"
set key left 
set border 3
#set output "output/fig_fft.tex"
set xlabel 'Degree'
set ylabel 'Time (sec)' rotate by 90
ntics = 1
set yzeroaxis
set logscale x 2; 
set logscale y 2; 
set format x '2^{%L}'
set format y '2^{%L}'
set grid

plot "raw_data/div_hpc256.dat" using 1:($2/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($3/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($4/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($5/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($6/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($7/1000)   notitle with linespoints,\
	 "raw_data/div_hpc256.dat" using 1:($8/1000)   notitle with linespoints

#2. Groth 
set title "Groth16"
set key left 
set border 3
#set output "output/fig_fft.tex"
set xlabel 'Degree'
set ylabel 'Time (sec)' rotate by 90
ntics = 1
set yzeroaxis
set logscale x 2; 
set logscale y 2; 
set format x '2^{%L}'
set format y '2^{%L}'
set grid

plot "raw_data/groth_hpc256.dat" using 1:($2/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($3/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($4/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($5/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($6/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($7/1000)   notitle with linespoints,\
	 "raw_data/groth_hpc256.dat" using 1:($8/1000)   notitle with linespoints
unset multiplot
