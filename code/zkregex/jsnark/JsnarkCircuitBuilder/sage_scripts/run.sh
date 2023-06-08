#sage curve_stats.sage

#sage verify.sage curves/Mont_486662
#echo "==============Montgomory Curve with A: 486662============"
#find curves/Mont_486662 -name "verify-safe*" | xargs -I % sh -c 'echo %; cat %;'
#sage verify.sage curves/Mont_126932
#echo "==============Montgomory Curve with A: 126932============"
#find curves/Mont_126932 -name "verify-safe*" | xargs -I % sh -c 'echo %; cat %;'
sage verify.sage curves/Mont_30428
echo "==============Montgomory Curve with A: 30428============"
find curves/Mont_30428 -name "verify-safe*" | xargs -I % sh -c 'echo %; cat %;'
