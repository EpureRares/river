#!/bin/bash

DIR=$(pwd)/BinaryFiles

for file in $DIR/sample $DIR/crackme_xor $DIR/crackme_sample; do
	echo ".binaryPath = \"$(echo $file)\"";
	jq ".binaryPath = \"$(echo $file)\"" $(echo $(pwd)/arguments.json) > tmp.$$.json && mv tmp.$$.json $(echo $(pwd)/arguments.json);
	
	gdb --batch-silent -x $(pwd)/simple_test.py --batch --args $file
	echo "\n";
done	

rm -rf tmp.*
#gdb --batch-silent -x /home/ubuntu/Desktop/auux/river/River3/Unittests/simple_test.py --batch --args /home/ubuntu/Desktop/auux/river/River3/Unittests/BinaryFiles/sample
