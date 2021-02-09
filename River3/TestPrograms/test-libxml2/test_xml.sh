#!/bin/bash

make && pushd ../../python
python3 concolic_GenerationalSearch2.py --binaryPath "../TestPrograms/test-libxml2/read_xml" \
    --architecture x64 \
    --maxLen 500 \
    --logLevel CRITICAL \
    --secondsBetweenStats 10 \
    --outputType textual
popd
