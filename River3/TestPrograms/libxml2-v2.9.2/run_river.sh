#!/bin/bash

pushd ../../python
python3 concolic_GenerationalSearch2.py --binaryPath "../TestPrograms/libxml2-v2.9.2/out/xml" \
    --entryfuncName "main" \
    --architecture x64 \
    --maxLen 5 \
    --logLevel CRITICAL \
    --secondsBetweenStats 10 \
    --outputType textual && \
popd
