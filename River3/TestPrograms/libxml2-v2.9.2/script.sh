#!/bin/bash

cd report 
rm -rf*
cd ..
lcov -c -d . -d libxml2/ -o report/app.info

cd report
genhtml app.info
cd ..

