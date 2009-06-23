#! /bin/sh

cd ${0%/*}
export PATH=$PWD:${PATH}

echo "Testing all. (All results are reported)"
newns tomoyo_file_test
echo
echo "Testing all. (Only ERRORS are reported)"
newns tomoyo_file_test | grep -vF OK
