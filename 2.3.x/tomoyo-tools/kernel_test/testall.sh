#! /bin/sh

cd ${0%/*}
export PATH=$PWD:${PATH}

echo "Testing all. (All results are reported)"
newns ccs_accept_test
newns ccs_filesystem_test
newns ccs_file_test
newns ccs_rewrite_test
newns ccs_new_file_test
newns ccs_new_test
echo
echo
echo
echo "Testing all. (Only ERRORS are reported)"
newns ccs_accept_test | grep -vF Done
newns ccs_filesystem_test | grep -vF OK | grep -F '('
newns ccs_file_test | grep -vF OK | grep -F '('
newns ccs_rewrite_test | grep -vF OK | grep -F '('
newns ccs_new_test | grep -vF OK
echo
echo
echo
echo "Testing policy I/O.  (Only ERRORS are reported)"
newns ccs_policy_io_test | grep -vF OK
newns ccs_new_file_test | grep -vF OK
