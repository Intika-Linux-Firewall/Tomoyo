#! /bin/sh

cd ${0%/*}
export PATH=$PWD:${PATH}

echo "Testing all. (All results are reported)"
newns tomoyo_accept_test
newns tomoyo_filesystem_test
newns tomoyo_file_test
newns tomoyo_rewrite_test
newns tomoyo_argv0_test
newns tomoyo_new_file_test
newns tomoyo_new_test
echo
echo
echo
echo "Testing all. (Only ERRORS are reported)"
newns tomoyo_accept_test | grep -vF Done
newns tomoyo_filesystem_test | grep -vF OK | grep -F '('
newns tomoyo_file_test | grep -vF OK | grep -F '('
newns tomoyo_rewrite_test | grep -vF OK | grep -F '('
newns tomoyo_argv0_test | grep -vF OK | grep -F '('
newns tomoyo_new_test | grep -vF OK
echo
echo
echo
echo "Testing policy I/O.  (Only ERRORS are reported)"
newns tomoyo_bprm_test | grep -vF OK
newns tomoyo_cond_test | grep -vF OK
newns tomoyo_policy_io_test | grep -vF OK
newns tomoyo_new_file_test | grep -vF OK
