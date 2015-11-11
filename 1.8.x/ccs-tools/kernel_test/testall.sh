#! /bin/sh
#
# testall.sh
#
# Copyright (C) 2005-2011  NTT DATA CORPORATION
#
# Version: 1.8.5   2015/11/11
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License v2 as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#
cd ${0%/*}
export PATH=$PWD:${PATH}

echo "Testing all. (All results are reported)"
newns ccs_accept_test
newns ccs_filesystem_test
newns ccs_file_test
newns ccs_rewrite_test
newns ccs_capability_test
newns ccs_signal_test
newns ccs_network_test
newns ccs_argv0_test
newns ccs_env_test
newns ccs_new_file_test
newns ccs_new_capability_test
newns ccs_new_network_test
newns ccs_new_test
newns ccs_transition_test
newns ccs_bind_test
echo
echo
echo
echo "Testing all. (Only ERRORS are reported)"
newns ccs_accept_test | grep -vF Done
newns ccs_filesystem_test | grep -vF OK | grep -F '('
newns ccs_bind_test | grep -vF exhausted | grep -vF Done
newns ccs_file_test | grep -vF OK | grep -F '('
newns ccs_rewrite_test | grep -vF OK | grep -F '('
newns ccs_capability_test | grep -vF OK | grep -F '('
newns ccs_signal_test | grep -vF OK | grep -F '('
newns ccs_network_test | grep -vF OK | grep -F '('
newns ccs_argv0_test | grep -vF OK | grep -F '('
newns ccs_env_test | grep -vF OK | grep -F '('
newns ccs_new_test | grep -vF OK
newns ccs_transition_test | grep -vF OK
echo
echo
echo
echo "Testing policy I/O.  (Only ERRORS are reported)"
newns ccs_bprm_test | grep -vF OK
newns ccs_cond_test | grep -vF OK
newns ccs_policy_io_test | grep -vF OK
newns ccs_new_file_test | grep -vF OK
newns ccs_new_capability_test | grep -vF OK
newns ccs_new_network_test | grep -vF OK
newns ccs_execute_handler_test | grep -vF OK
dmesg -c
uname -r
