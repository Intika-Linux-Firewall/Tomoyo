#! /bin/sh
cd ${0%/*}
exec ./init_policy policy_dir=/etc/ccs "$@"
