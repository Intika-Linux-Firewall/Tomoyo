#! /bin/sh
cd ${0%/*}
exec ./init_policy version=1.6.8 policy_dir=/etc/ccs "$@"
