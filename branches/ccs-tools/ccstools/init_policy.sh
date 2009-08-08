#! /bin/sh
cd ${0%/*}
exec ./init_policy version=1.7.0-pre policy_dir=/etc/ccs "$@"
