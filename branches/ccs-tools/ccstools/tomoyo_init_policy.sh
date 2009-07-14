#! /bin/sh
cd ${0%/*}
exec ./init_policy version=2.2.0 policy_dir=/etc/tomoyo
