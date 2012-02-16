#!/bin/bash

if (( $# != 1 )); then
	printf '%s\n' "Usage: build-man-pages.sh VERSION"
	printf '%s\n' "    Example: build-man-pages.sh 1.8.3"
	exit 1
fi

version="${1}"

for i in *.pod; do
	pod2man --center="System Administration Utilities" \
		--release="ccs-tools ${version}" "${i}" \
		| gzip -9 > "${i%pod}8.gz"
done
