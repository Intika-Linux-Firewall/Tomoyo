#!/bin/bash

if (( $# != 2 )); then
	printf '%s\n' "Usage: build-man-pages.sh NAME VERSION"
	printf '%s\n' "    Example: build-man-pages.sh ccs-tools 1.8.3"
	printf '%s\n' "    Example: build-man-pages.sh tomoyo-tools 2.5.0"
	exit 1
fi

name="${1}"
version="${2}"

for i in *.pod; do
	# Convert to man page.
	pod2man --section=8 \
		--center="System Administration Utilities" \
		--release="${name} ${version}" "${i}" \
		| gzip -9 > "${i%pod}8.gz"
	# Convert to html.
	pod2html --title="${i%.pod}" "${i}" > "${i%pod}html.en"
	# Remove temporary files.
	rm -v pod2htm*
done
