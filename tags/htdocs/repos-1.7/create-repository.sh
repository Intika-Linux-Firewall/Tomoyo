#! /bin/sh

rm -f Contents.gz Packages Packages.gz Release Release.gpg
apt-ftparchive contents . | gzip -9 > Contents.gz
apt-ftparchive packages . > Packages
gzip -9 < Packages > Packages.gz
apt-ftparchive release . > Release
gpg --sign -b -a -o Release.gpg Release
echo "Done"
exit 0
