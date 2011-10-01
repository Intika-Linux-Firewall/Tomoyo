#! /bin/sh

rm -f -- *backport*.deb *debug*.deb
ls -1 linux*ccs*deb | awk ' { if ( index($0, "ccs1.8.3") == 0 ) print "mv " $0 " " $0; } ' | sed -e 's/ccs/ccs1.8.3/2' | sh
rm -f Contents.gz Packages Packages.gz Release Release.gpg
apt-ftparchive contents . | gzip -9 > Contents.gz
apt-ftparchive packages . > Packages
gzip -9 < Packages > Packages.gz
apt-ftparchive release . > Release
gpg --sign -b -a -o Release.gpg Release
echo "Done"
exit 0
