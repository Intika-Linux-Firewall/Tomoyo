#! /bin/sh

update_maintainer() {
    [ -r $1 ] || exit 1
    mkdir tmp
    dpkg-deb -e $1 tmp
    if grep -qF 'Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>' -- tmp/control
	then
	rm -fR tmp
    else
	mkdir tmp/DEBIAN
	mv tmp/control tmp/DEBIAN/
	echo "Processing " $1
	dpkg-deb -x $1 tmp
	sed -i -e 's/^Maintainer:.*/Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>/' -- tmp/DEBIAN/control
	dpkg-deb -b tmp
	rm -fR tmp
	mv tmp.deb $1
    fi
}

export LANG=C
for i in *.deb
  do
  update_maintainer $i
done

rm -f Contents.gz Packages Packages.gz Release Release.gpg
apt-ftparchive contents . | gzip -9 > Contents.gz
apt-ftparchive packages . > Packages
gzip -9 < Packages > Packages.gz
apt-ftparchive release . > Release
gpg --sign -b -a -o Release.gpg Release
echo "Done"
exit 0
