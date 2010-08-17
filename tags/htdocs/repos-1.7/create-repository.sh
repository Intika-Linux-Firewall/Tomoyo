#! /bin/sh

update_maintainer() {
    [ -r $1 ] || exit 1
    mkdir tmp || exit 1
    mkdir tmp/DEBIAN || exit 1
    dpkg-deb -e $1 tmp/DEBIAN || exit 1
    if ! grep -qF 'Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>' -- tmp/DEBIAN/control
    then
	echo "Processing " $1
	dpkg-deb -x $1 tmp || exit 1
	sed -i -e 's/^Maintainer:.*/Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>/' -- tmp/DEBIAN/control || exit 1
	dpkg-deb -b tmp && mv tmp.deb $1 || exit 1
    fi
    rm -fR tmp
}

export LANG=C
[ `id -u` -ne 0 ] && exit 1
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
