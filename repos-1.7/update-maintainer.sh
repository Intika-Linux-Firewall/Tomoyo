#! /bin/sh
[ -r $1 ] || exit 1
export LANG=C
mkdir tmp
dpkg-deb -e $1 tmp
if grep -qF 'Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>' -- tmp/control
then
    rm -fR tmp
    exit 0
fi
mkdir tmp/DEBIAN
mv tmp/control tmp/DEBIAN/
echo "Processing " $1
dpkg-deb -x $1 tmp
sed -i -e 's/^Maintainer:.*/Maintainer: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>/' -- tmp/DEBIAN/control
dpkg-deb -b tmp
rm -fR tmp
mv tmp.deb $1
exit 0
