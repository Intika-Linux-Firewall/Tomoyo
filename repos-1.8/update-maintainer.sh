#! /bin/sh
export LANG=C
[ `id -u` -ne 0 ] && exit 1
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
exit 0
