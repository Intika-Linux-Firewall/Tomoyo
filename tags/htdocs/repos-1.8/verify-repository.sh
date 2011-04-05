#! /bin/sh

die () {
    echo $1
    exit 1
}

export LANG=C
gpg --verify Release.gpg Release 2>&1 | grep -qF 'Good signature from "Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>"' || die "GPG verify failed."
awk ' { if ( $3 == "Packages" && length($1) == 40) print $1 "  " $3 ; } ' Release | sha1sum --status --check - || die "SHA1SUM verify failed."
awk ' { if ( $1 == "Filename:" ) fn = $2; else if ( $1 == "MD5sum:" ) print $2 "  " fn; } ' Packages | md5sum --status --check - || die "MD5SUM verify failed."
echo "OK"
exit 0
