#! /bin/bash
dir=$PWD
exec 100< dirmap.txt
while read -u 100 release_id release_dir
  do
  # mkdir -p $dir/$release_dir
  cd $dir/$release_dir || continue
  echo $PWD
  wget -q -O - http://osdn.jp/projects/tomoyo/releases/$release_id/ | awk -F'"' ' { for (i = 1; i < NF; i++) { if ( index( $i, "/projects/tomoyo/downloads/" ) > 0) { $i = substr($i, 28); print "http://osdn.dl.osdn.jp/tomoyo/" substr($i, 1, length($i) - 1); } } } ' | xargs wget
done
exit 0
