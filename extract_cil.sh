#!/bin/bash -x
set -e
# Any subsequent(*) commands which fail will cause the shell script to exit immediately

# Copy this script into copy of /var/lib/selinux/targeted/active/modules/100/ directory and run
# It will yield directory containing extracted cil files <module_name>.cil

FOLDER="__extracted"

mkdir $FOLDER

for i in $( ls ) 
do
	if [[ -d $i ]] && [ "$i" != "$FOLDER" ]
	then
		bzcat $i/cil > ./$FOLDER/$i.cil
	fi
done