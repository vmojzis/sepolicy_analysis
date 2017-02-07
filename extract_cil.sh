#!/bin/bash -vx

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

set -e
# Any subsequent(*) commands which fail will cause the shell script to exit immediately

TOOL_FOLDER=$(pwd)
FOLDER="__extracted"

mkdir /tmp/cil
cd /tmp/cil
cp -R /var/lib/selinux/targeted/active/modules/100/* .

mkdir $FOLDER

for i in $( ls ) 
do
	if [[ -d $i ]] && [ "$i" != "$FOLDER" ]
	then
		bzcat $i/cil > ./$FOLDER/$i.cil
	fi
done

CIL_FILES=$(pwd)

cd $TOOL_FOLDER

python3 -c "import sepolicyanalysis.domain_grouping; domain_grouping.parse_cil_files('$CIL_FILES/$FOLDER')" > /etc/sepolicyanalysis/domain_groups_cil.conf

rm -rf $CIL_FILES
