#!/bin/bash -vx

#if [ "$(id -u)" != "0" ]; then
#   echo "This script must be run as root" 1>&2
#   exit 1
#fi

set -e
# Any subsequent(*) commands which fail will cause the shell script to exit immediately

TOOL_FOLDER=$(pwd)
FOLDER="data"
SOURCE="policy_data"

for i in $( ls $SOURCE ) 
do
	if [[ -d $SOURCE/$i ]]
	then
		#echo data/graph_${i:24}
		./build_graph.py -fb -c file,process $FOLDER/graph_${i:24} -p $SOURCE/$i/policy.29
	#	bzcat $i/cil > ./$FOLDER/$i.cil
	fi
		
done

#CIL_FILES=$(pwd)

#cd $TOOL_FOLDER

#python3 -c "import domain_grouping; domain_grouping.parse_cil_files('$CIL_FILES/$FOLDER')" > domain_groups_cil.conf

#rm -rf $CIL_FILES
