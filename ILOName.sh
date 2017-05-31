#!/bin/bash
#######This Script is to change ILO Server name & ILO Name#######

HOSTLIST=`cat /home/stack/DHEEPAN/host`
#USERID='helionopslab'
IFS=$'\n'

for HOSTLISTS in $HOSTLIST
do
                ILOIP=$(echo $HOSTLISTS | awk '{print $1}')
                ILONAME=$(echo $HOSTLISTS | awk '{print $2}')

echo "*********Changing Server Name of $ILONAME************"
echo $ILOIP
                ssh -l Administrator $ILOIP "set /system1 oemhp_server_name=$ILONAME"
                ssh -l Administrator $ILOIP "set /map1/enetport1 SystemName=ILO-$ILONAME"
done
