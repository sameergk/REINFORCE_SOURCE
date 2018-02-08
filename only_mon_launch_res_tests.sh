#!/bin/bash
#usage: <prog_name> <$1=Mode [ Baseline, Local_Replica or Remote_Replica]> <$2=Result_Subdir [r1, r2, r3..]> 
#./launch_res_tests.sh baseline r5
# Results will be stored at: /home/skulk901/dev/res_results/<$2>/<$1>
mode=$1
res_dir=$2

if [ -z $mode ]
then
  mode="unknown"
fi

if [ -z $res_dir ]
then
  res_dir="res_unset"
fi
mkdir -p dev/res_results/$res_dir
mkdir -p dev/res_results/$res_dir/$mode

t_sec=150
base_dir="dev/res_results/${res_dir}/${mode}/"

function post_process_data() {
nf_name=$1
cp histogram.csv $base_dir/${nf_name}_histogram_c.csv

#Duplicate the entires that have been clustered in same group a,b => a,a,... b times.
#awk 'BEGIN { FS = ","; l=0;k=0;j=0;}; $2 > 1 {l++; k=$2; j+=$2; for(i=0;i<k;i++) $2="1";print } END {print "repeat_count=" l "j=" j}' mtest.csv >mtest3.csv
#awk 'BEGIN { FS = ","; l=0;k=0;j=0;}; $2 > 1 {l++; k=$2; j+=$2; for(i=0;i<k;i++) $2="1";print }' $base_dir/${nf_name}_histogram_c.csv >$base_dir/${nf_name}_histogram.csv
#awk 'BEGIN { FS = ","; OFS=","; l=0;k=0;j=0;}; {l++; k=$2; j+=$2; for(i=0;i<k;i++) print $1,1}' $base_dir/${nf_name}_histogram_c.csv >$base_dir/${nf_name}_histogram.csv
awk 'BEGIN { FS = ","; OFS=","; l=0;k=0;j=0;}; {l++; k=$2; j+=$2; for(i=0;i<k;i++){ $2="1";print;} }' $base_dir/${nf_name}_histogram_c.csv >$base_dir/${nf_name}_histogram.csv
awk 'BEGIN { FS = "," } ; {print $1}' $base_dir/${nf_name}_histogram.csv > $base_dir/${nf_name}_lat_$mode.csv
wc -l $base_dir/${nf_name}_histogram_c.csv $base_dir/${nf_name}_histogram.csv $base_dir/${nf_name}_lat_$mode.csv

#clear Outliers: First and Last (5+5) 10 entries.
sed '1,5d' $base_dir/${nf_name}_lat_$mode.csv > $base_dir/${nf_name}_lat_${mode}_0.csv
for i in `seq 1 5`;
do
    sed -i '$d' $base_dir/${nf_name}_lat_${mode}_0.csv
done

#Add count of total records to the first index or add as first column
LCOUNT=`awk 'END{print NR}' $base_dir/${nf_name}_lat_${mode}_0.csv`
awk 'BEGIN{OFS=","} {print $1,'$LCOUNT'}' $base_dir/${nf_name}_lat_${mode}_0.csv > $base_dir/${nf_name}_lat_${mode}_0_gnu.csv
sed  '1s/^/'$LCOUNT' \n/' $base_dir/${nf_name}_lat_${mode}_0.csv > $base_dir/${nf_name}_lat_${mode}_1_gnu.csv
}

stime="echo Start@ `date`: `date +%T.%3N`"
etime="echo End@ `date`: `date +%T.%3N`"
echo "Startin Test for Mode:$1"

function run_DPI() {
test_nf="DPI"
echo "Starting Test for DPI:"
$stime; timeout $t_sec ./lmoon001.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for DPI Ended!!! Reset ONVM_MGR, setup for Simple Forwarder and press Enter to continue!"
echo " Test for $mode Ended!! \n "
read varname
echo "Key: $varname"
echo ""
}
#run_DPI

function run_SFWD () {
test_nf="Simple_Forwarder"
echo "Starting Test for Simple Forwarder"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Simple Forwarder Ended!!!"
echo "Reset ONVM_MGR, setup for MONITOR and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""
}
#run_SFWD

function run_MON() {
test_nf="Monitor"
echo "Starting Test for Monitor:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Simple Monitor Ended!!!"
echo "Reset ONVM_MGR, setup for VLAN_TAGGER and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""
}
#run_MON

function run_QOS() {
test_nf="QoS"
echo "Starting Test for QoS(VlanTag):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for QoS(VlanTag) Ended!!!"
echo "Reset ONVM_MGR, setup for Load Balancer and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""
}
#run_QOS

function run_LB() {
test_nf="Load Balancer"
echo "Starting Test for Load Balancer:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Load Balancer Ended!!!"
echo "Reset ONVM_MGR settings; service chain settings in services.txt to setup Chain 1 (QoS_c->Mon)!"
read varname
echo "Key: $varname"
echo ""
}
run_LB

function run_chain1() {
test_nf="Chain1"
echo "Starting Test for Chain1:(QoS->Mon):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain1(Qos_c->Mon) Ended!!!"
echo " Test for $mode Ended!! \n Reset ONVM_MGR settings; service chain settings in services.txt and setup Chain2 (Qos_c->Mon_c->LB)!"
read varname
echo "Key: $varname"
echo ""
}
#run_chain1

function run_chain2() {
test_nf="Chain2"
echo "Starting Test for Chain1:(QoS->Mon):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain2 (QoS_c->Mon_c->LB) Ended!!!"
echo "Test for $mode Ended!! \n Reset ONVM_MGR settings; Reset ONVM_SETTINGS; service chain settings in services.txt RECOMPILE AND LAUNCH NEW TESTS!"
read varname
echo "Key: $varname"
echo ""
}
#run_chain2
scp -r $base_dir/* root@flashstack-3:/home/skulk901/dev/my_fork/nfv_resiliency_work/res_results/${res_dir}/${mode}/
