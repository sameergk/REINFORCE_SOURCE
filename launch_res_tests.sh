#!/bin/bash
#usage: <prog_name> <$1=Mode [ Baseline, Local_Replica or Remote_Replica]> <$2=Result_Subdir [r1, r2, r3..]> 
#./launch_res_tests.sh baseline r5
# Results will be stored at: /home/skulk901/dev/res_results/<$2>/<$1>
mode=$1
res_dir=$2
#now=$(date +"%d_%m_%Y_%H_%M_%S")
now=$(date +"%d_%m_%Y_%H")
if [ -z $mode ]
then
  mode="unknown"
fi

if [ -z $res_dir ]
then
  res_dir="res_unset"
fi
res_dir=$res_dir$now

root_dir="/home/skulk901"
mkdir -p ${root_dir}/dev/res_results/$res_dir
mkdir -p ${root_dir}/dev/res_results/$res_dir/$mode

t_sec=120
base_dir="${root_dir}/dev/res_results/${res_dir}/${mode}/"
echo"Base Directory for Results: ${base_dir}"

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

test_nf="DPI"
echo "Starting Test for DPI: in ${mode}. Launch the DPI NF and enter 1"
read varname
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for DPI: in ${mode} Ends! enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for DPI Ended!!! Reset ONVM_MGR, setup for Simple Forwarder and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""

test_nf="Simple_Forwarder"
echo "Starting Test for Simple Forwarder in ${mode}."
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Simple Forwarder in ${mode} Ends! enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Simple Forwarder Ended!!!"
echo "Reset ONVM_MGR, setup for MONITOR and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""

test_nf="Monitor"
echo "Starting Test for Monitor in ${mode}:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Monitor Ended!. Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Simple Monitor Ended!!!"
echo "Reset ONVM_MGR, setup for VLAN_TAGGER and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""

test_nf="QoS"
echo "Starting Test for QoS(VlanTag) in $mode:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Qos in ${mode} Ended!. Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for QoS(VlanTag) Ended!!!"
echo "Reset ONVM_MGR, setup for Load Balancer and press Enter to continue!"
read varname
echo "Key: $varname"
echo ""

test_nf="Load Balancer"
echo "Starting Test for Load Balancer in $mode:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for LB in $mode Ended!. Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Load Balancer Ended!!!"
echo "Reset ONVM_MGR settings; service chain settings in services.txt to setup Chain 1 (QoS_c->Mon)!"
read varname
echo "Key: $varname"
echo ""

test_nf="Chain1"
echo "Starting Test for Chain1:(QoS->Mon) in $mode:"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Chain1(QoS->Mon) Ended!. Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain1(Qos_c->Mon) Ended!!!"
echo " Test for $mode Ended!! \n Reset ONVM_MGR settings; service chain settings in services.txt and setup Chain2 (Qos_c->Mon_c->LB)!"
read varname
echo "Key: $varname"
echo ""


test_nf="Chain2a"
echo "Starting Test for Chain1:(QoS->Mon->LB):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Chain2a(Qos_c->Mon_c->LB) Ended!, Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain2a (QoS_c->Mon_c->LB) Ended!!!"
echo "Test for $mode Ended!! \n Reset ONVM_MGR settings; Reset ONVM_SETTINGS; and setup Chain2b (QoS_C->Mon_c->SF1)!"
read varname
echo "Key: $varname"
echo ""

test_nf="Chain2b"
echo "Starting Test for Chain1:(QoS->Mon->SF):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Chain2(Qos_c->Mon_c->SF) Ended!, Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain2 (QoS_c->Mon_c->SF) Ended!!!"
echo "Test for $mode Ended!! \n Reset ONVM_MGR settings; Reset ONVM_SETTINGS; and setup Chain3 (QoS_C->Mon_c->SF1->SF2->SF3)!"
read varname
echo "Key: $varname"
echo ""


test_nf="Chain3"
echo "Starting Test for Chain1:(QoS->Mon->SF1->SF2->SF3):"
$stime; timeout $t_sec ./lmoon1.sh ; sleep 2; $etime
echo "Test for Chain2(Qos_c->Mon_c->LB) Ended!, Enter 1"
read varname
echo "$test_nf: <start> Histogram Data </start>:"
cat histogram.csv
echo "<end> Histogram Data </end>:"
post_process_data $test_nf
echo "Test for Chain2 (QoS_c->Mon_c->LB) Ended!!!"
echo "Test for $mode Ended!! \n Reset ONVM_MGR settings; Reset ONVM_SETTINGS; service chain settings in services.txt RECOMPILE AND LAUNCH NEW TESTS!"
read varname
echo "Key: $varname"
echo ""
scp -r $base_dir root@flashstack-3:/home/skulk901/dev/my_fork/nfv_resiliency_work/res_results/${res_dir}/${mode}/
#scp -r $base_dir root@flashstack-3:/home/skulk901/dev/my_fork/nfv_resiliency_work/res_results/${res_dir}/${mode}/
