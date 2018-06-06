if [ -z $1 ] 
then
  nd_rate=100
else
  nd_rate=$1
fi 
./og.sh 8 1 ${nd_rate} 1
