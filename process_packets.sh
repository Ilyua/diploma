#!/bin/bash



# import time 
# import numpy as np
# import tqdm
# import os 
# import subprocess


# print('### Starting custom module ###')


# print('Starting packets processing')

# command_tshark = ['tshark ','-i','enp0s3','-w','./input_folder/capture-output.pcap']
# output, error = subprocess.Popen(command_tshark).communicate()



# while True:
# 	command_flowmeter = ['/home/ilyua/cicflowmeter-4/CICFlowMeter-4.0/bin', 'input_folder', 'output_folder']
# 	output, error = subprocess.Popen(command_flowmeter).communicate()

# while [ 1 = 1 ]
# do
# ./cfm ~/diploma/input_folder ~/diploma/output_folder
# done






if [ -t 0 ]; then stty -echo -icanon -icrnl time 0 min 0; fi


echo 'Starting packet processing, wait'
sleep 5
cd /home/ilyua/cicflowmeter-4/CICFlowMeter-4.0/bin/

count=0
keypress=''
while [ "x$keypress" = "x" ]; do
  let count+=1
  echo -ne $count'\r'
  sleep 5
  ./cfm ~/diploma/input_folder ~/dipl oma/output_folder
  keypress="`cat -v`"
done

if [ -t 0 ]; then stty sane; fi

echo "You pressed '$keypress' after $count loop iterations"
echo "Thanks for using this script."
exit 0


