import time 
import numpy as np
import tqdm
import os 
import subprocess







import datetime


now = datetime.datetime.now()
subprocess.Popen('./ares runserver -h 0.0.0.0 -p 8080 --threaded &')

subprocess.Popen('./ares runserver -h 0.0.0.0 -p 8080 --threaded &')


# try:
#     while True:
        
# except KeyboardInterrupt:
#     pass

# if [ -t 0 ]; then stty -echo -icanon -icrnl time 0 min 0; fi

# count=0
# keypress=''

# while [ "x$keypress" = "x" ]; do
#   let count+=1
#   echo -ne $count'\r'
#   ./cfm ~/diploma/input_folder ~/diploma/output_folder
#   keypress="`cat -v`"
# done

# if [ -t 0 ]; then stty sane; fi

# echo "You pressed '$keypress' after $count loop iterations"
# echo "Thanks for using this script."
# exit 0
# output, error = subprocess.Popen(['ls','-l']).communicate()

print('Attack started in {}'.format(str(now)))



