import time 
import numpy as np
import tqdm
import os 
import subprocess

print('### Starting Snort ###')

output, error = subprocess.Popen(['ls','-l']).communicate()

print('### Snort Succesfully started ###')