import time 
import numpy as np
import tqdm
import os 
import subprocess
import pandas as pd 
from io import StringIO
import io

import pickle

columns = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
       'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
       'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min', 'Label']


columns_to_drop =['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol','Timestamp' ]



def process_data(df):
    def f1(x):
        if x == 'Infinity':
            return 1
        else:
            return 0
        
        
    def f(x):
        if x == 'BENIGN':
            return 0
        else:
            return 1

    df['Label'] = df['Label'].apply(f)
    
    df['isInfFB'] = df['Flow Bytes/s'].apply(f)

    df['isInfFP'] = df['Flow Packets/s'].apply(f)

    m = 10000#pd.to_numeric(df.loc[df['Flow Bytes/s'] != "Infinity", 'Flow Bytes/s']).max()
    df['Flow Bytes/s'].replace("Infinity",m,inplace=True)

#     m = pd.to_numeric(df.loc[df['Flow Packets/s'] != "Infinity", 'Flow Packets/s']).max()
    df['Flow Packets/s'].replace("Infinity",m,inplace=True)

    df['Flow Bytes/s'] = pd.to_numeric(df['Flow Bytes/s'])
    df['Flow Packets/s'] = pd.to_numeric(df['Flow Packets/s'])
    
    return df.dropna()




# now you can save it to a file
with open('model.pkl', 'rb') as f:
    model  = pickle.load(f)


with open('detector.pkl', 'rb') as f:
    detector  = pickle.load(f)



# df = pd.read_csv('./output_folder/capture-output.pcap_Flow.csv')	
import time
from optparse import OptionParser

SLEEP_INTERVAL = 1.0

def readlines_then_tail(fin):
    "Iterate through lines and then tail for further lines."
    while True:
        line = fin.readline()
        if line:
            yield line
        else:
            tail(fin)

def tail(fin):
    "Listen for new lines added to file."
    while True:
        where = fin.tell()
        line = fin.readline()
        if not line:
            time.sleep(SLEEP_INTERVAL)
            fin.seek(where)
        else:
            yield line
            
def main():
    with open('./output_folder/capture-output.pcap_Flow.csv', 'r') as fin:
        for line in readlines_then_tail(fin):
            print (line.strip())


i=0

while True:

    try:
        

        
        df= pd.read_csv('./output_folder/capture-output.pcap_Flow.csv')
        print(df.columns)
        
        i=i+1
        print(i)
        

        # chunk.drop(columns_to_drop,axis=1,inplace=True)
        # print(chunk)
        # chunk.columns = columns
        # chunk = process_data(chunk)

        # #     print(chunk.columns)
        # new_chunk = chunk.copy()

        # new_chunk['anomality'] = detector.decision_function(chunk.drop(['Label'],axis=1))


        # result = model.predict(new_chunk.drop(['Label'],axis=1))
        
        
        # if result == 1:
        #     print(new_chunk['Destination Port'])
        #     print('DETECTED',datetime.datetime.now())
        
        
    except Exception as e:
        # print(e)
        print('\rwaiting for new connections',end='')
        pass
















