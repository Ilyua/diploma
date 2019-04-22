touch ./input_folder/capture-output.pcap
chmod ./input_folder/capture-output.pcap
tshark -i enp0s3 -w ./input_folder/capture-output.pcap 