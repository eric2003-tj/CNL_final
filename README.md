# CNL_final

## Packet extracting

```
# example:
sudo tcpdump -i en0 -c 200000 -w ./new_dataset/pcap/unprocessed/traffic_data3.pcap
```
## Workflow
1. (Ignore) Store your pcap file in new_dataset/pcap/unprocessed.
2. Run rum_with_ip_time to convert pcap files to csv files.
3. Move processed pcap files to processed
4. Run train.py/train_model.ipynb.


## boot backend
```
python3 monitor_and_block_with_auto_unblock.py
sudo python3 new_app.py
```

