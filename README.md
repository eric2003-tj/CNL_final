# CNL_final

## Installation
1. Python packages
```
pip3 install -r requirements.txt
```
2. Necessary Packages
```
# example -- arch linux:
sudo pacman -S tcpdump iptables
# sudo is also needed if it isn't installed
```

## Workflow

### Training
Traing steps are provided here, although:
* `.csv` files we used to train model is not provided
* Trained models `isolation_forest_model.joblib` and `feature_scalor.joblib` are provided

1. Catch Packets for Training Dataset
Store your `.pcap` files in `./new_dataset/`
```
# example -- specific amount:
sudo tcpdump -i en0 -c 20000 -w ./new_dataset/traffic_data0.pcap

# example -- specific time(300sec):
sudo tcpdump -i en0 -G 300 -w ./new_dataset/traffic_data0.pcap
```

2. Basic Properties Extraction
Run `./rum_with_ip_time.py` to convert pcap files to `.csv` files.
```
python3 run_with_ip_time.py
```

3. Feature Transforming
Translate original `.csv` files to new ones including new features we need with `./data_traslation.py`.
```
python3 data_traslation.py
```

4. Training
Run `train.py` to train model.
```
python3 train.py
```

### Application Booting
We integrated all `.py` scripts into one `main.py`. This script will:
1. Call `new_app.py` to boot simple frontend interface
2. Execute `monitor_and_block_with_auto_unblock.py` to start monitoring generation of new `.pcap` files
3. Starting the main loop of continuous `tcpdump`

#### For Differences Between Systems
Since we used `subprocess` of python to run scripts in background, correct absolute path of `tcpdump` and `iptables` are needed. You can run the commands below to find them out:
```
which tcpdump # For tcpdump
which iptables # For iptables
```
Then you should modify the `PATH` variables in the scripts.
```
# main.py
TCPDUMP_PATH = "/usr/bin/tcpdump"
```
```
# new_app.py
IPTABLES_PATH = "/usr/sbin/iptables"
```

#### Simple execution
Just execute
```
python3 main.py
```
You might encounter permisssion issue that ask for `sudo` when running. You can either just type the password, or modify `/etc/sudoers` file with the paths you obatained in `For Differences Between Systems` to grant yourself no-password authorization


