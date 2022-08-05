# SDN Ryu Estimate Link loss by using Probe Packet algorithm (Ubuntu 20.04)

## Step 1: Build the Topology by using mininet and ryu:

- Run the commands below to start the mininet download:

    > $ sudo apt update

    > $ sudo apt-get install mininet

- Run the commands below to start the ryu download:
    - Install git first:
        > $ sudo apt update

        > $ sudo apt-get install git
    - Check git version:
        > $ git --version

    - Install pip:
        > $ sudo apt update

        > $ sudo apt install python3-pip
    - Install ryu:
        > $  git clone https://github.com/faucetsdn/ryu.git

        > $ cd ryu; pip install .

    - Install scappy:

        > $ git clone https://github.com/secdev/scapy.git
        
        > $ cd scapy

        > $ sudo python setup.py install
- After finishing the download, run the following command to build Topology ( first terminal):
  
    > $ sudo python Topo.py

- You can see the topology by using ryu GUI:
    - Open the second terminal:

        > $ cd ryu
        
        > $  PYTHONPATH=. ./bin/ryu run --observe-links ryu/app/gui_topology/gui_topology.py

    - Access http:// "ip address of ryu host":8080 with your web browser.

    - My topology should look like this ( you can build whatever topology you like):
  
## Step 2: Run the ryu-manager command to build Ryu controller:
-   Run the command below on the second terminal to build Ryu controller:
    
    >   sudo ryu-manager Link_loss.pu --observe-links 

## Step 3: Open xterm h1 and run scappy to build Probe Packet

- Come back to mininet terminal:
    > mininet> xterm h1

- On the h1 xterm:
    > sudo python probe_packet.py

- Go to the second terminal and wait a moment you will see the result like this:
    ![](https://github.com/TranAnh-Tuan/SDN-Ryu-Estimate-Link-loss-by-using-Probe-Packet-algorithm/blob/main/Link-loss/Result.png)
