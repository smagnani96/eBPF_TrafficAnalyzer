# eBPF_TrafficAnalyzer

eBPF C programs to analyze some packets' feature in order to detect (and possibly prevent) a possible ongoing network attack.

Highly recommended to be used within the [Polycube](https://github.com/polycube-network/polycube) framework.

## DDos detection

This section covers the [ddos_detection/feature\_extractor.c](./src/ddos_detection/feature_extractor.c) program related to DDos detection.

The following parameters are vital:

#define SESSION_PACKET_RESTART_TIME 1000000000      // Seconds to wait before restarting to track packets from an already tracked session

* *N_SESSION*, the number of max TCP session tracked
* *N_PACKET_PER_SESSION*, the number of packet from the same TCP session
* *N_PACKET_TOTAL*, the number of max packet captured (size of PACKET_BUFFER, usually N_SESSION*N_PACKET_PER_SESSION)
* *SESSION_PACKET_RESTART_TIME*, seconds to wait before restarting to track packets from an already tracked session

The current filtered protocols are:

* TCP
* UDP
* ICMP

When booted of course the program does not have any information about which packet has to be captured or not (if belonging to a TCP session), so it will consider all passing packet if there is enough space.

Every packet belonging to a current tracked TCP session or to one of the other considered protocols is analyzed, and some information are stored in the metric map to be consulted later on.

Every session can store a limited amount of captured packets. Once that the maximum is reached, it starts checking if that connection is still active (other packets are arriving) for the following *SESSION_PACKET_RESTART_TIME* seconds, and then the session will be automatically tracked again. This is to allow me to intercept packets belonging to many flows, avoiding to overlook other important ones.

When a new untracked session is detected, it is automatically added to all the other tracked ones using an LRU policy. If the map containing the sessions is large enough, this would mean that the LRU session who will be replaced is very old. Thanks to this policy and data structure (LRU_HASH map), I do not have to worry about memory leaks or flushing the table.

These steps are performed both in the *INGRESS* and *EGRESS* data path, using alongside maps. Their content will later be read and unified using the [dynmon_extractor_ddos.py](./tools/dynmon_extractor_ddos.py) script.

The packets are stored in a Queue, meaning that they are automatically deleted when read (push/pop policy).

Reading the required features does not lock the map for the dataplane, which can continue monitoring incoming packets. This is thanks to an advance swap feature, which allow me to swap the required metric with a new appositely created one, letting the user completely unaware of what is going on.

## Crypto mining

This section covers the [crypto_mining/feature\_extractor.c](./src/crypto_mining/feature_extractor.c) program related to Crypto Mining detection.

The only parameter vital to the program is *N_SESSION*, which represents the max number of sessions tracked.

The current filtered protocols are:

* TCP
* UDP

When booted of course the program does not have any information about which packet has to be captured or not (if belonging to a TCP session), so it will consider all passing packet if there is enough space.

Every packet belonging to a current tracked TCP session or to one of the other considered protocols is analyzed, and some information are stored in the metric map to be consulted later on.

When the sessions map is full, the oldest entry is deleted, according to LRU policy which ensures that the oldest data is replaced when arriving new one.

For each session, the following parameters are stored both for *INGRESS* and *EGRESS* data path:

* *n_packets_server*
* *n_packets_client*
* *n_bits_server*
* *n_bits_client*
* *start_timestamp*: timestamp of the first passed packet
* *alive_timestamp*: timestamp of the last passed packet
* *method*: the method used to understand which is the server in the communication

The methods to heuristically find out which is the server are the following:

* if TCP communication and TCP->SYN detected, then the destination IP is the server 
* if destination port < 1024, then destination IP is the server
* otherwise choose randomly

## Infrastructure Architecture

Thanks to the [Dynmon](https://polycube-network.readthedocs.io/en/latest/services/pcn-dynmon/dynmon.html) service recently integrated in the framework, users
are able to inject dynamically new eBPB code to be inserted in the Data Plane. This code is managed by a Monitor, which needs to be created and attached to a network interface.

Using the [dymon\_injector.py](./tools/dynmon_injector.py) script a user inject the new code into the probe. From that moment on, by querying the correct monitor the user can retrieve all the informations it has gathered. But what information? Those we tell the probe to gather. In fact both in [ddos_detection/feature_extractor.json](./src/ddos_detection/feature_extractor.json)  and [crypto_mining/feature\_extractor.json](./src/crypto_mining/feature_extractor.json) files, users not only insert their own code, but they also specify which metrics should be exported by the service.

The injectable code should be formatted and escaped accordingly to JSON format. To achieved that, an apposite python [formatter.py](./tools/formatter.py) script has been created.

To extract the metrics from the monitor, I created apposite scripts which contact Polycube via REST APIs.
These scripts are:

* [dynmon\_extractor\_ddos.py](./tools/dynmon_extractor_ddos.py)
* [dynmon\_extractor\_ddos.py](./tools/dynmon_extractor_ddos.py)

I recently integrated in Dynmon two vital features for this project:

* the possibility to completely erase metric data when reading it
* the possibility to ensure atomic metric read thanks to an advanced swapping technique.

Thanks to these features, all our objectives can be achieved. When reading a metric, we don't want new values to be pushed into it, since it could lead to an infinite read-loop.
If specified (as in our configurations), when a program containing a metric with the *swap* feature on is injected, a new parallel map is created. The program points alternatively to the native/fake map, letting the Control Plane to read the previously filled on. Those operations are atomic: reads are performed sequentially to ensure that swapping the metric is possibile only when the previous client has finished reading it.

You can also tell Dynmon to erase the map after the read. Dynmon automatically understands the map type and, if supported, it delete all the entries. Deleting the entries means:

* for a key-value map => deleting all the key-value entry
* for an array map => zero-ing the value (if it is a user define data type like a struct, all the values are zero-ed).

## Infrastructure Setup 

### Polycube Requirements

* OS: Ubuntu >= 18.04 (20.04 works fine)
* Kernel: 5.7.0 (also 5.4.0-33-generic is good, but map extraction can be slower due to some features missing)
* Disk space: >= 2.5 GB + needed space for output files
* Memory: >= 100MB + X (where X is the size of the used BPF_MAP depending on parameters like: N°Sessions, N°Packets_per_session,...)

### OS installation

Download Ubuntu Focal Fossa from <https://releases.ubuntu.com/20.04/ubuntu-20.04-desktop-amd64.iso>.

Installing OS in a physical device or in a VirtualMachine is up to you and it does not make difference for Polycube.

### Kernel installation

If you have a fresh Ubuntu 20.04 installation and you want to keep the kernel v5.4.0 you should skip this session

Otherwise, to update to v.5.7.0 you can use the following commands:

```bash
wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v5.7/amd64/linux-headers-5.7.0-050700_5.7.0-050700.202006082127_all.deb
wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v5.7/amd64/linux-headers-5.7.0-050700-generic_5.7.0-050700.202006082127_amd64.deb
wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v5.7/amd64/linux-image-unsigned-5.7.0-050700-generic_5.7.0-050700.202006082127_amd64.deb
wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v5.7/amd64/linux-modules-5.7.0-050700-generic_5.7.0-050700.202006082127_amd64.deb

sudo dpkg -i *.deb
sudo reboot
```

If the new kernel is not automatically chosen during the next boot, you should enter grub menu and select the right one.

### Automatic environment setup

The script [setup_environment.sh](./setup_environment.sh) manages and launches every resource needed to setup:

* Polycube daemon in a docker
* The DDos monitor (named `monitor_ddos`)
* The Crypto monitor (named `monitor_crypto`)
* The Firewall (named `fw`) with the default `FORWARD` policy

The final architecture will be something like:

```bash
                                                               +-----------+   
                          +----+----------------+--------------+           |   
 ---|INTERNET|------------| fw | monitor_crypto | monitor_ddos | Interface |-----|User_Device|
                          +----+----------------+--------------+  wlp59s0  |   
                                                               +-----------+  
```

Otherwise, if you prefer to manually set it up with custom names you can continue to read the following section.


### Starting Polycube

Download my personal Polycube image with all the latest features needed.

```bash
docker pull s41m0n/polycube:latest
```

Despite having a Docker container, Polycube needs linux headers from the hosts to compile and inject at lower layers (XDP/TC).
Download `linux-headers` according to your kernel version.

```bash
sudo apt install linux-headers-$(uname -r)
```

Finally, Polycube can be now run using the following command:

```bash
docker run -p 9000:9000 --rm -it --privileged --network host \
-v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro \
s41m0n/polycube /bin/bash -c 'polycubed'
```

As you can see, the port 9000 has been forwarded to the Docker where the Polycube server is listening through a REST API.
This way, other programs in your system can interact with Polycube using `http://localhost:9000/polycube/v1/.....`.

If you prefer to use the Docker assigned IP (172.17.0.\*), remove the port binding.

The running container is still attached to the command line where you launched it, to let the user see all the debug messages from Polycube (useful when dynamically injecting eBPF code and you are not 100% it will compile).

Test connectivity with Polycube:

```bash
curl localhost:9000/polycube/v1
```

### Loading program (DDos/Crypto)

The following scripts create a Dynmon instance with the specified configuration attached to the network interface `wlp59s0` (change it to yours).

It automatically contacts Polycube at `localhost:9000` which, if you followed the previous sections, should be forwaded to the docker container where Polycube is actually running.

#### DDos

```bash
./dynmon_injector.py monitor wlp59s0  ../src/ddos_detection/feature_extractor.json
```

### Crypto

```bash
./dynmon_injector.py monitor wlp59s0  ../src/crypto_mining/feature_extractor.json
```

### Extracting data (DDos/Crypto)

The following scripts extract data from the Dynmon `monitor` instance previously created and generate outputs under `dump_crypto` and `dump_ddos` directories. If you want a more specific debug-like output, insert `--debug`.

It automatically contacts Polycube at `localhost:9000` which, if you followed the previous sections, should be forwaded to the docker container where Polycube is actually running.

For more accepted parameters (like interval between 2 read operation), type `--help`.

### DDos

```bash
./dynmon_extractor_ddos.py monitor
```

### Crypto

```bash
./dynmon_extractor_crypto.py monitor
```

## General Usage

Let's analyze step by step every operation needed to make the system work. If you are not willing to write new code, please go to Step2 and use my [ddos_detection](./src/ddos_detection/feature_extractor.c) or [crypto_mining](./src/crypto_mining/feature_extractor.c) example.

No need to tell that if you are going to use this project with Polycube, a running `polycubed` daemon is needed to accomplish every interaction.

### Step1 - Writing eBPF C code

In order to be run in kernel, eBPF C code must with compliant with some standard. In the Pointers section you will find some useful links to start with.

In the code, you can use all data structures eBPF offers you. Later you can decide which of these data you want to export.

### Step2 - Format code

Once finished your program, you should escape it to be inserted inside one of [ddos_detection/feature\_extractor.json](./src/ddos_detection/feature_extractor.json) or [crypto_mining/feature\_extractor.json](./src/crypto_mining/feature\_extractor.json) file under the `"code"` field. 
Moreover, you should also specify in this file all the metrics (also OpenMetrics is supported) to be exported between the service and the outside world and their configurations.

All the metrics `map_name` should refer to existing map you have previously declared in your eBPF C code, otherwise it will not be found.

To format the file, you can use my [formatter.py](./tools/formatter.py) script:

```bash
~$  ./formatter.py <your_code_filename.c>
```

### Step3 - Inject code

This step consists in inserting your code inside the service. To do that, you can use the [dynmon\_injector.py](./tools/dynmon_injector.py) script:

```bash
~$  ./dynmon_injector.py <monitor_name> <network_interface> <json_filename.json>
```

An example could be `./dynmon_injector.py monitor1 br1:port1 feature_extractor.json` where `br1:port1` are a Polycube Simplebridge and a port previously created and assigned, but it could be any value (also your computer `eth0` or `wlp59s0` interfaces).

### Step4 - Extract results

At this point if everything went well the service is already gathering informations ready to be consumed. You can type `polycubectl <monitor_name> show metrics`
to read results on a command line.

Although, I have though of two scripts to automatically and periodically retrieve data and to store them in an apposite directory using as default the `json` data format.
The scrips are: 

* [dynmon_extractor_ddos.py](./tools/dynmon\_extractor\_ddos.py) 
* [dynmon_extractor_crypto.py](./tools/dynmon\_extractor\_crypto.py) 

The default output type uses the JSON format, but you can obtains CSV files by adding `--debug` as parameter to the scripts in order to better inspect data (as required).

## Test

Under the [test](./test) directory there is the used script to perform an iPerf3 test.

The input parameters are the following:

* `-f <config_file>` the configuration file to be injected in the created Dynmon instance (the one to be tested, default [ddos_detection/feature_extractor.json](./src/ddos_detection/feature_extractor.json))
* `-c <n_connessions>` the number of parallel connections to be opened to the server (default 1 using the entire bandwidth)

Briefly, a Simplebridge service is created and two ports in two different network namespaces are assigned to it with the corresponding IP addressed:

* 10.0.0.1
* 10.0.0.2

While in a namespace there is an iPerf3 server waiting for incoming tcp connection, in the other there is our client ready to start the connection.

By testing it using 1 unique session we achieve the folliwing result of **53.4 Gbits/sec**.

```bash
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  6.50 GBytes  55.8 Gbits/sec    0    390 KBytes       
[  5]   1.00-2.00   sec  6.72 GBytes  57.7 Gbits/sec    0    390 KBytes       
[  5]   2.00-3.00   sec  6.72 GBytes  57.8 Gbits/sec    0    390 KBytes       
[  5]   3.00-4.00   sec  6.71 GBytes  57.6 Gbits/sec    0    390 KBytes       
[  5]   4.00-5.00   sec  6.73 GBytes  57.8 Gbits/sec    0    390 KBytes       
[  5]   5.00-6.00   sec  6.75 GBytes  58.0 Gbits/sec    0    390 KBytes       
[  5]   6.00-7.00   sec  6.73 GBytes  57.8 Gbits/sec    0    390 KBytes       
[  5]   7.00-8.00   sec  6.75 GBytes  58.0 Gbits/sec    0    390 KBytes       
[  5]   8.00-9.00   sec  6.77 GBytes  58.1 Gbits/sec    0    390 KBytes       
[  5]   9.00-10.00  sec  6.73 GBytes  57.8 Gbits/sec    0    390 KBytes       
[  5]  10.00-11.00  sec  6.73 GBytes  57.9 Gbits/sec    0    390 KBytes       
[  5]  11.00-12.00  sec  6.69 GBytes  57.4 Gbits/sec    0    390 KBytes       
[  5]  12.00-13.00  sec  6.75 GBytes  57.9 Gbits/sec    0    390 KBytes       
[  5]  13.00-14.00  sec  6.75 GBytes  58.0 Gbits/sec    0    390 KBytes       
[  5]  14.00-15.00  sec  6.75 GBytes  58.0 Gbits/sec    0    390 KBytes       
[  5]  15.00-16.00  sec  6.70 GBytes  57.5 Gbits/sec    0    390 KBytes       
[  5]  16.00-17.00  sec  6.74 GBytes  57.9 Gbits/sec    0    390 KBytes       
[  5]  17.00-18.00  sec  6.75 GBytes  58.0 Gbits/sec    0    390 KBytes       
[  5]  18.00-19.00  sec  6.68 GBytes  57.3 Gbits/sec    0    390 KBytes       
[  5]  19.00-20.00  sec  5.95 GBytes  51.1 Gbits/sec    0    587 KBytes       
[  5]  20.00-21.00  sec  5.25 GBytes  45.1 Gbits/sec    0    587 KBytes       
[  5]  21.00-22.00  sec  5.27 GBytes  45.2 Gbits/sec    0    587 KBytes       
[  5]  22.00-23.00  sec  5.34 GBytes  45.9 Gbits/sec    0    587 KBytes       
[  5]  23.00-24.00  sec  5.30 GBytes  45.5 Gbits/sec    0    587 KBytes       
[  5]  24.00-25.00  sec  5.28 GBytes  45.4 Gbits/sec    0    587 KBytes       
[  5]  25.00-26.00  sec  5.30 GBytes  45.5 Gbits/sec    0    587 KBytes       
[  5]  26.00-27.00  sec  5.30 GBytes  45.5 Gbits/sec    0    587 KBytes       
[  5]  27.00-28.00  sec  5.29 GBytes  45.4 Gbits/sec    0    587 KBytes       
[  5]  28.00-29.00  sec  5.30 GBytes  45.5 Gbits/sec    0    587 KBytes       
[  5]  29.00-30.00  sec  5.36 GBytes  46.0 Gbits/sec    0    587 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec   187 GBytes  53.4 Gbits/sec    0             sender
[  5]   0.00-30.00  sec   187 GBytes  53.4 Gbits/sec                  receiver

iperf Done.
```

If we try to parallelize multiple connection (`-c 10` for in the client command for example), we achieve a total **46.5 Gbits/sec** speed (all the parallel connections are launched in the same computer using the same resources so the performance worsening is reasonable). 

```bash
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[  5]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[  7]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[  7]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[  9]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[  9]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 11]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 11]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 13]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 13]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 15]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 15]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 17]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 17]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 19]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 19]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 21]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 21]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[ 23]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec    0             sender
[ 23]   0.00-30.00  sec  16.2 GBytes  4.65 Gbits/sec                  receiver
[SUM]   0.00-30.00  sec   162 GBytes  46.5 Gbits/sec    0             sender
[SUM]   0.00-30.00  sec   162 GBytes  46.5 Gbits/sec                  receiver

iperf Done.
```

The tests have also been run with parallel connections (5) and a small session table (only 10 entries) to see how the program reacts to continuous entries substitution. The results are in line with those described before.

## Pointers

<https://www.freeformatter.com/json-escape.html>

<https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md>

<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=29ba732acbeece1e34c68483d1ec1f3720fa1bb3>

<https://support.cumulusnetworks.com/hc/en-us/articles/216509388-Throughput-Testing-and-Troubleshooting>

<https://iris.polito.it/retrieve/handle/11583/2712562/207457/18HPSR-ebpf-lessons-learned.pdf>