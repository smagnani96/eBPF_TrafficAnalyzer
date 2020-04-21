# eBPF_TrafficAnalyzer

Simple eBPF C program to analyze some packets' feature in order to detect (and possibly prevent) a possible ongoing network attack.

Highly recommended to be used within the [Polycube](https://github.com/polycube-network/polycube) framework.

## How it works

This section covers the main feature of this project, the [feature\_extractor.c](./src/feature_extractor.c) program.

Two parameters are vital:

* *N_SESSION*, the number of max TCP session tracked
* *N_PACKET_PER_SESSION*, the number of packet from the same TCP session
* *N_PACKET_TOTAL*, the number of max packet captured (Size of PACKET_BUFFER)
* *SESSION_ACCEPT_RESTART_TIME*, seconds to wait before accepting new sessions
* *SESSION_PACKET_RESTART_TIME*, seconds to wait before restarting to track packets from an already tracked session
* *BUFFER_PACKET_RESTART_TIME*, seconds to wait before resetting the buffer (5 seconds)

The current filtered protocols are:

* TCP
* UDP
* ICMP

When booted of course the program does not have any information about which packet has to be captured or not (if belonging to a TCP session), so it will consider all passing packet if there is enough space.

Every packet belonging to a current tracked TCP session or to one of the other considered protocols is analyzed, and some information are stored in the metric map to be consulted later on.

When there is not enough space left for more packet to be stored, the program ignores the following packets for *BUFFER_PACKET_RESTART_TIME* nanoseconds.

Once *BUFFER_PACKET_RESTART_TIME* nanoseconds are passed, the program resets the head of the circular buffer to start gathering new packets' info. 

A recent feature consists in setting the maximum amount of packet belonging to the same session captured. Once that the maximum is reached, I start checking if that connection is still active (other packets are arriving) for the following *SESSION_PACKET_RESTART_TIME* seconds, and then the session will be automatically tracked again. This is to allow me to intercept packets belonging to many flows, avoiding to overlook other important ones.

In case a new session arrives but already *N_SESSION* are being tracked, if *SESSION_ACCEPT_RESTART_TIME* nanoseconds since the last accepted session have passed, this new connection is taken into account, replacing the oldest one.

Concerning the tracked sessions, I have used an LRU map thanks to when a new session should be inserted but there is not enough space, the oldest one (the one less accessed) is discarded. Thanks to this data structure, I do not have to worry about memory leaks or flushing the table.

## Infrastructure Architecture

Thanks to the [Dynmon](https://polycube-network.readthedocs.io/en/latest/services/pcn-dynmon/dynmon.html) service recently integrated in the framework, users
are able to inject dynamically new eBPB code to be inserted in the Data Plane. This code is managed by a Monitor, which needs to be created and attached to a network interface.

Using the [dymon\_injector.py](./tools/dynmon_injector.py) script (src. [here](https://github.com/polycube-network/polycube/blob/master/src/services/pcn-dynmon/tools/dynmon_injector.py>)) a user inject the new code into the probe. From that moment on, by querying the correct monitor the user can retrieve all the informations
it has gathered. But what information? Those we tell the probe to gather. In fact in the [feature_extractor.json](./src/feature_extractor.json) file users not only insert their own code, but they also specify which metrics should be exported by the service.

The injectable code should be formatted and escaped accordingly to JSON format. To achieved that, an apposite python [formatter.py](./tools/formatter.py) script has been created.

To extract the metrics from the monitor, there are multiple options, but the two most relevant are the following:

* querying the polycube daemon via command line interface (`polycubectl <monitor_name> show metrics`);
* using the python [dynmon\_extractor.py](./tools/dynmon_extractor.py), which will automatically stores all the information in files.

## Usage

Let's analyze step by step every operation needed to make the system work. If you are not willing to write new code, please go to Step2 and use my [feature\_extractor\_all.c](./src/feature_extractor_all.c) example.

No need to tell that if you are going to use this project with Polycube, a running `polycubed` daemon is needed to accomplish every interaction.

### Step1 - Writing eBPF C code

In order to be run in kernel, eBPF C code must with compliant with some standard. In the Pointers section you will find some useful links to start with.

In the code, you can use all data structures eBPF offers you. Later you can decide which of these data you want to export.

### Step2 - Format code

Once finished your program, you should escape it to be inserted inside the [feature\_extractor.json](./src/feature_extractor.json) file under the `"code"` field. 
Moreover, you should also specify in this file all the metrics (also OpenMetrics is supported) to be exported between the service and the outside world.

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

Although, we have though of a [dynmon_extractor.py](./tools/dynmon\_extractor.py) script to retrieve results and to store them in a directory (default `./dump`). The file `result.json` will contain the dump of the retrieved data. 

In case you want to inspect packet per packet, by adding `--debug` the scripts will print each packet in different files identified by `srcIp-srcPort___dstIp-dstPort__timestamp.csv`.

## Test

Under the [test](./test) directory there are all the used script and configuration file to perform an iPerf3 test.

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

If we try to parallelize multiple connection (`-P 10` for in the client command for example), we achieve a total **46.5 Gbits/sec** speed (all the parallel connections are launched in the same computer using the same resources so the performance worsening is reasonable). 

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

## Pointers

<https://www.freeformatter.com/json-escape.html>

<https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md>

<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=29ba732acbeece1e34c68483d1ec1f3720fa1bb3>

<https://support.cumulusnetworks.com/hc/en-us/articles/216509388-Throughput-Testing-and-Troubleshooting>

<https://iris.polito.it/retrieve/handle/11583/2712562/207457/18HPSR-ebpf-lessons-learned.pdf>