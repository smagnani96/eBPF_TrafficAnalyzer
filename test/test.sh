#! /bin/bash
set -x
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

function create_veth {
  for i in `seq 1 $1`;
  do
  	sudo ip netns add ns${i}
  	sudo ip link add veth${i}_ type veth peer name veth${i}
  	sudo ip link set veth${i}_ netns ns${i}
  	sudo ip netns exec ns${i} ip link set dev veth${i}_ up
  	sudo ip link set dev veth${i} up
  	sudo ip netns exec ns${i} ifconfig veth${i}_ 10.0.0.${i}/24
  done
}

function delete_veth {
  for i in `seq 1 $1`;
  do
  	sudo ip link del veth${i}
  	sudo ip netns del ns${i}
  done
}

function cleanup {
  	set +e
  	polycubectl simplebridge del br1
  	polycubectl monitor del
  	delete_veth 2
    sudo pkill iperf3
}

function main {
	
	trap cleanup EXIT

	create_veth 2

	polycubectl simplebridge add br1

	polycubectl simplebridge br1 ports add port1
	polycubectl simplebridge br1 ports add port2

	polycubectl connect br1:port1 veth1
	polycubectl connect br1:port2 veth2

	sleep 1
	../dynmon_injector.py monitor br1:port1 test.json
	sleep 1

	sudo ip netns exec ns2 iperf3 -s &
	sudo ip netns exec ns1 iperf3 -c 10.0.0.2 -i 1 -t 10 #-P 5
}

main $@