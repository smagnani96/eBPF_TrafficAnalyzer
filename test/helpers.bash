#!/usr/bin/env bash

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
    #polycubectl simplebridge del br1
    curl -X DELETE http://localhost:9000/polycube/v1/simplebridge/br1
  	#polycubectl monitor del
    curl -X DELETE http://localhost:9000/polycube/v1/dynmon/monitor

  	delete_veth 2
    sudo pkill iperf3
}
