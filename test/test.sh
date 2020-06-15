#! /bin/bash
set -x
set -e

test_file="../src/ddos_detection/feature_extractor.json"
n_connections=1

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
    #polycubectl simplebridge del br1
    curl -X DELETE http://localhost:9000/polycube/v1/simplebridge/br1
  	#polycubectl monitor del
    curl -X DELETE http://localhost:9000/polycube/v1/dynmon/monitor

  	delete_veth 2
    sudo pkill iperf3
}

function parse {
  while getopts "f:c:" opt; do
    case $opt in
      f) 
        test_file=$OPTARG
        ;;
      c)
        n_connections=$OPTARG
        ;;
    esac
  done
}
function main {
  
  parse $@
  
  trap cleanup EXIT

  create_veth 2

  #polycubectl simplebridge add br1
  curl -d '' -H  "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1

  #polycubectl simplebridge br1 ports add port1 peer=veth1
  curl -d '{"peer": "veth1"}' -H "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1/ports/port1

  #polycubectl simplebridge br1 ports add port2 peer=veth2
  curl -d '{"peer": "veth2"}' -H "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1/ports/port2

  sleep 2
  ../tools/dynmon_injector.py monitor br1:port1 $test_file
  sleep 2

  sudo ip netns exec ns2 iperf3 -s &>/dev/null &
  sleep 1

  sudo ip netns exec ns1 iperf3 -c 10.0.0.2 -i 1 -t 30 -P $n_connections
}

main $@