#! /bin/bash
set -x
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# include helper.bash file: used to provide some common function across testing scripts
source "helpers.bash"

trap cleanup EXIT

create_veth 2

#polycubectl simplebridge add br1
curl -d '' -H  "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1

#polycubectl simplebridge br1 ports add port1 peer=veth1
curl -d '{"peer": "veth1"}' -H "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1/ports/port1

#polycubectl simplebridge br1 ports add port2 peer=veth2
curl -d '{"peer": "veth2"}' -H "Content-Type: application/json" http://localhost:9000/polycube/v1/simplebridge/br1/ports/port2

sleep 2
../tools/dynmon_injector.py monitor br1:port1 "../src/crypto_mining/feature_extractor.json"
sleep 2

sudo ip netns exec ns2 iperf3 -s &>/dev/null &
sleep 1

sudo ip netns exec ns1 iperf3 -c 10.0.0.2 -i 1 -t 60
