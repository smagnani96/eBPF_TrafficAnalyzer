#! /bin/bash
set -x
set -e

interface="wlp59s0"
firewall="fw"
dynmon_ddos="monitor_ddos"
dynmon_crypto="monitor_crypto"

path_ddos_config="../src/ddos_detection/feature_extractor.json"
path_crypto_config="../src/crypto_mining/feature_extractor.json"

ret=$(docker container ls | grep s41m0n/polycube)
if [ $? -eq 0 ]
then
	echo "Found Polycube daemon running"
else
	echo "Running Polycube daemon at http://localhost:9000"
	docker run -p 9000:9000 -d --rm --privileged --network host \
		-v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro \
		-it s41m0n/polycube /bin/bash -c 'polycubed'
	sleep 1
fi

echo "Creating Dynmon for DDos detection"
./dynmon_injector.py $dynmon_ddos $interface $path_ddos_config

echo "Creating Dynmon for Crypto detection"
./dynmon_injector.py $dynmon_crypto $interface $path_crypto_config

echo "Creating Firewall instance"
./firewall_injector.py $firewall $interface

echo "Your environment is ready to be used :)"
