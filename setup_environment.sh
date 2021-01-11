#! /bin/bash
set -x

# Set online=1 in case the probe is directly involved in switching the packets (the interface receives both incoming and outgoing packets)
online=0
interface="wlp59s0"
firewall="fw"
dynmon_ddos="monitor_ddos"
dynmon_crypto="monitor_crypto"
path_ddos_config="./src/ddos_detection/dataplane.json"
path_crypto_config="./src/crypto_mining/dataplane.json"

ret=$(docker container ls | grep "s41m0n/polycube:toshi")
if [ $? -eq 0 ]
then
	echo "Found Polycube daemon running"
else
	echo "Running Polycube daemon at http://localhost:9000"
	docker run -p 9000:9000 -d --rm --privileged --network host \
		-v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro \
		-it s41m0n/polycube:toshi /bin/bash -c 'polycubed'
	sleep 8
fi



if [ $online -eq 1 ];
then
	online="both"
else
	online="ingress"
fi

echo "Creating Firewall instance"
./tools/firewall_injector.py $firewall $interface -d

echo "Creating Dynmon for DDos detection"
./tools/dynmon_injector.py $dynmon_ddos $interface $path_ddos_config -t $online -d

echo "Creating Dynmon for Crypto detection"
./tools/dynmon_injector.py $dynmon_crypto $interface $path_crypto_config -t $online -d

echo "Your environment is ready to be used :)"
