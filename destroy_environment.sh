#! /bin/bash
set -x
set -e

dynmon_ddos="monitor_ddos"
dynmon_crypto="monitor_crypto"

ret=$(docker container ls | grep s41m0n/polycube)
if [ $? -eq 0 ]
then
	echo "Found Polycube daemon running"
	read container_id x<<<$(docker container ls | grep portainer)
	docker container stop $container_id
fi

echo "Destroying Dynmon for DDos detection"
curl -X DELETE http://localhost:9000/polycube/v1/dynmon/$dynmon_ddos

echo "Destroying Dynmon for Crypto detection"
curl -X DELETE http://localhost:9000/polycube/v1/dynmon/$dynmon_crypto

echo "Destroying Firewall instance"
curl -X DELETE http://localhost:9000/polycube/v1/firewall/$firewall

echo "Your environment is clean :)"
