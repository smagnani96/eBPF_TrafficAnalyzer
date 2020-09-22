#! /bin/bash
set -x
set -e

dynmon_ddos="monitor_ddos"
dynmon_crypto="monitor_crypto"
firewall="fw"

read container_id x<<<$(docker container ls | grep s41m0n/polycube:toshi)
if [ -z $container_id ]
then
	exit 0
fi

echo "Found Polycube daemon running"
	
docker container kill $container_id

#echo "Destroying Dynmon for DDos detection"
#curl -X DELETE http://localhost:9000/polycube/v1/dynmon/$dynmon_ddos
#echo "Destroying Dynmon for Crypto detection"
#curl -X DELETE http://localhost:9000/polycube/v1/dynmon/$dynmon_crypto
#echo "Destroying Firewall instance"
#curl -X DELETE http://localhost:9000/polycube/v1/firewall/$firewall
echo "Your environment is clean :)"
