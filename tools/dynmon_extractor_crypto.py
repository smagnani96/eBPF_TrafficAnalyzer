#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, ipaddress, errno
from datetime import datetime
from collections.abc import Sequence

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 10
OUTPUT_DIR = 'dump_crypto'
INTERVAL = 2 # seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01

polycubed_endpoint = 'http://{}:{}/polycube/v1'
counter = 0

def main():
	global polycubed_endpoint

	args = parseArguments()

	addr = args['address']
	port = args['port']
	cube_name = args['cube_name']
	output_dir = args['output']
	interval = args['interval']
	debug = args['debug']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfServiceExists(cube_name)
	checkIfOutputDirExists(output_dir)
	
	dynmonConsume(cube_name, output_dir, interval, debug)


def dynmonConsume(cube_name, output_dir, interval, debug):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	start_time = time.time()
	res =  getMetrics(cube_name)
	req_time = time.time()
	
	threading.Timer(interval, dynmonConsume, (cube_name, output_dir, interval, debug)).start()

	ingress = res['ingress-metrics'][0]['value'] if res['ingress-metrics'][0]['value'] is not None else []
	egress = res['egress-metrics'][0]['value'] if res['egress-metrics'][0]['value'] is not None else []

	if not ingress and not egress:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
		return

	data = {}
	parseIngress(ingress, data)
	parseEgress(egress, data)
	dumpData(data, output_dir, my_count, debug)
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')


def dumpData(data, output_dir, counter, debug):
	if debug: 
		file = open(f"{output_dir}/result_{counter}.csv", 'w')
		file.write("Timestamp, IP Client, IP Server, Port Client, Port Server, Protocol, Server Method, Packets_ server, Packets_"
			"client, Bits_ server, Bits_ client, Duration, Packets_ server /Seconds,Packets_ client /Seconds, Bits_ server"
			"Seconds, Bits_client /Seconds, Bits _server / Packets _server, Bits _client / Packets _client, Packets_server"
			"Packets_client, Bits_server /Bits_client\n")
		for key, value in data.items():
			n_packets_client = value['n_packets_client']
			n_packets_server = value['n_packets_server']
			n_bits_server = value['n_bits_server']
			n_bits_client = value['n_bits_client']
			duration = value['duration']
			print(key)
			file.write(f"{time.time()}, {', '.join(map(str, key))}, 1, {n_packets_server}, {n_packets_client}, "
				f"{n_bits_server}, {n_bits_client}, {duration}, {makeDivision(n_packets_server,duration)}, {makeDivision(n_packets_client,duration)}, "
				f"{makeDivision(n_bits_server,duration)}, {makeDivision(n_bits_client,duration)}, {makeDivision(n_bits_server,n_packets_server)}, "
				f"{makeDivision(n_bits_client,n_packets_client)}, {makeDivision(n_packets_server,n_packets_client)}, {makeDivision(n_bits_server,n_bits_client)}\n")
		file.close()	
	else:
		parsed = []
		for key, value in data.items():
			parsed.append({"id": key, "features": value})
		with open(f'{output_dir}/result_{counter}.json', 'w') as fp:
			json.dump(parsed, fp, indent=2)

def parseEgress(entries, conn):
	for entry in entries:
		key = entry['key']
		value = entry['value']
		connIdentifier = (
			socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
			socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
			socket.ntohs(key['dport']),
			socket.ntohs(key['sport']),
			key['proto'])
		if connIdentifier in conn:
			conn[connIdentifier]["n_packets_server"] = value['n_packets']
			conn[connIdentifier]["n_bits_server"] = value['n_bits']
		else:
			conn[connIdentifier] = {
				"n_packets_server": value['n_packets'],
				"n_bits_server": value['n_bits']}


def parseIngress(entries, conn):
	for entry in entries:
		key = entry['key']
		value = entry['value']
		connIdentifier = (
			socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
			socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
			socket.ntohs(key['sport']),
			socket.ntohs(key['dport']),
			key['proto'])
		if connIdentifier in conn:
			conn[connIdentifier]["n_packets_client"] = value['n_packets']
			conn[connIdentifier]["n_bits_client"] = value['n_bits']
			conn[connIdentifier]["duration"] = value['alive_timestamp'] - value['start_timestamp']
		else:
			conn[connIdentifier] = {
				"n_packets_client": value['n_packets'],
				"n_bits_client": value['n_bits'],
				"duration": value['alive_timestamp'] - value['start_timestamp']}


def makeDivision(i, j):
	return i / j if j else 0


def checkIfOutputDirExists(output_dir):
	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")


def checkIfServiceExists(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}', timeout=REQUESTS_TIMEOUT)
		response.raise_for_status()
	except requests.exceptions.HTTPError:
		print('Error: the desired cube does not exist.')
		exit(1)
	except requests.exceptions.ConnectionError:
		print('Connection error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.Timeout:
		print('Timeout error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.RequestException:
		print('Error: unable to connect to polycube daemon.')
		exit(1)


def getMetrics(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics', timeout=REQUESTS_TIMEOUT)
		if response.status_code == 500:
			print(response.content)
			exit(1)
		response.raise_for_status()
		return json.loads(response.content)
	except requests.exceptions.HTTPError:
		return False, None
	except requests.exceptions.ConnectionError:
		print('Connection error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.Timeout:
		print('Timeout error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.RequestException:
		print('Error: unable to connect to polycube daemon.')
		exit(1) 


def parseArguments():
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
	parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
	parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
	parser.add_argument('-o', '--output', help='set the output directory', type=str, default=OUTPUT_DIR)
	parser.add_argument('-d', '--debug', help='set the debug mode, to print also single packets file in the directory as .csv', action='store_true')
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()