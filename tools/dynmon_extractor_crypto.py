#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, ipaddress, errno, sys
from datetime import datetime
from collections.abc import Sequence

VERSION = '1.1'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 10
INTERVAL = 2 # seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01

polycubed_endpoint = 'http://{}:{}/polycube/v1'
counter = 0

def main():
	global polycubed_endpoint

	args = parseArguments()

	addr = args['address']
	port = args['port']
	cube_name = args['cube_name']
	interval = args['interval']
	debug = args['debug']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)
	
	print("Timestamp, IP Client, IP Server, Port Client, Port Server, Protocol, Server Method, Packets_ server, Packets_"
		"client, Bits_ server, Bits_ client, Duration, Packets_ server /Seconds,Packets_ client /Seconds, Bits_ server"
		"Seconds, Bits_client /Seconds, Bits _server / Packets _server, Bits _client / Packets _client, Packets_server"
		"Packets_client, Bits_server /Bits_client")

	dynmonConsume(cube_name, interval, interval*1000000000, debug)


def dynmonConsume(cube_name, interval, interval_ns, debug):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	# TODO: the timestampt works if executed on the same machine,
	curr_time = time.perf_counter_ns()
	start_time = time.time()
	metric =  getMetric(cube_name)
	req_time = time.time()
	
	threading.Timer(interval, dynmonConsume, (cube_name, interval, interval_ns, debug)).start()

	if not metric:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)') if debug else None
		return

	parseAndStore(metric, interval_ns, curr_time, my_count)
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)') if debug else None


def parseAndStore(metric, interval, curr_time, my_count):
	for entry in metric:
		key = entry['key']
		value = entry['value']
		
		if value['alive_timestamp'] < curr_time - interval:
			continue

		print(entry)
		print(curr_time)
		exit()
		if value['server_ip'] == key['saddr']:
			connIdentifier = (
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.ntohs(key['dport']),
				socket.ntohs(key['sport']),
				'TCP' if key['proto'] == 6 else 'UDP')
		else:
			connIdentifier = (
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.ntohs(key['sport']),
				socket.ntohs(key['dport']),
				'TCP' if key['proto'] == 6 else 'UDP')
		n_packets_client = value['n_packets_client']
		n_packets_server = value['n_packets_server']
		n_bits_server = value['n_bits_server']
		n_bits_client = value['n_bits_client']
		duration = value['alive_timestamp'] - value['start_timestamp']
		print(f"{time.time()}, {', '.join(map(str, connIdentifier))}, {value['method']}, {n_packets_server}, {n_packets_client}, "
			f"{n_bits_server}, {n_bits_client}, {duration}, {makeDivision(n_packets_server,duration)}, {makeDivision(n_packets_client,duration)}, "
			f"{makeDivision(n_bits_server,duration)}, {makeDivision(n_bits_client,duration)}, {makeDivision(n_bits_server,n_packets_server)}, "
			f"{makeDivision(n_bits_client,n_packets_client)}, {makeDivision(n_packets_server,n_packets_client)}, {makeDivision(n_bits_server,n_bits_client)}")
		sys.stdout.flush()


def makeDivision(i, j):
	return i / j if j else 0


def getMetric(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/ingress-metrics/SESSIONS_TRACKED_CRYPTO/value', timeout=REQUESTS_TIMEOUT)
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
	parser.add_argument('-d', '--debug', help='set the debug mode', action='store_true')
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()