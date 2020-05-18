#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, ipaddress, errno
from datetime import datetime
from collections.abc import Sequence

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 5
OUTPUT_DIR = 'dump_crypto'
SESSIONS_MAP_NAME = "SESSIONS_TRACKED"
INTERVAL = 10 

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
	sessions_map_name = args['sessions_map_name']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfServiceExists(cube_name)
	checkIfOutputDirExists(output_dir)
	
	dynmonConsume(cube_name, sessions_map_name, output_dir, interval)


def dynmonConsume(cube_name, sessions_map_name, output_dir, interval):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	threading.Timer(interval, dynmonConsume, (cube_name, sessions_map_name, output_dir, interval)).start()
	start_time = time.time()
	values = getMetric(cube_name, sessions_map_name)
	if values is None:
		return
	elif isinstance(values, Sequence):
		for entry in values:
			parseEntry(entry, parsed_entries)
	else :
		parseEntry(values, parsed_entries)
	with open(f'{output_dir}/result_{my_count}.json', 'w') as fp:
		json.dump(parsed_entries, fp, indent=2)
	print(f'Got something! Execution n°{my_count} time {time.time() - start_time}')


def parseEntry(entry, parsed_entries):
	#TODO HERE
	key = entry['key']
	value = entry['value']
	saddr = socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little"))
	daddr = socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little"))
	sport = int.from_bytes(int(key['sport']).to_bytes(2, "little"), "little")
	dport = int.from_bytes(int(key['dport']).to_bytes(2, "little"), "little")
	parsed_entries.append({
		"id": (saddr, daddr, sport, dport, key['proto']),
		"value": {
			"n_packets_server": value['n_packets_server'],
			"n_packets_client": value['n_packets_client'],
			"duration": int(value['alive_timestamp']) - int(value['start_timestamp'])
		}})
	

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


def getMetric(cube_name, metric_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/{metric_name}/value', timeout=REQUESTS_TIMEOUT)
		response.raise_for_status()
		return json.loads(json.loads(response.content))
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
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=int, default=INTERVAL)
	parser.add_argument('-sm', '--sessions_map_name', help='set the sessions map name (the same in the json file)', type=str, default=SESSIONS_MAP_NAME)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()