#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, ipaddress, errno
from datetime import datetime
from collections.abc import Sequence

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 5
OUTPUT_DIR = 'dump_ddos'
CAPTURE_INFO_MAP_NAME = "CAPTURE_INFO"
PACKET_FEATURE_MAP_NAME = "PACKET_BUFFER"
INTERVAL = 10 # seconds, to have less just insert a decimal number like 0.01

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
	capture_map_name = args['capture_map_name']
	packet_feature_map_name = args['packet_feature_map_name']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfServiceExists(cube_name)
	checkIfOutputDirExists(output_dir)

	dynmonConsume(cube_name, capture_map_name, packet_feature_map_name, output_dir, interval, debug)


def dynmonConsume(cube_name, capture_map_name, packet_feature_map_name, output_dir, interval, debug):
	global counter
	parsed_entries = []
	entry_index = 0
	my_count = counter
	counter += 1
	threading.Timer(interval, dynmonConsume, (cube_name, capture_map_name, packet_feature_map_name, output_dir, interval, debug)).start()
	start_time = time.time()
	
	info_values = getMetric(cube_name, capture_map_name)
	packet_values =  getMetric(cube_name, packet_feature_map_name)

	entry_index = info_values[0]['next_index']

	if entry_index is None or entry_index == 0:
		print(f'Got nothing ... Execution n°{my_count} time {time.time() - start_time}')
		return

	parseAndStore(packet_values[:entry_index], output_dir, my_count) if debug is False else parseAndStoreDebug(packet_values[:entry_index], output_dir, my_count)	
	print(f'Got something! Execution n°{my_count} time {time.time() - start_time}')


def parseAndStore(entries, output_dir, counter):
	data = []
	flows = {}
	for entry in entries:
		saddr = socket.inet_ntoa(int(entry['srcIp']).to_bytes(4, "big"))
		daddr = socket.inet_ntoa(int(entry['dstIp']).to_bytes(4, "big"))
		flowIdentifier = (saddr, entry['srcPort'], daddr, entry['dstPort'], entry['protocol'])
		features = []
		for key, value in entry.items():
			if key not in ['srcIp', 'srcPort', 'dstIp', 'dstPort', 'protocol']:
				features.append(value)
		if flowIdentifier in flows:
			flows[flowIdentifier].append(features)
		else:
			flows[flowIdentifier] = [features]
	for key, value in flows.items():
		data.append({"id": key, "packets": value})
	with open(f'{output_dir}/result_{counter}.json', 'w') as fp:
		json.dump(data, fp, indent=2)



def parseAndStoreDebug(entries, output_dir, counter):
	for entry in entries:
		timestamp = entry['timestamp']
		seconds = timestamp // 1000000000
		nanoseconds = str(timestamp)[:9]
		saddr = socket.inet_ntoa(int(entry['srcIp']).to_bytes(4, "big"))
		daddr = socket.inet_ntoa(int(entry['dstIp']).to_bytes(4, "big"))
		file = open(f"{output_dir}/{saddr}-{entry['srcPort']}___{daddr}-{entry['dstPort']}___{timestamp}.csv", 'w')
		file.write(f"Seconds     ,\t{seconds}\n"
			f"Ns          ,\t{nanoseconds}\n"
			f"Length      ,\t{entry['length']}\n"
			f"IPv4 flags  ,\t{entry['ipFlagsFrag']}\n"
			f"TCP len     ,\t{entry['tcpLen']}\n"
			f"TCP ACK     ,\t{entry['tcpAck']}\n"
			f"TCP flags   ,\t{entry['tcpFlags']}\n"
			f"TCP Win     ,\t{entry['tcpWin']}\n"
			f"UDP len     ,\t{entry['udpSize']}\n"
			f"ICMP type   ,\t{entry['icmpType']}")
		file.close()

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
		if response.status_code == 500:
			print(response.content)
			exit(1)
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
	parser.add_argument('-d', '--debug', help='set the debug mode, to print also single packets file in the directory as .csv', action='store_true')
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=int, default=INTERVAL)
	parser.add_argument('-cm', '--capture_map_name', help='set the capture map name (the same in the json file)', type=str, default=CAPTURE_INFO_MAP_NAME)
	parser.add_argument('-pm', '--packet_feature_map_name', help='set the packet feature map name (the same in the json file)', type=str, default=PACKET_FEATURE_MAP_NAME)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()