#!/usr/bin/python3
# coding: utf-8

import sched
import time
import argparse
import requests
import json
import socket, struct
from datetime import datetime
import os
import errno

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 5 #seconds
OUTPUT_DIR = 'dump'
CAPTURE_INFO_MAP_NAME = "CAPTURE_INFO"
PACKET_FEATURE_MAP_NAME = "PACKET_BUFFER"
INTERVAL = 10 

polycubed_endpoint = 'http://{}:{}/polycube/v1'

def main():
	global polycubed_endpoint

	args = parseArguments()

	addr = args['address']
	port = args['port']
	cube_name = args['cube_name']
	output_dir = args['output']
	debug = args['debug']
	interval = args['interval']

	capture_map_name = args['capture_map_name']
	packet_feature_map_name = args['packet_feature_map_name']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfServiceExists(cube_name)

	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")

	s = sched.scheduler(time.time, time.sleep)
	dynmonConsume(s, cube_name, capture_map_name, packet_feature_map_name, output_dir, debug, interval)
	s.run()

def dynmonConsume(sc, cube_name, capture_map_name, packet_feature_map_name, output_dir, debug, interval):
	entry_index = 0
	metrics = getMetrics(cube_name)

	for metric in metrics[:-1]:
		value = json.loads(metric['value'])
		if metric['name'] == capture_map_name:
			entry_index = int(value['next_index']) - 1 if int(value['next_index'])-1 >= 0 else 0 
			print('Information concerning the actual capture')
			print('\tEntryValidIndex: [0-{}]'.format(entry_index))
			print('\tSessionsTracked: {}'.format(value['n_session_tracking']))
		elif metric['name'] == packet_feature_map_name:
			valid_entries = value[:entry_index]
			printDebug(valid_entries, output_dir) if debug is True else None
			reassembleAndPrint(valid_entries, output_dir)
		else:
			#Add here for more metric to be parsed
			print('Ignored metric')
	sc.enter(interval, 1, dynmonConsume, (sc, cube_name, capture_map_name, packet_feature_map_name, output_dir, debug, interval))


def reassembleAndPrint(packets, output_dir):
	flows = {}
	for packet in packets:
		saddr = socket.inet_ntoa(struct.pack('!L', packet['srcIp']))
		daddr = socket.inet_ntoa(struct.pack('!L', packet['dstIp']))
		flowIdentifier = (saddr, packet['srcPort'], daddr, packet['dstPort'], packet['protocol'])
		features = []
		for key, value in packet.items():
			if key not in ['srcIp', 'srcPort', 'dstIp', 'dstPort', 'protocol']:
				features.append(value)
		if flowIdentifier in flows:
			flows[flowIdentifier].append(features)
		else:
			flows[flowIdentifier] = [features]
	data = {"flows": []}
	for key, value in flows.items():
		data['flows'].append({"id": key, "packets": value})
	with open(f'{output_dir}/result.json', 'w') as fp:
		json.dump(data, fp, indent=2)


def printDebug(packets, output_dir):
	for packet in packets:
		timestamp = packet['timestamp']
		seconds = timestamp // 1000000000
		nanoseconds = str(timestamp)[:9]
		saddr = socket.inet_ntoa(struct.pack('!L', packet['srcIp']))
		daddr = socket.inet_ntoa(struct.pack('!L', packet['dstIp']))
		file = open(f"{output_dir}/{saddr}-{packet['srcPort']}___{daddr}-{packet['dstPort']}___{timestamp}.csv", 'w')
		file.write(f"Seconds     ,\t{seconds}\n")
		file.write(f"Ns          ,\t{nanoseconds}\n")
		file.write(f"Length      ,\t{packet['length']}\n")
		file.write(f"IPv4 flags  ,\t{packet['ipFlagsFrag']}\n")
		file.write(f"TCP len     ,\t{packet['tcpLen']}\n")
		file.write(f"TCP ACK     ,\t{packet['tcpAck']}\n")
		file.write(f"TCP flags   ,\t{packet['tcpFlags']}\n")
		file.write(f"TCP Win     ,\t{packet['tcpWin']}\n")
		file.write(f"UDP len     ,\t{packet['udpSize']}\n")
		file.write(f"ICMP type   ,\t{packet['icmpType']}\n")
		file.write
		file.close()

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
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/', timeout=REQUESTS_TIMEOUT)
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
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=int, default=INTERVAL)
	parser.add_argument('-d', '--debug', help='set the debug mode, to print also single packets file in the directory as .csv', action='store_true')
	parser.add_argument('-cm', '--capture_map_name', help='set the capture map name (the same in the json file)', type=str, default=CAPTURE_INFO_MAP_NAME)
	parser.add_argument('-pm', '--packet_feature_map_name', help='set the packet feature map name (the same in the json file)', type=str, default=PACKET_FEATURE_MAP_NAME)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()