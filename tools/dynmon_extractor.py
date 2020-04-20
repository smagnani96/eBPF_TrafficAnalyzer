#!/usr/bin/python3
# coding: utf-8

import argparse
import requests
import json
import socket, struct
import os
import errno

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 5 #seconds
OUTPUT_DIR = 'dump'
FILE_FORMAT = 'csv'
CAPTURE_INFO_MAP_NAME = "CAPTURE_INFO"
PACKET_FEATURE_MAP_NAME = "PACKET_FEATURE_MAP"

polycubed_endpoint = 'http://{}:{}/polycube/v1'

def main():
	global polycubed_endpoint

	args = parseArguments()

	addr = args['address']
	port = args['port']
	cube_name = args['cube_name']
	output_dir = args['output']
	file_format = args['file_format']

	capture_map_name = args['capture_map_name']
	packet_feature_map_name = args['packet_feature_map_name']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfServiceExists(cube_name)
	metrics = getMetrics(cube_name)

	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")

	entry_index = 0

	for metric in metrics:
		value = json.loads(metric['value'])
		if metric['name'] == capture_map_name:
			entry_index = int(value['feature_map_index'])
			print('Information concerning the actual capture')
			print('\tEntryValidIndex: 0-{}'.format(value['feature_map_index']))
			print('\tSessionTracked: {}'.format(value['n_session_tracking']))
		elif metric['name'] == packet_feature_map_name:
			for i in range(entry_index):
				timestamp = value[i]['timestamp']
				saddr = socket.inet_ntoa(struct.pack('!L', value[i]['saddr']))
				daddr = socket.inet_ntoa(struct.pack('!L', value[i]['daddr']))
				length = value[i]['length']
				ipv4_flags = value[i]['ipv4_flags']
				tcp_len = value[i]['tcp_len']
				tcp_ack = value[i]['tcp_ack']
				tcp_flags = value[i]['tcp_flags']
				tcp_win = value[i]['tcp_win']
				udp_len = value[i].get('udp_len', 0)
				icmp_type = value[i].get('icmp_type', 0)
				file = open(f'{output_dir}/{timestamp}__{saddr}__{daddr}.{file_format}', 'w')
				file.write(f"Timestamp,\t{timestamp}\n")
				file.write(f"Length,\t{length}\n")
				file.write(f"IPv4 flags,\t{ipv4_flags}\n")
				file.write(f"TCP len,\t{tcp_len}\n")
				file.write(f"TCP ACK,\t{tcp_ack}\n")
				file.write(f"TCP flags,\t{tcp_flags}\n")
				file.write(f"TCP Win,\t{tcp_win}\n")
				file.write(f"UDP len,\t0\n")
				file.write(f"ICMP type,\t0")
				file.write
				file.close()
		else:
			#Add here for more metric to be parsed
			print('Ignored metric')


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
	parser.add_argument('-f', '--file_format', help='set the output files format', type=str, default=FILE_FORMAT)
	parser.add_argument('-cm', '--capture_map_name', help='set the capture map name (the same in the json file)', type=str, default=CAPTURE_INFO_MAP_NAME)
	parser.add_argument('-pm', '--packet_feature_map_name', help='set the packet feature map name (the same in the json file)', type=str, default=PACKET_FEATURE_MAP_NAME)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()