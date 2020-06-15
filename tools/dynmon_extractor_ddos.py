#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, ipaddress, errno
from datetime import datetime
from collections.abc import Sequence

VERSION = '1.0'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 10
OUTPUT_DIR = 'dump_ddos'
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

	checkIfOutputDirExists(output_dir)

	dynmonConsume(cube_name, output_dir, interval, debug)


def dynmonConsume(cube_name, output_dir, interval, debug):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	start_time = time.time()
	metric =  getMetric(cube_name)
	req_time = time.time()

	threading.Timer(interval, dynmonConsume, (cube_name, output_dir, interval, debug)).start()

	if not metric:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
		return

	parseAndStore(metric, output_dir, my_count) if debug is False else parseAndStoreDebug(metric, output_dir, my_count)	
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)\n\tPacket parsed: {len(metric)}')


def parseAndStore(entries, output_dir, counter):
	data = []
	flows = {}
	for entry in entries:
		sid = entry['id']
		srcIp = socket.inet_ntoa(sid['saddr'].to_bytes(4, 'little'))
		dstIp = socket.inet_ntoa(sid['daddr'].to_bytes(4, 'little'))
		srcPort = socket.ntohs(sid['sport'])
		dstPort = socket.ntohs(sid['dport'])
		flowIdentifier = (srcIp, srcPort, dstIp, dstPort, sid['proto'])
		features = []
		for key, value in entry.items():
			if key != 'id':
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
		sid = entry['id']
		srcIp = socket.inet_ntoa(sid['saddr'].to_bytes(4, 'little'))
		dstIp = socket.inet_ntoa(sid['daddr'].to_bytes(4, 'little'))
		srcPort = socket.ntohs(sid['sport'])
		dstPort = socket.ntohs(sid['dport'])
		file = open(f"{output_dir}/{srcIp}-{srcPort}___{dstIp}-{dstPort}___{timestamp}.csv", 'w')
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


def getMetric(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/ingress-metrics/PACKET_BUFFER/value', timeout=REQUESTS_TIMEOUT)
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