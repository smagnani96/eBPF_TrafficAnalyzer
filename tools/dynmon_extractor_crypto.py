#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, copy

VERSION = '1.0'
FILENAME 					= 'results.csv'
POLYCUBED_ADDR 				= 'localhost'
POLYCUBED_PORT				= 9000
REQUESTS_TIMEOUT 			= 300
OUTPUT_DIR 					= 'dump_crypto'
INTERVAL 					= 10  # seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01
polycubed_endpoint 			= 'http://{}:{}/polycube/v1'
counter 					= 0
protocol_map 				= dict(			# map protocol integer value to name
	[(6, "TCP"), (17, "UDP")])
empty_feature 				= dict(
	[('n_packets',0), ('n_packets_reverse',0), ('n_bytes',0), ('n_bytes_reverse',0), ('start_timestamp',0), ('alive_timestamp',0), ('method',0), ('server_ip',0)])


def main():
	global polycubed_endpoint

	args = parseArguments()

	addr 		= args['address']
	port 		= args['port']
	output_dir = args['output']
	cube_name 	= args['cube_name']
	interval 	= args['interval']
	is_json 	= args['json']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)
	
	checkIfOutputDirExists(output_dir)

	if is_json is False:
		with open(f"{output_dir}/{FILENAME}", 'w') as fp:
			fp.write("Timestamp (Unix ns), IP Client, IP Server, Port Client, Port Server, Protocol, Server Method, Packets_server, Packets_client, "
				"Bits_ server, Bits_ client, Duration (ns), Packets_server / Seconds, Packets_client / Seconds, Bits_server / Seconds, "
				"Bits_client / Seconds, Bits_server / Packets_server, Bits_client / Packets_client, Packets_server / Packets_client, Bits_server / Bits_client\n")

	threading.Timer(interval, dynmonConsume, (cube_name, interval, is_json, output_dir)).start()


def dynmonConsume(cube_name, interval, is_json, output_dir):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	start_time = time.time()
	metric =  getMetrics(cube_name)['ingress-metrics'][0]['value']
	req_time = time.time()
	
	threading.Timer(interval, dynmonConsume, (cube_name, interval, is_json, output_dir)).start()
	
	if not metric:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metric: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
		return

	parseAndStore(metric, output_dir, req_time) if is_json is False else parseAndStoreJson(metric, my_count, output_dir, req_time)
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metric: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)\n\tMetric parsed: {len(metric)}')


def sumCPUValues(values, key):
	ret = copy.copy(empty_feature)
	#summing each cpu values
	for value in values:
		ret['n_packets'] += value['n_packets']
		ret['n_packets_reverse'] += value['n_packets_reverse']
		ret['n_bytes'] += value['n_bytes']
		ret['n_bytes_reverse'] += value['n_bytes_reverse']
		if value['server_ip'] != 0: ret['server_ip'] = value['server_ip']
		if value['start_timestamp'] > ret['start_timestamp']: ret['start_timestamp'] = value['start_timestamp']
		if value['alive_timestamp'] > ret['alive_timestamp']: ret['alive_timestamp'] = value['alive_timestamp']
		if value['method'] != 0: ret['method'] = value['method']
	#modifying fields according to client-server and parsing Identifiers
	if value['server_ip'] == key['saddr']:
		ret['n_packets_client'] = ret.pop('n_packets_reverse')
		ret['n_packets_server'] = ret.pop('n_packets')
		ret['n_bytes_client'] = ret.pop('n_bytes_reverse')
		ret['n_bytes_server'] = ret.pop('n_bytes')
		ret['id'] = (
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.ntohs(key['dport']),
				socket.ntohs(key['sport']),
				protocol_map[key['proto']])
	else:
		ret['n_packets_client'] = ret.pop('n_packets')
		ret['n_packets_server'] = ret.pop('n_packets_reverse')
		ret['n_bytes_client'] = ret.pop('n_bytes')
		ret['n_bytes_server'] = ret.pop('n_bytes_reverse')
		ret['id'] = (
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.ntohs(key['sport']),
				socket.ntohs(key['dport']),
				protocol_map[key['proto']])
	return ret


def parseAndStoreJson(metric, my_count, output_dir, curr_time):
	data = []
	for entry in metric:
		value = sumCPUValues(entry['value'], entry['key'])

		n_packets_client = value['n_packets_client']
		n_packets_server = value['n_packets_server']
		n_bits_server = value['n_bytes_server']*8
		n_bits_client = value['n_bytes_client']*8
		duration = value['alive_timestamp'] - value['start_timestamp']
		seconds = duration / 1000000000
		values = [value['alive_timestamp'], value['method'], n_packets_server, n_packets_client,
			n_bits_server, n_bits_client, duration, makeDivision(n_packets_server,seconds), makeDivision(n_packets_client,seconds),
			makeDivision(n_bits_server,seconds), makeDivision(n_bits_client,seconds), makeDivision(n_bits_server,n_packets_server),
			makeDivision(n_bits_client,n_packets_client), makeDivision(n_packets_server,n_packets_client), makeDivision(n_bits_server,n_bits_client)]
		data.append({"id": value['id'], "value": values})

	#data is a list of session identifiers-features
	#REPLACE THE FOLLOWING CODE (output to file) with your ML direct interaction@@@
	with open(f'{output_dir}/result_{my_count}.json', 'w') as fp:
		json.dump(data, fp, indent=2)


def parseAndStore(metric, output_dir, curr_time):
	fp = open(f"{output_dir}/{FILENAME}", 'a')
	for entry in metric:
		value = sumCPUValues(entry['value'], entry['key'])
		
		n_packets_client = value['n_packets_client']
		n_packets_server = value['n_packets_server']
		n_bits_server = value['n_bytes_server']*8
		n_bits_client = value['n_bytes_client']*8
		duration = value['alive_timestamp'] - value['start_timestamp']
		seconds = duration / 1000000000
		fp.write(f"{value['alive_timestamp']}, {', '.join(map(str, value['id']))}, {value['method']}, {n_packets_server}, {n_packets_client}, "
			f"{n_bits_server}, {n_bits_client}, {duration}, {makeDivision(n_packets_server,seconds)}, {makeDivision(n_packets_client,seconds)}, "
			f"{makeDivision(n_bits_server,seconds)}, {makeDivision(n_bits_client,seconds)}, {makeDivision(n_bits_server,n_packets_server)}, "
			f"{makeDivision(n_bits_client,n_packets_client)}, {makeDivision(n_packets_server,n_packets_client)}, {makeDivision(n_bits_server,n_bits_client)}\n")
	fp.close()


def makeDivision(i, j):
	return i / j if j else '-'


def getMetrics(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/', timeout=REQUESTS_TIMEOUT)
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


def checkIfOutputDirExists(output_dir):
	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")


def showVersion():
    return '%(prog)s - Version ' + VERSION


def parseArguments():
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
	parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
	parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
	parser.add_argument('-o', '--output', help='set the output directory', type=str, default=OUTPUT_DIR)
	parser.add_argument('-j', '--json', help='set the output files format to json', action='store_true')
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
	parser.add_argument('-v', '--version', action='version', version=showVersion())
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()