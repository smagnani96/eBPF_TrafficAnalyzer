#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os

FILENAME 					= 'results.csv'
POLYCUBED_ADDR 				= 'localhost'
POLYCUBED_PORT				= 9000
REQUESTS_TIMEOUT 			= 10
OUTPUT_DIR 					= 'dump_crypto'
INTERVAL 					= 2  # seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01
OLD_WINDOW					= 30 # seconds after to we consider a local entry old
polycubed_endpoint 			= 'http://{}:{}/polycube/v1'
counter 					= 0
protocol_map 				= dict(			# map protocol integer value to name
	[(6, "TCP"), (17, "UDP")])


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
			fp.write("Timestamp, IP Client, IP Server, Port Client, Port Server, Protocol, Server Method, Packets_ server, Packets_"
				"client, Bits_ server, Bits_ client, Duration, Packets_ server /Seconds,Packets_ client /Seconds, Bits_ server"
				"Seconds, Bits_client /Seconds, Bits _server / Packets _server, Bits _client / Packets _client, Packets_server"
				"Packets_client, Bits_server /Bits_client\n")

	dynmonConsume(cube_name, interval, interval*1000000000, is_json, output_dir)


def dynmonConsume(cube_name, interval, interval_ns, is_json, output_dir):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	start_time = time.time()
	metric =  getMetric(cube_name)
	ns = time.time_ns()
	req_time = ns / 1000000000
	
	threading.Timer(interval, dynmonConsume, (cube_name, interval, interval_ns, is_json, output_dir)).start()

	if not metric:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
		return

	parseAndStore(metric, ns - interval_ns, output_dir, req_time) if is_json is False else parseAndStoreJson(metric, ns - interval_ns, my_count, output_dir, req_time)
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')


def parseAndStoreJson(metric, last_check_time, my_count, output_dir, curr_time):
	data = []
	for entry in metric:
		key = entry['key']
		value = entry['value']
		
		if value['alive_timestamp'] <= last_check_time: 
			continue
		
		if value['server_ip'] == key['saddr']:
			connIdentifier = (
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.ntohs(key['dport']),
				socket.ntohs(key['sport']),
				protocol_map[key['proto']])
		else:
			connIdentifier = (
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.ntohs(key['sport']),
				socket.ntohs(key['dport']),
				protocol_map[key['proto']])

		n_packets_client = value['n_packets_client']
		n_packets_server = value['n_packets_server']
		n_bits_server = value['n_bits_server']
		n_bits_client = value['n_bits_client']
		duration = value['alive_timestamp'] - value['start_timestamp']
		seconds = duration / 1000000000
		values = [value['alive_timestamp'], value['method'], n_packets_server, n_packets_client,
			n_bits_server, n_bits_client, duration, makeDivision(n_packets_server,seconds), makeDivision(n_packets_client,seconds),
			makeDivision(n_bits_server,seconds), makeDivision(n_bits_client,seconds), makeDivision(n_bits_server,n_packets_server),
			makeDivision(n_bits_client,n_packets_client), makeDivision(n_packets_server,n_packets_client), makeDivision(n_bits_server,n_bits_client)]
		data.append({"id": connIdentifier, "value": values})

	with open(f'{output_dir}/result_{counter}.json', 'w') as fp:
		json.dump(data, fp, indent=2)


def parseAndStore(metric, last_check_time, output_dir, curr_time):
	fp = open(f"{output_dir}/{FILENAME}", 'a')
	for entry in metric:
		key = entry['key']
		value = entry['value']
		
		if value['alive_timestamp'] <= last_check_time: 
			continue
		
		if value['server_ip'] == key['saddr']:
			connIdentifier = (
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.ntohs(key['dport']),
				socket.ntohs(key['sport']),
				protocol_map[key['proto']])
		else:
			connIdentifier = (
				socket.inet_ntoa(int(key['saddr']).to_bytes(4, "little")),
				socket.inet_ntoa(int(key['daddr']).to_bytes(4, "little")),
				socket.ntohs(key['sport']),
				socket.ntohs(key['dport']),
				protocol_map[key['proto']])
		
		n_packets_client = value['n_packets_client']
		n_packets_server = value['n_packets_server']
		n_bits_server = value['n_bits_server']
		n_bits_client = value['n_bits_client']
		duration = value['alive_timestamp'] - value['start_timestamp']
		seconds = duration / 1000000000
		fp.write(f"{value['alive_timestamp']}, {', '.join(map(str, connIdentifier))}, {value['method']}, {n_packets_server}, {n_packets_client}, "
			f"{n_bits_server}, {n_bits_client}, {duration}, {makeDivision(n_packets_server,seconds)}, {makeDivision(n_packets_client,seconds)}, "
			f"{makeDivision(n_bits_server,seconds)}, {makeDivision(n_bits_client,seconds)}, {makeDivision(n_bits_server,n_packets_server)}, "
			f"{makeDivision(n_bits_client,n_packets_client)}, {makeDivision(n_packets_server,n_packets_client)}, {makeDivision(n_bits_server,n_bits_client)}\n")
	fp.close()


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


def checkIfOutputDirExists(output_dir):
	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")


def parseArguments():
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
	parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
	parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
	parser.add_argument('-o', '--output', help='set the output directory', type=str, default=OUTPUT_DIR)
	parser.add_argument('-j', '--json', help='set the output files format to json', action='store_true')
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()