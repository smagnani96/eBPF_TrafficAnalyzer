#!/usr/bin/python3
# coding: utf-8

import time
import threading
import argparse
import requests
import json
import socket
import os
from os import path

POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 300
OUTPUT_DIR = 'dump_ddos'
INTERVAL = 10   		 	# seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01
protocol_map = dict(			# map protocol integer value to name
    [(6, "TCP"), (17, "UDP"), (1, "ICMP")])

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
    is_json = args['json']

    polycubed_endpoint = polycubed_endpoint.format(addr, port)

    checkIfOutputDirExists(output_dir)

    threading.Timer(interval, dynmonConsume, (cube_name,
                                              output_dir, interval, is_json)).start()


def dynmonConsume(cube_name, output_dir, interval, is_json):
    global counter
    parsed_entries = []
    my_count = counter
    counter += 1

    start_time = time.time()
    metrics = getMetrics(cube_name)
    req_time = time.time()

    threading.Timer(interval, dynmonConsume, (cube_name,
                                              output_dir, interval, is_json)).start()

    packets = metrics['ingress-metrics'][0]['value']
    sessions_map = metrics['ingress-metrics'][1]['value']

    if not packets or not sessions_map:
        print(
            f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
        return

    parseAndStoreJson(packets, sessions_map, output_dir, my_count) if is_json else parseAndStore(
        packets, sessions_map, output_dir, my_count)
    print(
        f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)\n\tPacket parsed: {len(packets)}')


def parseAndStoreJson(packets, sessions, output_dir, my_count):
    flows = {}
    for session in sessions:
        key = session['key']
        flow_id = (key['saddr'], key['sport'],
                   key['daddr'], key['dport'], key['proto'])
        flows[flow_id] = (session['value']['server_ip'], [])

    for entry in packets:
        sid = entry['id']
        timestamp = entry['timestamp'] / 1000000000
        features = [timestamp]
        for key, value in entry.items():
            if key != 'id' and key != 'timestamp':
                features.append(value)

        flow_id = (sid['saddr'], sid['sport'],
                   sid['daddr'], sid['dport'], sid['proto'])

        flows[flow_id][1].append(features)

    # used to convert flows identifier
    data = []
    for key, value in flows.items():
        if key[0] == value[0]:
            key = (key[2], key[3], key[0], key[1], key[4])
        parsed_key = (
            socket.inet_ntoa(key[0].to_bytes(4, 'little')),
            socket.ntohs(key[1]),
            socket.inet_ntoa(key[2].to_bytes(4, 'little')),
            socket.ntohs(key[3]),
            protocol_map[key[4]]
        )
        data.append({"id": parsed_key, "packets": value[1]})

    # print data to file (SUBSTITUTE HERE YOUR CODE)
    with open(f'{output_dir}/result_{my_count}.json', 'w') as fp:
        json.dump(data, fp, indent=2)


def parseAndStore(packets, sessions, output_dir, my_count):
    flows = {}
    for session in sessions:
        key = session['key']
        flow_id = (key['saddr'], key['sport'],
                   key['daddr'], key['dport'], key['proto'])
        flows[flow_id] = (session['value']['server_ip'], {
            'seconds': 		[],
            'nanoseconds':  [],
            'ipFlagsFrag':	[],
            'tcpFlags':		[],
            'tcpWin':		[],
            'udpSize':		[],
            'icmpType':		[]
        })

    for entry in packets:
        seconds = entry['timestamp'] // 1000000000
        nanoseconds = str(entry['timestamp'])[-9:]
        sid = entry['id']
        flowIdentifier = (sid['saddr'], sid['sport'],
                          sid['daddr'], sid['dport'], sid['proto'])

        flows[flowIdentifier][1]['seconds'].append(seconds)
        flows[flowIdentifier][1]['nanoseconds'].append(nanoseconds)
        flows[flowIdentifier][1]['ipFlagsFrag'].append(entry['ipFlagsFrag'])
        flows[flowIdentifier][1]['tcpFlags'].append(entry['tcpFlags'])
        flows[flowIdentifier][1]['tcpWin'].append(entry['tcpWin'])
        flows[flowIdentifier][1]['udpSize'].append(entry['udpSize'])
        flows[flowIdentifier][1]['icmpType'].append(entry['icmpType'])

    # flows now is a json with key the session ID, and as value each feature as array, optimized for printing csv

    # foreach entry print to a different file
    for key, value in flows.items():
        if key[0] == value[0]:
            key = (key[2], key[3], key[0], key[1], key[4])
        parsed_key = (
            socket.inet_ntoa(key[0].to_bytes(4, 'little')),
            socket.ntohs(key[1]),
            socket.inet_ntoa(key[2].to_bytes(4, 'little')),
            socket.ntohs(key[3]),
            protocol_map[key[4]]
        )
        with open(f"{output_dir}/{parsed_key[0]}-{parsed_key[1]}___{parsed_key[2]}-{parsed_key[3]}___{parsed_key[4]}-iter{my_count}.csv", 'w') as fp:
            fp.write(""
                     f"Seconds     ,\t{', '.join(map(str,value[1]['seconds']))}\n"
                     f"Ns          ,\t{', '.join(map(str,value[1]['nanoseconds']))}\n"
                     f"IPv4 flags  ,\t{', '.join(map(str,value[1]['ipFlagsFrag']))}\n"
                     f"TCP flags   ,\t{', '.join(map(str,value[1]['tcpFlags']))}\n"
                     f"TCP Win     ,\t{', '.join(map(str,value[1]['tcpWin']))}\n"
                     f"UDP len     ,\t{', '.join(map(str,value[1]['udpSize']))}\n"
                     f"ICMP type   ,\t{', '.join(map(str,value[1]['icmpType']))}")


def checkIfOutputDirExists(output_dir):
    try:
        os.mkdir(output_dir)
    except IOError:
        print(f"Directory {output_dir} already exists")
    except OSError:
        print(f"Creation of the directory {output_dir} failed")
    else:
        print(f"Successfully created the directory {output_dir}")


def getMetrics(cube_name):
    try:
        response = requests.get(
            f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/', timeout=REQUESTS_TIMEOUT)
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


def showVersion():
    with open(f'{path.dirname(__file__)}/../VERSION', 'r') as fp:
        return '%(prog)s - Version ' + fp.readline()


def parseArguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        'cube_name', help='indicates the name of the cube', type=str)
    parser.add_argument(
        '-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
    parser.add_argument(
        '-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
    parser.add_argument(
        '-o', '--output', help='set the output directory', type=str, default=OUTPUT_DIR)
    parser.add_argument(
        '-j', '--json', help='set the output files format to json', action='store_true')
    parser.add_argument(
        '-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
    parser.add_argument('-v', '--version', action='version',
                        version=showVersion())
    return parser.parse_args().__dict__


if __name__ == '__main__':
    main()
