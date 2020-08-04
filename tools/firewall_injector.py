#!/usr/bin/python3
# coding: utf-8

import argparse
import socket
import requests
import json
import os.path
from os import path

VERSION = '1.1'
POLYCUBED_ADDR = 'localhost'
POLYCUBED_PORT = 9000
REQUESTS_TIMEOUT = 5 #seconds

polycubed_endpoint = 'http://{}:{}/polycube/v1'


def main():
    global polycubed_endpoint
    args = parseArguments()

    addr = args['address']
    port = args['port']

    cube_name = args['cube_name']
    interface_name = args['peer_interface']
    
    polycubed_endpoint = polycubed_endpoint.format(addr, port)

    already_exists, cube = checkIfServiceExists(cube_name)

    if already_exists:
        print(f'Firewall {cube_name} already exist')
        attached_interface = cube['parent']
        if attached_interface:
            if attached_interface != interface_name:
                detach_from_interface(cube_name, attached_interface)
                attach_to_interface(cube_name, interface_name)
        else:
            attach_to_interface(cube_name, interface_name)
    else:
        createInstance(cube_name)
        attach_to_interface(cube_name, interface_name)


def checkIfServiceExists(cube_name):
    try:
        response = requests.get(f'{polycubed_endpoint}/firewall/{cube_name}', timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        return True, json.loads(response.content)
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


def createInstance(cube_name):
    try:
        print(f'Creating new Firewall instance named {cube_name}')
        response = requests.post(f'{polycubed_endpoint}/firewall/{cube_name}',
                                timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        print(f'Error: {response.content.decode("UTF-8")}')
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


def detach_from_interface(cube_name, interface):
    try:
        print(f'Detaching {cube_name} from {interface}')
        response = requests.post(f'{polycubed_endpoint}/detach',
                                 json.dumps({'cube': cube_name, 'port': interface}),
                                 timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        print(f'Error: {response.content.decode("UTF-8")}')
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


def attach_to_interface(cube_name, interface):
    try:
        print(f'Attaching {cube_name} to {interface}')
        response = requests.post(f'{polycubed_endpoint}/attach',
                                 json.dumps({'cube': cube_name, 'port': interface, 'position': 'first'}),
                                 timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        print(f'Error: {response.content.decode("UTF-8")}')
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


def parseArguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
    parser.add_argument('peer_interface', help='indicates the network interface to connect the cube to', type=str)
    parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
    parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
    parser.add_argument('-v', '--version', action='version', version=showVersion())
    return parser.parse_args().__dict__


def showVersion():
    return '%(prog)s - Version ' + VERSION


if __name__ == '__main__':
    main()
