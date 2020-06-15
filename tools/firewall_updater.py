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
    rule = args['rule']
    isToRemove = args['remove']
    chain = "egress" if args['egress'] else "ingress"

    polycubed_endpoint = polycubed_endpoint.format(addr, port)

    fw = getFirewall(cube_name)
    print(json.dumps(fw, indent=2))

    eraseRule(cube_name, 0, chain) if isToRemove else injectRule(cube_name, json.loads(rule), chain)
    '''
    TODO: define how to inject new rules with red border
    '''

def eraseRule(cube_name, rule_id, chain):
    try:
        response = requests.delete(f'{polycubed_endpoint}/firewall/{cube_name}/chain/${chain}/rule/{rule_id}', timeout=REQUESTS_TIMEOUT)
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


def injectRule(cube_name, rule, chain):
    try:
        response = requests.post(f'{polycubed_endpoint}/firewall/{cube_name}/chain/{chain}/insert', timeout=REQUESTS_TIMEOUT, data=chain)
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


def getFirewall(cube_name):
    try:
        response = requests.get(f'{polycubed_endpoint}/firewall/{cube_name}', timeout=REQUESTS_TIMEOUT)
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
    parser.add_argument('rule', help='the rule to be added/removed', type=str)
    parser.add_argument('-r', '--remove', help='set that the rule is to be removed', action='store_true')
    parser.add_argument('-e', '--egress', help='set that the rule is to be inserted in the egress chain', action='store_true')
    parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
    parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
    parser.add_argument('-v', '--version', action='version', version=showVersion())
    return parser.parse_args().__dict__


def showVersion():
    return '%(prog)s - Version ' + VERSION


if __name__ == '__main__':
    main()
