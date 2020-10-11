#!/usr/bin/python3
# coding: utf-8

import argparse
import socket
import requests
import json
import os.path
from os import path

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
    rule_file = args['rule_file']
    show = args['show_rules']
    chain = "EGRESS" if args['egress'] else "INGRESS"

    polycubed_endpoint = polycubed_endpoint.format(addr, port)

    if show:
        ingress = getRules(cube_name, "INGRESS")
        egress = getRules(cube_name, "EGRESS")
        print(f'Ingress rules:')
        for x in ingress: print(f'\t{json.dumps(x)}')
        print(f'Egress rules:')
        for x in egress: print(f'\t{json.dumps(x)}')
        return
    
    rules = None
    '''
    Here the rules are loaded from a JSON file, feel free to create the payload of the POST request directly here.
    An example could be:

    {
        "rules": [
            {"operation": "insert", "id": 0, "l4proto":"TCP", "src":"10.0.0.100/32", "dst":"10.0.0.150/24", "action":"drop"},
            {"operation": "append", "l4proto": "ICMP", "src":"10.0.0.50/32", "dst":"10.0.0.75/24", "action":"drop"},
            {"operation": "append", "l4proto": "ICMP", "src":"10.0.0.11/32", "dst":"10.0.0.12/24", "action":"drop"},
            {"operation": "update", "id": 0, "l4proto":"TCP", "src":"10.0.0.100/32", "dst":"10.0.0.75/24", "action":"forward"},
            {"operation": "delete", "id": 0},
            {"operation": "delete", "l4proto":"ICMP", "src":"10.0.0.50/32", "dst":"10.0.0.75/24", "action":"drop"}
        ]
    }
    
    '''

    with open(rule_file) as fp:
        rules = json.load(fp)
    
    if rules is None:
        print('An error occurred reading the JSON file')
        return
    
    injectRules(cube_name, rules, chain)
    print('All done :)')


def injectRules(cube_name, rules, chain):
    try:
        response = requests.post(f'{polycubed_endpoint}/firewall/{cube_name}/chain/{chain}/batch', timeout=REQUESTS_TIMEOUT, json=rules)
        if response.status_code == 500:
            print(response.content)
            return
        response.raise_for_status()
        print(f'Rule correctly injected')
    except requests.exceptions.HTTPError:
        print(f'Unable to inject rule {rule}\n\tError -> {response.status_code}\n\tWhat -> {response.content}')
    except requests.exceptions.ConnectionError:
        print('Connection error: unable to connect to polycube daemon.')
        exit(1)
    except requests.exceptions.Timeout:
        print('Timeout error: unable to connect to polycube daemon.')
        exit(1)
    except requests.exceptions.RequestException:
        print('Error: unable to connect to polycube daemon.')
        exit(1)
    except json.JSONDecodeError:
        print(f'Unable to decode rule {rule}')
        exit(1)


def getRules(cube_name, chain):
    try:
        response = requests.get(f'{polycubed_endpoint}/firewall/{cube_name}/chain/{chain}/rule', timeout=REQUESTS_TIMEOUT)
        if response.status_code == 500:
            print(response.content)
            exit(1)
        response.raise_for_status()
        return json.loads(response.content)[:-1]
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
    with open('../VERSION', 'r') as fp:
        return '%(prog)s - Version ' + fp.readline()


def parseArguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
    parser.add_argument('-r', '--rule-file', help='the file containing the rules to be pushed', type=str, default=None)
    parser.add_argument('-s', '--show-rules', help='show the rules already stored in firewall', action='store_true')
    parser.add_argument('-e', '--egress', help='set that the rule is to be inserted in the egress chain', action='store_true')
    parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
    parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
    parser.add_argument('-v', '--version', action='version', version=showVersion())
    args = parser.parse_args().__dict__
    if args['rule_file'] is None and args['show_rules'] is False:
        parser.error('You need to specify an action (-r / -s)')
    return args


if __name__ == '__main__':
    main()
