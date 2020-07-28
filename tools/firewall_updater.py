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
    inject_rule = args['inject_rule']
    remove_rule = args['remove_rule']
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

    if inject_rule:
        tmp = {}
        for field in inject_rule.split():
            pair = field.split("=")
            tmp[pair[0]] = pair[1]
        injectRule(cube_name, tmp, chain)

    if remove_rule:
        removeRule(cube_name, remove_rule, chain)
    
    print('All done :)')


def removeRule(cube_name, rule_id, chain):
    try:
        response = requests.delete(f'{polycubed_endpoint}/firewall/{cube_name}/chain/{chain}/rule/{rule_id}', timeout=REQUESTS_TIMEOUT)
        if response.status_code == 500:
            print(response.content)
            return
        response.raise_for_status()
        print(f'Rule correctly removed')
    except requests.exceptions.HTTPError:
        print(f'Unable to remove rule {rule_id}\n\tError -> {response.status_code}\n\tWhat -> {response.content}')
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
        response = requests.post(f'{polycubed_endpoint}/firewall/{cube_name}/chain/{chain}/insert', timeout=REQUESTS_TIMEOUT, data=json.dumps(rule))
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


def parseArguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
    parser.add_argument('-i', '--inject-rule', help='the rule to be added', type=str, default=None)
    parser.add_argument('-r', '--remove-rule', help='the rule ID to be removed', type=str, default=None)
    parser.add_argument('-e', '--egress', help='set that the rule is to be inserted in the egress chain', action='store_true')
    parser.add_argument('-s', '--show-rules', help='show the rules already stored in firewall', action='store_true')
    parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
    parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
    parser.add_argument('-v', '--version', action='version', version=showVersion())
    return parser.parse_args().__dict__


def showVersion():
    return '%(prog)s - Version ' + VERSION


if __name__ == '__main__':
    main()
