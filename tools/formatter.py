#!/usr/bin/python3
# coding: utf-8

import argparse
import json


def main():
	args = parseArguments()
	with open(args['source_file'], 'r') as content_file:
		content = content_file.read()
	print(json.dumps(content))


def showVersion():
    with open('../VERSION', 'r') as fp:
        return '%(prog)s - Version ' + fp.readline()


def parseArguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('source_file', help='indicates the file to be escaped', type=str)
    parser.add_argument('-v', '--version', action='version', version=showVersion())
    return parser.parse_args().__dict__

if __name__ == '__main__':
	main()