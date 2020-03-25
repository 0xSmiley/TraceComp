#!/usr/bin/env python3

import socket
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("ip")
parser.add_argument("port")
parser.add_argument("wordlist")
args = parser.parse_args()

if args.ip == "":
    print("You must define an IP address")
    exit()
if args.port == "":
    print("You must define a Port")
    exit()
if args.port == "":
    print("You must define a path to a wordlist")
    exit()


HOST = args.ip
PORT = int(args.port )
WORDLIST = args.wordlist

with open(WORDLIST) as f:
        line = f.readline()
        while line != "":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                line=line.strip()
                s.send(line.encode("utf-8"))    
                s.close()
            line = f.readline()
        

# python3 client.py 192.168.1.85 65432 wordlist.txt
#docker run --network=host -v /Users/nunolopes/Desktop/Runtime/Fuzzer/Socket/Client:/app socketclient python3 client.py 192.168.1.85 65432 wordlist.txt
