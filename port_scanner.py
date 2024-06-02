#!/usr/bin/env python3

import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

open_socket = []

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo del programa...", 'red'))

    for socket in open_socket:
        socket.close()
    
    sys.exit(1)
signal.signal(signal.SIGINT, def_handler) # Ctrl+C

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Victim target to scan (Ex. -t 192.164.1.1) ")
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range to scan (Ex. -p 1-100)")

    options = parser.parse_args() #Recopila los argumentos pasados

    return options.target, options.port

def create_socket():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    open_socket.append(s)

    return s

def port_scanner(port, host):

    s = create_socket()

    try:
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = s.recv(1024)
        response = response.decode(errors='ignore').split('\n')[0]

        if response:
            print(colored(f"\n El puerto {port} está abierto - {response}", 'green'))
        else:
            print(colored(f"\n[+] El puerto {port} está abierto", 'green'))

    except (socket.timeout, ConnectionRefusedError):
        pass

    finally:
        s.close()

def scan_ports(ports, target):

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(port, target), ports)


def parse_ports(ports_str):
    if '-' in ports_str:
        start, end = map(int,ports_str.split('-'))
        return range (start, end+1)

    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    else:
        return (int(ports_str),) #Tupla con un unico elemento


def main():

    target, ports_str = get_arguments()
    ports = parse_ports(ports_str)
    scan_ports(ports, target)

    
if __name__ == '__main__':
    main()
