#!/usr/bin/env python
import os
import sys
import socket


HOST = 'quadpoint.org'
PORT = 31336


def main():
  if len(sys.argv) == 1:
    return

  data = ' '.join(sys.argv[1:])
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((HOST, PORT))
  sock.send(data)
  sock.close()


if __name__ == '__main__':
  main()
