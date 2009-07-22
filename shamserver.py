#!/usr/bin/python
import datetime
import os
import sys
import logging
import hashlib
import socket
import threading
import SocketServer


HOST = '0.0.0.0'
PORT = 31336
min_dist = 999
output_fh = None


class TCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
  pass


class TCPRequestHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    global min_dist
    data = self.request.recv(1024)
    client_host = socket.getfqdn(self.client_address[0])

    client_hash = hashlib.sha1(data)
    distance = hamming_distance(client_hash, challenge_hash)

    if distance < min_dist:
      logging.info('[%s] distance: %d' % (client_host, distance))
      logging.info('[%s] phrase: %s' % (client_host, data))
      min_dist = distance


def hamming_distance(sha1, sha2):
  d = 0
  for i in range(20):
    x = sha1.digest()[i]
    y = sha2.digest()[i]
    v = ord(x) ^ ord(y)
    while v:
      d += 1
      v &= v - 1
  return d


def main():
  global challenge_hash
  global output_fh

  log_format = "%(asctime)s - %(message)s"
  logging.basicConfig(level=logging.INFO,
                      format=log_format,
                      filename='results',
                      filemode='a')
  console_logger = logging.StreamHandler()
  console_logger.setFormatter(logging.Formatter(log_format))
  logging.getLogger('').addHandler(console_logger)
  logging.info('*** shamserver starting ***')

  if len(sys.argv) == 1:
    print 'usage: %s <challenge phrase>' % sys.argv[0]
    sys.exit(1)

  phrase = ' '.join(sys.argv[1:])
  challenge_hash = hashlib.sha1(phrase)
  logging.info('challenge phrase: %s' % phrase)
  logging.info('challenge hash: %s' % challenge_hash.hexdigest())

  # start tcp server
  server = TCPServer((HOST, PORT), TCPRequestHandler)
  server.serve_forever()


if __name__ == '__main__':
  main()
