import socket
import os
from subprocess import Popen, PIPE, STDOUT
import sys


def validate_cert(cert) -> bool:
   print('Validating certificate request')


def fork_connection():
    cmd = './auth/cert ca.key ca.pem'
    validation_process = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = validation_process.communicate()
    if stderr is not None:
        print(stderr, file=sys.stderr)
        return False
        os._exit(1)
    else:
        return validate_cert(stdout)


def server_loop():
    s = socket.socket()
    port = 8080
    s.bind(('', port))

    # Allow for 10 connections at any given time
    s.listen(10)

    while True:
        client, addr = s.accept()
        print('Got connection from: {}'.format(addr))
        print('Validating certificate request')
        client.send('Validating....')
        if fork_connection:
            client.send('Validation successful! Closing conneciton')
            client.close()
        else:
            client.send('Validation failed! Closing connection')
            client.close()
