import requests
import os
from pwn import *

conn = remote('127.0.0.1', 1337)
conn.recvline()
conn.recvline()

# submitFlag is used only if send_flags_in_bulk is set to False
def submitFlag(flag):
    try:
        conn.send(flag.encode() + b'\n')
        result = conn.recvuntil(b'\n').decode().strip()

        # This should return a short string, which will be then be showed in statistics as the sum of all flag outputs (e.g. `OK`: 5, `ERR`: 12232)
        return result.split(' ')[1]
    except EOFError:
        # TODO: some sort of retry mechanism?
        log.warn('Received EOF when trying to submit a flag, assuming the submission server is dead. Exiting...')
        os._exit(1)

# submitFlags is used only if send_flags_in_bulk is set to True
# should return an array in format of [(flag, result), (flag, result), (flag, result), ...]
def submitFlags(flags):
    pass

def getCompetition():
    response = requests.get('http://127.0.0.1:1338/scoreboard/attack.json', timeout = 5)
    assert response.status_code == 200

    return response.json()

def getTeamsFromCompetition(competition):
    return competition['availableTeams']