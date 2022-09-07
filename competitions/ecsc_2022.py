import requests
import os
from pwn import *

### CONFIG

# Competition name
name = 'ECSC 2022 (dry-run)'

# Flag validation regex
flag_format = 'ECSC_[A-Za-z0-9\+/]{32}'

# Round duration in seconds
# Alternatively, this can be higher to reduce the amount of times exploits get ran (=> less chance of getting caught/noticed)
round_duration = 120

# How many teams should be targeted at once per script
concurrent_teams_per_script = 10

# How often should flag submission statistics be printed in seconds
statistics_delay = round_duration

# Set to true to submit all flags in once - depends on the competition if this is usually supported
send_flags_in_bulk = False

### CONFIG


conn = remote('10.10.254.254', 31337)
conn.recvline()
conn.recvline()

# Submit flag to the competition's submission server
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

# Submit all flags at once to the competition's submission server
# submitFlags is used only if send_flags_in_bulk is set to True
# should return an array in format of [(flag, result), (flag, result), (flag, result), ...]
def submitFlags(flags):
    pass

# Get the competition data
# should return everything which the exploit scripts should be able to access
def getCompetition():
    response = requests.get('http://10.10.254.254/competition/teams.json', timeout = 5)
    assert response.status_code == 200

    return response.json()

# Get the list of all team IDs to trigger exploits on from the competition data
def getTeamsFromCompetition(competition):
    return competition['teams']