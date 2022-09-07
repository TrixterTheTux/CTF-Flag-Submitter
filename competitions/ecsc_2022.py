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
round_duration = 120 # TBD

# How many teams should be targeted at once per script
# the announced ratelimit is ~120 conn/s
# ~1 req/s (estimate which we should enforce ourselves)/flag store, up to 2 flag stores per service, in 5-7 services
# => ~14 req/s/team
concurrent_teams_per_script = 8 # ~14 req/s * 8 teams => 112 req/s

# How often should flag submission statistics be printed in seconds
statistics_delay = 30

# Set to true to submit all flags in once - depends on the competition if this is usually supported
send_flags_in_bulk = False

### CONFIG

our_team_id = 9

conn = remote('10.10.254.254', 31337)
conn.recvline()
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
    return list(filter(lambda team_id: team_id != our_team_id, competition['teams']))