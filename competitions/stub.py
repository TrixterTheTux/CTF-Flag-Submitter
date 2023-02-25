from pwn import *
from submitter.flag_handler import SubmissionStatus

# NOTE: This format is designed for kaos - most of these are not used in CTF-Flag-Submitter

display_name = 'Stub'

# Regex that can be used to detect valid flags
flag_format = 'FLAG_[A-Za-z0-9\+/]{32}'

# Round duration in seconds
round_duration = 60

# Flag lifetime in rounds
flag_lifetime = 5

# The ID (i.e. IP) of our team, this will mean that no exploits will be ran against this team.
our_team_id = '127.0.0.1'

# The ID (i.e. IP) of the NOP team, this will mean that any local runs will automatically target this team,
# unless this value is set to `None`.
nop_team_id = '127.0.0.1'

# If enabled, this will also allow targeting this team which would be useful if there's no dedicated NOP team.
run_exploits_on_nop_team = False

# If the submission server supports bulk submissions, prefer that method.
bulk_submit_supported = False

# The preferred amount of flags to submit at once per flag submission
bulk_chunk_size = 32

def get_data():
    return {
        'teams': {
            'team_ip': 'Team Name',
        },
        'services': {
            'service_id': {
                'name': 'Service Name',
                # Optional:
                'flagstores': ['flagstore_id', 'flagstore_id'],
            },
        },
        'flag_ids': {
            'team_ip': {
                'service_id': {
                    'flagstore_id': ['flag_id', 'flag_id'],
                }
            }
        }
    }

def get_scoreboard_data():
    # Alternatively, return an empty dict if you don't want to implement this/use monitoring
    return {
        'tick': 0,
        'scoreboard': [
            {
                'team_ip': '127.0.0.1',
                'team_name': 'No place like home!',
                'points': 1337,
                'rank': 1,
                'services': [
                    {
                        'service_id': 'service_1',
                        'offense': 0,
                        'defense': 0,
                        'sla': 0,
                        'gathered_flags': 1337,
                        'lost_flags': 0,
                        'online': True,
                    }
                ],
            }
        ]
    }

conn = null
def init_submitter():
    global conn

    conn = remote('127.0.0.1', 1337)
    conn.recvline()
    conn.recvline()

def submit_flag(flag):
    global conn

    conn.send(flag.encode() + b'\n')
    result = conn.recvuntil(b'\n').decode().strip()

    # should return one of SubmissionStatus.{Ok, Dup, Own, Old, Inv, Err} and the raw response itself
    return {
        'OK': SubmissionStatus.Ok,
        'DUP': SubmissionStatus.Dup,
        'OWN': SubmissionStatus.Own,
        'OLD': SubmissionStatus.Old,
        'INV': SubmissionStatus.Inv,
        'ERR': SubmissionStatus.Err,
    }[result.split(' ')[1]], result

def submit_flags(flags):
    # Similar output to submit_flag(), but should be wrapped in a dict with the format of 'flag_id': (SubmissionStatus.{...}, raw)
    pass
