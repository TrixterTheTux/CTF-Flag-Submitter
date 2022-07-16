# CTF Flag Submitter

## Configuring for CTF

You can find a generic config file in `config.py`, you'll also have to modify `competition.py` to work with the specific CTF.

## Adding exploit scripts

The flag submitter handles concurrency and the flag submission, all that is needed is to place your exploit script in the `scripts/` folder with the appropriate shebang line, and it'll be executed automatically in the format of `./script [team_id] [json-encoded competition data]`. The script should print flags to stdout separated by a newline which will then be automatically submitted if the output hasn't ever been seen before and matches the flag format.

Note that you don't need to ever restart the flag submitter process, the scripts will be automatically detected.

Sample exploit script written in python:
```py
#!/usr/bin/python3

import sys
import json
import time
import string
import random

team_id = sys.argv[1]
with open(sys.argv[2], 'r') as fin:
    competition = json.loads(fin.read())

time.sleep(2)

print('TEST_' + ''.join(random.choice(string.ascii_letters) for i in range(32)))
```

## Running the project

You can start up the project with `pipenv run python3 ./main.py`. If you don't have `pipenv`, it can be installed easily with `pip install pipenv`.

In some cases the project can exit, for example if the submission server was down. Due to this, it may make sense to set this up as a systemd service instead or monitor it actively that it still works.

To enable debug mode, you can have the magic `DEBUG` argument in argv.