# CTF Flag Submitter

## Configuring for CTF

You can find an example competition file in `competitions/mock.py`, which you can use as a template for your own `competitions/[competition name].py` file.

## Adding exploit scripts

The flag submitter handles concurrency and the flag submission, all that is needed is to place your exploit script in the `scripts/` folder with the appropriate shebang line, and it'll be executed automatically in the format of `./script [team_id] [path to a file with json-encoded competition data]`. The script should print flags to stdout separated by a newline which will then be automatically submitted if the output hasn't ever been seen before and matches the flag format.

Note that you don't need to ever restart the flag submitter process (unless the submission server dies), the scripts will be automatically detected.

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

You can install the project's dependencies with `pip3 install -r requirements.txt`. Then, to start up the project all you need to run is `python3 ./main.py [competition name]`.

In some cases the project can exit, for example if the submission server was down. Due to this, it may make sense to set this up as a systemd service instead or monitor it actively that it still works.

To enable debug mode, you can have the magic `DEBUG` argument in argv.