import asyncio
import threading
import time
import re
import os
import yaml
import glob
import json
import argparse
from tabulate import tabulate
from pwn import *

parser = argparse.ArgumentParser()
parser.add_argument('competition', help='Competition file name')
parser.add_argument('--dry-run', action='store_true')
parser.add_argument('--concurrent-teams-per-script', type=int, default=20)
parser.add_argument('--script-timeout', type=int, default=45)
parser.add_argument('--statistics-delay', type=int, default=60)
options = parser.parse_args()

competition_file_name = options.competition.replace('.', '')  # this is not a CTF challenge pls
competition = getattr(__import__('competitions.%s' % competition_file_name), competition_file_name)

competition_data_path = '/tmp/competition.json'

# Fix CTRL+C
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

statistics = {}
def add_statistic(script, statistic):
    global statistics

    if statistic not in statistics:
        statistics[statistic] = {}

    if script not in statistics[statistic]:
        statistics[statistic][script] = 0

    statistics[statistic][script] += 1

# As sending flags is done over a single connection right now, we'll buffer them first to prevent them being a bottleneck.
flag_queue = []  # TODO: flag queue could have a lot of duplicates etc. if the buffer is full
seen = {}
def flag_submitter():
    global flag_queue, seen

    while True:
        if len(flag_queue) < 1:
            time.sleep(1)
            continue

        # TODO: this was implemented lazily, do some checks on our end first on what flags are valid
        if competition.bulk_submit_supported:
            queue_copy = flag_queue.copy()
            flag_queue = []

            flags = []
            script_lookup = {}
            for flag, script in queue_copy:
                if flag in seen:
                    continue
                seen[flag] = True

                flags.append(flag)
                script_lookup[flag] = script
            
            flag_results = competition.submit_flags(flags)
            for flag, result in flag_results.items():
                submission_status, submission_status_raw = result
                if flag in script_lookup:
                    log.info('Flag %s (%s): %s' % (flag, script_lookup[flag], submission_status))

                    add_statistic(script_lookup[flag], submission_status)
                else:
                    log.warn('Flag %s (untracked???): %s' % (flag, submission_status))

            continue

        flag, script = flag_queue[0]
        flag_queue = flag_queue[1:]

        if not re.match(competition.flag_format, flag):
            log.warn('Received invalid flag "%s" (%s), discarding...' % (flag, script))
            continue

        if flag in seen:
            log.debug('Received already seen flag "%s" (%s), discarding...' % (flag, script))
            continue
        seen[flag] = True

        submission_status, submission_status_raw = competition.submit_flag(flag)
        log.info('Flag %s (%s): %s' % (flag, script, submission_status))
        
        add_statistic(script, submission_status)

semaphores = {}
async def run_script(script, team_id):
    global semaphores, statistics

    if script not in semaphores:
        semaphores[script] = asyncio.Semaphore(options.concurrent_teams_per_script)

    sem = semaphores[script]
    async with sem:
        try:
            env = {}
            entrypoint = script
            if os.path.isdir(script):
                exploit_config_path = os.path.join(script, 'kaos.yaml')
                if os.path.exists(exploit_config_path):
                    with open(exploit_config_path, 'r') as fin:
                        exploit_config = yaml.load(fin, Loader=yaml.FullLoader)

                    env['KAOS_BRIDGE_FILE'] = competition_data_path
                    env['KAOS_TEAM_IP'] = team_id
                    env['KAOS_SERVICE_ID'] = exploit_config['service_id']
                    env['KAOS_FLAGSTORE_ID'] = exploit_config['flagstore_id']

                    entrypoint = os.path.join(script, exploit_config['entrypoint'])
                else:
                    entrypoint = os.path.join(script, 'exploit.py')

            process = await asyncio.create_subprocess_exec(
                *[entrypoint, str(team_id), competition_data_path],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
        except Exception as e:
            log.warn('Ran script "%s" for team_id %s, though it failed to spawn:\n%s' % (script, team_id, e))
            add_statistic(script, 'FAULTY_SCRIPT')

            return
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=options.script_timeout)
        except asyncio.exceptions.TimeoutError:
            log.warn('Ran script "%s" for team_id %s, though it has been doing something for too long (>%d seconds), killing...' % (script, team_id, options.script_timeout))

            try:
                process.kill()
            except OSError:  # no such process
                pass

            # TODO: attempt to recover stdout and stderr instead? (too much effort though, as it'll rarely will yield any flags)
            return

        if stderr != b'':
            log.warn('Ran script "%s" for team_id %s, though it returned data in stderr:\n%s' % (script, team_id, stderr.decode().strip()))

        return stdout.decode().strip()

tasks_pool = {}
async def handle_script(script, team_id):
    global tasks_pool

    stdout = await run_script(script, team_id)
    del tasks_pool[script][team_id]

    if stdout is None:
        return

    # TODO: this is a slightly breaking change behavior compared to kaos if someone implements their exploit lazily, possibly just document this behavior?
    for flag in stdout.split('\n'):
        if flag == '':
            continue

        flag_queue.append((flag, script.removeprefix('./scripts/')))

async def exploit_runner(loop):
    global tasks_pool

    while True:
        start = time.time()

        log.info('Fetching competition data...')
        while True:  # a bit ugly but this is required so that `start` is accurate
            try:
                competition_data = competition.get_data()
                break
            except:
                log.warn('Failed getting competition data, trying again in 5 seconds...')
                time.sleep(5)
                continue

        with open(competition_data_path, 'w') as fout:
            fout.write(json.dumps(competition_data))

        if options.dry_run:
            log.info('Running in dry-run mode, skipping running exploits...')
        else:
            log.info('Running exploits...')
            for script in glob.glob('./scripts/*'):
                if not script in tasks_pool:
                    tasks_pool[script] = {}

                log.debug('Handling script "%s"...' % script)
                for team_id in competition_data['teams'].keys():
                    if team_id == competition.our_team_id:
                        continue

                    if team_id in tasks_pool[script]:  # redundant? with properly configured script_timeout this should never be hit
                        log.warn('The script "%s" is still running for team_id %s, either too slow or hanging, skipping...' % (script, team_id))
                        continue

                    tasks_pool[script][team_id] = True
                    loop.create_task(handle_script(script, team_id))

        end = time.time() - start
        diff = round(competition.round_duration - end)
        if diff <= 0:  # redundant? should never be hit unless process spawning is broke?
            # TODO: this should be considered more, e.g. it may make sense to run the exploits less often to reduce them getting logged (though patches will have bigger impact)
            # this also indicates that either the exploits are slow or concurrency values in the config may have to be increased
            log.info('Exploits triggered, though we are running behind by %d seconds.' % abs(diff))
            continue

        log.info('Exploits triggered, repeating in %d seconds.' % diff)
        await asyncio.sleep(diff)

def exploit_runner_wrapper(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(exploit_runner(loop))

def print_statistics():
    global flag_queue

    while True:
        time.sleep(options.statistics_delay)

        if len(statistics.keys()) > 20:
            log.warn('Statistics seem to have too many unique keys (>20), possibly misconfigured flag output?')
            continue

        headers = list(statistics.keys())
        if len(headers) < 1:
            log.warn('No statistics data is available yet...?')
            continue

        headers = ['SCRIPT'] + headers
        data = []
        for script in list(map(lambda x: x.removeprefix('./scripts/'), glob.glob('./scripts/*'))):  # show only active scripts
            row = []

            for header in headers:
                if header == 'SCRIPT':
                    row.append(script)
                    continue

                if script not in statistics[header]:
                    row.append(0)
                    continue

                row.append(statistics[header][script])

            data.append(row)

        print('========================================================')
        print(tabulate(data, headers=headers))
        print('Flag buffer length: %d' % len(flag_queue))
        print('========================================================')

def main():
    log.info('Hello world! Using the competition config "%s"...' % competition.display_name)

    # Fix child watcher not having a loop attached
    # https://stackoverflow.com/a/44698923
    assert threading.current_thread() is threading.main_thread()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    asyncio.get_child_watcher()

    competition.init_submitter()

    threading.Thread(target=exploit_runner_wrapper, args=[loop]).start()
    threading.Thread(target=flag_submitter).start()
    threading.Thread(target=print_statistics).start()

main()
