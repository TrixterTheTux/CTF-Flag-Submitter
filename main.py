import asyncio
import threading
import time
import re
import glob
import json
from tabulate import tabulate
from pwn import *
from config import *
from competition import submitFlag, getCompetition, getTeamsFromCompetition

competition_data_path = '/tmp/competition.json'

# Fix CTRL+C
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

statistics = {}
def addStatistic(script, statistic):
    global statistics

    if not statistic in statistics:
        statistics[statistic] = {}

    if not script in statistics[statistic]:
        statistics[statistic][script] = 0

    statistics[statistic][script] += 1

# As sending flags is done over a single connection right now, we'll buffer them first to prevent them being a bottleneck.
flagQueue = []
seen = {}
def flagSubmitter():
    global flagQueue, seen

    while True:
        if len(flagQueue) < 1:
            time.sleep(1)
            continue

        flag, script = flagQueue[0]
        flagQueue = flagQueue[1:]

        if not re.match(flag_format, flag):
            log.debug('Received invalid flag "%s", discarding...' % flag)
            continue

        if flag in seen:
            log.debug('Received already seen flag "%s", discarding...' % flag)
            continue
        seen[flag] = True

        result = submitFlag(flag)
        log.info('Flag %s: %s' % (flag, result))
        
        addStatistic(script, result)

semaphores = {}
async def runScript(script, team_id):
    global semaphores, statistics

    if not script in semaphores:
        semaphores[script] = asyncio.Semaphore(concurrent_teams_per_script)

    sem = semaphores[script]
    async with sem:
        try:
            process = await asyncio.create_subprocess_exec(
                *[script, str(team_id), competition_data_path],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except Exception as e:
            log.warn('Ran script "%s" for team_id %s, though it failed to spawn:\n%s' % (script, team_id, e))
            addStatistic(script, 'FAULTY_SCRIPT')

            return ''
        
        stdout, stderr = await process.communicate()
        if stderr != b'':
            log.warn('Ran script "%s" for team_id %s, though it returned data in stderr:\n%s' % (script, team_id, stderr.decode().strip()))

        return stdout.decode().strip()

tasksPool = {}
async def handleScript(script, team_id):
    global tasksPool

    stdout = await runScript(script, team_id)

    for flag in stdout.split('\n'):
        flagQueue.append((flag, script))

    del tasksPool[script][team_id]

async def exploitRunner(loop):
    global tasksPool

    while True:
        start = time.time()

        log.info('Fetching competition data...')
        while True: # a bit ugly but this is required so that `start` is accurate
            try:
                competition = getCompetition()
                teams = getTeamsFromCompetition(competition)
                break
            except:
                log.warn('Failed getting competition data, trying again in 5 seconds...')
                time.sleep(5)
                continue

        with open(competition_data_path, 'w') as fout:
            fout.write(json.dumps(competition))

        log.info('Running exploits...')
        for script in glob.glob('./scripts/*'):
            if not script in tasksPool:
                tasksPool[script] = {}

            if len(tasksPool[script].keys()) > 0:
                log.warn('The script %s still has queued teams, either too slow or hanging, skipping...' % script)
                continue

            log.debug('Handling script "%s"...' % script)
            for team_id in teams:
                tasksPool[script][team_id] = True
                loop.create_task(handleScript(script, team_id))

        end = time.time() - start
        diff = round(round_duration - end)
        if diff <= 0:
            # TODO: this should be considered more, e.g. it may make sense to run the exploits less often to reduce them getting logged (though patches will have bigger impact)
            # this also indicates that either the exploits are slow or concurrency values in the config may have to be increased
            log.info('Finished running exploits, though we are running behind by %d seconds.' % abs(diff))
            continue

        log.info('Started running exploits, repeating in %d seconds.' % diff)
        await asyncio.sleep(diff)

def exploitRunnerWrapper(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(exploitRunner(loop))

def printStatistics():
    global flagQueue

    while True:
        time.sleep(statistics_delay)

        if len(statistics.keys()) > 20:
            log.warn('Statistics seem to have too many unique keys (>20), possibly misconfigured flag output?')
            continue

        headers = list(statistics.keys())
        if len(headers) < 1:
            log.warn('No statistics data is available yet...?')
            continue

        headers = ['SCRIPT'] + headers
        data = []
        for script in glob.glob('./scripts/*'): # show only active scripts
            row = []

            for header in headers:
                if header == 'SCRIPT':
                    row.append(script)
                    continue

                if not script in statistics[header]:
                    row.append(0)
                    continue

                row.append(statistics[header][script])

            data.append(row)

        print('========================================================')
        print(tabulate(data, headers=headers))
        print('Flag buffer length: %d' % len(flagQueue))
        print('========================================================')

def main():
    log.info('Hello world!')

    # Fix child watcher not having a loop attached
    # https://stackoverflow.com/a/44698923
    assert threading.current_thread() is threading.main_thread()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    asyncio.get_child_watcher()

    threading.Thread(target=exploitRunnerWrapper, args=[loop]).start()
    threading.Thread(target=flagSubmitter).start()
    threading.Thread(target=printStatistics).start()

main()
