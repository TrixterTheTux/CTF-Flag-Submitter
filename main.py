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

# Fix CTRL+C
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

# As sending flags is done over a single connection right now, we'll buffer them first to prevent them being a bottleneck.
# TODO: we want to also monitor that this itself isn't bottlenecking seriously or we could be missing flags (some type of statistics?)
flagQueue = []
seen = {}
statistics = {}
def flagSubmitter():
    global flagQueue, seen, statistics

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
        
        if not result in statistics:
            statistics[result] = {}

        if not script in statistics[result]:
            statistics[result][script] = 0

        statistics[result][script] += 1

sem = asyncio.Semaphore(concurrent_scripts)
async def runScript(script, team_id, competition):
    global sem, statistics

    async with sem: # TODO: the semaphore should be instead per-script - we don't want single slow exploit to bottleneck everything else
        try:
            process = await asyncio.create_subprocess_exec(
                *[script, str(team_id), json.dumps(competition)],
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except Exception as e:
            log.warn('Ran script "%s" for team_id %s, though it failed to spawn:\n%s' % (script, team_id, e))

            if not 'FAULTY_SCRIPT' in statistics:
                statistics['FAULTY_SCRIPT'] = {}

            if not script in statistics['FAULTY_SCRIPT']:
                statistics['FAULTY_SCRIPT'][script] = 0

            statistics['FAULTY_SCRIPT'][script] += 1

            return ''
        
        stdout, stderr = await process.communicate()
        if stderr != b'':
            log.warn('Ran script "%s" for team_id %s, though it returned data in stderr:\n%s' % (script, team_id, stderr.decode().strip()))

        return stdout.decode().strip()

async def handleScript(script, team_id, competition):
    stdout = await runScript(script, team_id, competition)

    for flag in stdout.split('\n'):
        flagQueue.append((flag, script))

async def exploitRunner():
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

        log.info('Running exploits...')
        tasks = []
        for script in glob.glob('./scripts/*'):
            log.debug('Handling script "%s"...' % script)
            for team_id in teams:
                tasks.append(handleScript(script, team_id, competition))
        await asyncio.gather(*tasks)

        end = time.time() - start
        diff = round(round_duration - end)
        if diff <= 0:
            # TODO: this should be considered more, e.g. it may make sense to run the exploits less often to reduce them getting logged (though patches will have bigger impact)
            # this also indicates that either the exploits are slow or concurrency values in the config may have to be increased
            log.info('Finished running exploits, though we are running behind by %d seconds.' % abs(diff))
            continue

        log.info('Finished running exploits, repeating in %d seconds.' % diff)
        time.sleep(diff)

def exploitRunnerWrapper(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(exploitRunner())

def printStatistics():
    global statistics

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
        print('========================================================')

def main():
    log.info('Hello world!')

    # Fix child watcher not having a loop attached
    # https://stackoverflow.com/a/44698923
    assert threading.current_thread() is threading.main_thread()
    loop = asyncio.get_event_loop()
    asyncio.get_child_watcher()

    threading.Thread(target=exploitRunnerWrapper, args=[loop]).start()
    threading.Thread(target=flagSubmitter).start()
    threading.Thread(target=printStatistics).start()

main()
