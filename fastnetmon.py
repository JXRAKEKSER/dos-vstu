#!/usr/bin/env python

import logging
import subprocess
import sys


SERVER = 'mitigator.local'
USER = 'admin'
PASSWORD = 'admin'
EXTRA = ['--no-verify']
LOG = 'fastnetmon-api.log'


def run(*args):
    parts = [
        'fastnetmon_initer.py',
        '--server', SERVER,
        '--user', USER,
        '--password', PASSWORD
    ] + EXTRA + list(args)
    logger.debug('execute %s' % parts)
    subprocess.call(parts)


def policy_by_ip(ip):
    return 1


def countermeasure_by_attack(attack_type, attack_protocol):
    if attack_type == 'syn_flood' or attack_protocol == 'tcp':
        return 'tcp'
    elif attack_type == 'icmp_flood' or attack_protocol == 'icmp':
        return 'acl'
    else:
        return 'sorb'


""" logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler = logging.FileHandler(LOG)
handler.setFormatter(formatter)
logger.addHandler(handler) """

""" logger.info('called with %s' % sys.argv) """
try:
    test_arg = sys.argv[1]
    print(test_arg)
    action = sys.argv[4]
    target = sys.argv[1]
    policy = str(policy_by_ip(target))

    if action == 'unban':
        for countermeasure in ['tcp', 'acl', 'sorb', 'state']:
            run('--policy', policy, countermeasure, 'switch', 'off')

    elif action == 'ban':
        run('--policy', policy, 'state', 'switch', 'on')

    elif action == 'attack_details':
        attack_type = None
        attack_protocol = None
        for line in sys.stdin.readlines():
            if line.startswith('Attack type:'):
                attack_type = line.rsplit(' ', 1)[1].strip()
            elif line.startswith('Attack protocol:'):
                attack_protocol = line.rsplit(' ', 1)[1].strip()

            if attack_type and attack_protocol:
                break

        run('--policy', policy,
            countermeasure_by_attack(attack_type, attack_protocol),
            'switch', 'on')
except Exception as e:
    logger.error(e)