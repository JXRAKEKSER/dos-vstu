import argparse
import subprocess
import sys;
import argparse;
""" args = ['smth', 'smth2', 'smth3'];
def args_print(*args):
    for printer in args:
        print(printer);  

args_print(*args); """
get_run = sys.argv
print(get_run)

def parse_args():
    def add_switch(root):
        switch = root.add_parser('switch')
        states = switch.add_subparsers(dest='state')
        states.add_parser('on')
        states.add_parser('off')

    def add_countermeasure(root, name):
        countermeasure = root.add_parser(name)
        actions = countermeasure.add_subparsers(dest='action')
        add_switch(actions)
        return actions

    parser = argparse.ArgumentParser()

    parser.add_argument('--server', required=True, help='Mitigator host')
    parser.add_argument('--user', required=True, help='Mitigator login')
    parser.add_argument('--password', required=True, help='Mitigator password')
    parser.add_argument('--policy', help='policy ID (as shown in URL)', type=int)
    parser.add_argument('--no-verify', help='disable TLS certificate validation', action='store_true')

    tools = parser.add_subparsers(dest='tool')

    tbl = tools.add_parser('tbl')
    subs = tbl.add_subparsers(dest='action')

    block = subs.add_parser('block')
    block.add_argument('-i', '--ip', required=True, help='IP address to block')
    block.add_argument('-t', '--time', required=True, help='block time in seconds', type=int)

    unblock = subs.add_parser('unblock')
    unblock.add_argument('-i', '--ip', required=True, help='IP address to unblock')

    add_countermeasure(tools, 'tcp')
    add_countermeasure(tools, 'acl')
    add_countermeasure(tools, 'sorb')

    add_countermeasure(tools, 'state')

    return parser.parse_args()

if __name__ == '__main__':
   option = parse_args()
   print(option.user)
   mitigator_params = ['mitigator.py', str(option.action), str(option.no_verify), str(option.password), str(option.policy), str(option.server), str(option.state),
   str(option.tool), str(option.user)]
   subprocess.call(mitigator_params, shell=True)
