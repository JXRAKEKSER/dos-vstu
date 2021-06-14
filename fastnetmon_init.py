import subprocess;
import random
import sys;

attack_type_list = ['syn_flood', 'icmp_flood', 'else'];
action_type_list = ['ban', 'unban', 'attack_details'];
attack= 'Attack type: ';
action = random.choice(action_type_list)
attack_protocol = None
attack+= random.choice(attack_type_list)
attack_details_list = [None, None]
if((attack.rsplit(' ',1)[1] == 'syn_flood')): 
    attack_protocol = 'Attack protocol: tcp'
elif((attack.rsplit(' ',1)[1]) == 'icmp_flood'):
     attack_protocol = 'Attack protocol: acl'
else:
    attack_protocol = 'Attack protocol: sorb'

if(action == 'attack_details'):
    attack_details_list = [attack, attack_protocol]
    args = ['fastnetmon.py', '94.233.56.171', action, attack_details_list[0], attack_details_list[1]]
    print('add attack details')
else:
    args = ['fastnetmon.py', '94.233.56.171', action]

pipe = subprocess.PIPE
proc = subprocess.Popen(args, shell=True, stdin=pipe, encoding='utf-8')
res = proc.communicate(attack+'\n'+attack_protocol)[0]
