import argparse;

args = ['smth', 'smth2', 'smth3'];
def args_print(*args):
    for printer in args:
        print(printer);  

args_print(*args);