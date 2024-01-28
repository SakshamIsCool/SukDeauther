#!/usr/bin/python2.7
# -*- Made by saksham  -*-

from py.Configuration import Configuration
from py.Scanner import Scanner
from py.Color import Color
from py.AttackWEP import AttackWEP
from py.AttackWPA import AttackWPA
from py.AttackWPS import AttackWPS

import os

def main():
    ''' Either performs action based on arguments, or starts attack scanning '''

    if os.getuid() != 0:
        Color.pl('{!} {R}error: {O}Deauth{R} must be run as {O}root{W}')
        Color.pl('{!} {O}re-run as: sudo python2 deauth.py{W}')
        Configuration.exit_gracefully(0)

    Configuration.initialize(load_interface=False)

    Configuration.get_interface()
    run()

def run():
    '''
        Main program.
        1) Scans for targets, asks the user to select targets
        2) Attacks each target
    '''
    s = Scanner()
    if s.target:
        # We found the target we want
        targets = [s.target]
    else:
        targets = s.select_targets()

    try:
        while True:
            for index, t in enumerate(targets):
                Color.pl('\n{+} ({G}%d{W}/{G}%d{W})' % (index + 1, len(targets)) +
                        ' starting attacks against {C}%s{W} ({C}%s{W})'
                        % (t.bssid, t.essid if t.essid_known else "{O}ESSID unknown"))
                if 'WEP' in t.encryption:
                    attack = AttackWEP(t)
                elif 'WPA' in t.encryption:
                    if t.wps:
                        attack = AttackWPS(t)
                    else:
                        attack = AttackWPA(t)
                else:
                    Color.pl("{!} {R}Error: {O}unable to attack: encryption not WEP or WPA")
                    continue

                try:
                    attack.run()
                except Exception as e:
                    Color.pl("\n{!} {R}Error: {O}%s" % str(e))
                except KeyboardInterrupt:
                    Color.pl('\n{!} {O}interrupted{W}\n')
                    raise  # Re-raise the KeyboardInterrupt to trigger the exit handling

    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Cleaning up and exiting...{W}')
        
        Configuration.exit_gracefully(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}interrupted, shutting down...{W}')
        Configuration.exit_gracefully(0)
