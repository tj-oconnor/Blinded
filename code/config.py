#!/usr/bin/python
# -*- coding: utf-8 -*-

MYQ = '10.10.4.126'
LYNX = '10.10.4.124'
GEENIE = '10.10.4.123'
IRIS = '10.10.4.122'
SMARTTHINGS = '10.10.4.121'
IVIEW = '10.10.4.115'
WSTEIN = '10.10.4.116'
TUYA   = '10.10.4.125'
DLINK_CAM = '10.10.4.118'
DLINK = '10.10.4.117'
AXEL_CAM = '10.10.4.120'
MERCURY = '10.10.4.119'
WYZE = '10.10.4.112'
WEMO = '10.10.4.101'
CANARY = '10.10.4.105'
RING = "10.10.4.104"
HUE = "10.10.4.103"
NEST = "10.10.4.106"
RING2 = "10.10.4.108"
WYZEV2 = "10.10.4.128"

LOGLIST = []
#LOGLIST.append(WYZEV2)
#LOGLIST.append(MERCURY)
LOGLIST.append(RING)
#LOGLIST.append(RING2)
#LOGLIST.append(SMARTTHINGS)
PCAP = 'telem-ng.pcap'
DEBUG = True

from colorama import Fore, Back, Style

def info(msg):
    print msg


def log(msg):
    print Fore.GREEN + msg + Style.RESET_ALL


def warn(msg):
    print Fore.RED + msg + Style.RESET_ALL


def debug(msg):
    if DEBUG:
        print msg


