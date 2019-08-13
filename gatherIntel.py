#!/usr/bin/python3
"""
Created By: Thomas Osgood
Program Name: gatherIntel
Description:
    Gather cyber-intelligence on a target machine or list of
    IP addresses.
Requirements:
    - Python3
    - NMAP
    - SQLite3
Note:
    This must be run as SUDO / root user.
"""

import nmap
import sqlite3
import sys

common_ports = {
        "http1" : 80,
        "http2" : 8080,
        "ftp1" : 20,
        "ftp2" : 21,
        "ssh" : 22,
        "telnet" : 23,
        "smtp" : 25,
        "dns" : 53,
        "dhcp1" : 67,
        "dhcp2" : 68,
        "tftp" : 69,
        "pop" : 110,
        "ntp" : 123,
        "netBIOS1" : 137,
        "netBIOS2" : 138,
        "netBIOS3" : 139,
        "imap" : 143,
        "snmp1" : 161,
        "snmp2" : 162,
        "bgp" : 179,
        "ldap" : 389,
        "https" : 443,
        "ldaps" : 636,
        "ftp_ssl1" : 989,
        "ftp_ssl2" : 990
        }

targets = ['127.0.0.1']
target = '127.0.0.1'

def addScan():
    """
    Function Name: addScan
    Description:
        Add a new scan to the scan database.
    Input(s):
        None
    Return(s):
        None
    """
    return

def baseConnect():
    """
    Function Name: baseConnect
    Description:
        Function to connect to the scan database.
    Input(s):
        None
    Return(s):
        conn - connection to the SQLite3 database.
    """
    baseName = "scanDB.db"

    try:
        conn = sqlite3.connect(baseName)
        print("[+] Connected to database < {0} >".format(baseName))
    except Exception as e:
        print("[!] Something went wrong < {0} >".format(e))
        conn = "FAILED"

    return conn

def scanCommon(tgt):
    """
    Function Name: scanCommon
    Description:
        Scan the most commonly used network ports
        on the 'tgt' device.
    Input(s):
        tgt - IP Address to scan. String
    Return(s):
        None
    """
    global common_ports
    nm = nmap.PortScanner()

    tgtOS = "Unknown"

    print("\nBeginning NMAP Scan Of {0}\n".format(tgt))

    print("{0:^10}|{1:^8}|{2:^15}|".format("Type","Port","Status"))
    print('-'*36)

    for key, val in common_ports.items():
        print("{0:10}|{1:^8}|".format(key.upper(),val),end='')
        try:
            scan = nm.scan(tgt, str(val), arguments='-O')
            sc_obj = scan['scan'][tgt]
            #print("Status : {0}".format(sc_obj['tcp'][val]['state']))
            print("{0:^15}|".format(sc_obj['tcp'][val]['state']))
            print('-'*36)
            if((sc_obj['tcp'][val]['state'] == "open") and (tgtOS == "Unknown")):
                try:
                    tgtOS = "{0} ( {1} % Chance )".format(sc_obj['osmatch'][0]['name'],sc_obj['osmatch'][0]['accuracy'])
                except:
                    tgtOS = "Unknown"
        except Exception as e:
            print("Something went wrong < {0} >".format(e))
    
    print("\nTarget Operating System : {0}".format(tgtOS))
    return

def tgtType(tgt):
    """
    Function Name: tgtType
    Description:
        Test the 'target' and return what Python Type
        it is (list, dict, string, etc).
    Input(s):
        tgt - Target to test. No specific type Expected.
    Return(s):
        ttype - Target type in string form.
    """
    ttype = "Unknown"
    test = type(tgt)

    if(test is list):
        ttype = 'list'
    elif(test is dict):
        ttype = 'dictionary'
    elif(test is str):
        ttype = 'string'
    elif(test is tuple):
        ttype = 'tuple'
    else:
        ttype = 'invalid'

    return ttype.upper()

def main():
    """
    Function Name: Main
    Description:
        Main function. Called if the program is not
        being imported.
    Input(s):
        None
    Return(s):
        None
    """
    global targets

    scanCommon(targets[0])

    conn = baseConnect()
    if(conn == "FAILED"):
        print("Database Connection Failed")
    else:
        conn.close()

    return

if __name__ == '__main__':
    main()
