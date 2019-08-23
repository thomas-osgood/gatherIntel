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
import time

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
        "ftp_ssl2" : 990,
        "nfs_lm" : 4045,
        "nfs_client" : 1110,
        "nfs_server1" : 111,
        "nfs_server2" : 2049
        }

targets = ['127.0.0.1']
target = '127.0.0.1'

def addScan(conn,tgt,openPorts):
    """
    Function Name: addScan
    Description:
        Add a new scan to the scan database.
    Input(s):
        conn - database connection. SQLite3 connection object
        tgt - target to add to db (ex: 127.0.0.1). String.
        openPorts - List of DICTs containing target's open ports.
    Return(s):
        None
    """
    tbl = "scans"
    opType = tgtType(openPorts)
    if(len(openPorts) == 0):
        openPorts = "NONE"

    if(checkTable(conn,tbl) == False):
        print("Database Table < {0} > Does Not Exist".format(tbl.upper()))
        return

    timestamp = time.strftime("%Y-%m-%d @ %H:%M:%S GMT", time.gmtime())
    sql = ""
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

def checkTable(conn,tbl):
    """
    Function Name: checkTable
    Description:
        Function to see if database table exists.
    Input(s):
        conn - db connection object.
        tbl - Table to chceck. String.
    Return(s):
        True - database table exists.
        False - database table doesn't exist.
    """
    sql = "SELECT name FROM sqlite_master WHERE name = '{0}'".format(tbl)
    
    cur = conn.cursor()
    cur.execute(sql)

    if(cur.fetchone() is None):
        return False

    return True

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
    
    ttype = tgtType(tgt)
    print(tgt)

    nm = nmap.PortScanner()

    openPorts = []


    if(ttype == "STRING"):
        tgtOS = "Unknown"
        print("\nBeginning NMAP Scan Of {0}\n".format(tgt))

        print("{0:^13}|{1:^8}|{2:^15}|".format("Type","Port","Status"))
        print('-'*39)

        for key, val in common_ports.items():
            print("{0:13}|{1:^8}|".format(key.upper(),val),end='')
            try:
                scan = nm.scan(tgt, str(val), arguments='-O')
                sc_obj = scan['scan'][tgt]

                """
                Check if the host is up before continuing with the output.
                Currently this is not working and just throwing an exception.
                """
                if(sc_obj['status']['state'] != "up"):
                    print("[!] {0} is DOWN... Returning...".format(tgt))
                    return

                print("{0:^15}|".format(sc_obj['tcp'][val]['state']))
                #print('-'*39)
                if((sc_obj['tcp'][val]['state'] == "open") and (tgtOS == "Unknown")):
                    try:
                        tgtOS = "{0} ( {1} % Chance )".format(sc_obj['osmatch'][0]['name'],sc_obj['osmatch'][0]['accuracy'])
                    except:
                        tgtOS = "Unknown"

                if(sc_obj['tcp'][val]['state'] == "open"):
                    openPorts.append({"{0}".format(key.upper()) : "{0}".format(val)})

            except Exception as e:
                print("Something went wrong < {0} >".format(e))
        
        print("-"*39)
        print("\nTarget Operating System : {0}".format(tgtOS))
        
        return
    elif((ttype == "LIST") or (ttype == "TUPLE")):
        for t in tgt:
            tgtOS = "Unknown"
            openPorts.clear()
            print("\nBeginning NMAP Scan Of {0}\n".format(t))

            print("{0:^13}|{1:^8}|{2:^15}|".format("Type","Port","Status"))
            print('-'*39)

            for key, val in common_ports.items():
                print("{0:13}|{1:^8}|".format(key.upper(),val),end='')
                try:
                    scan = nm.scan(t, str(val), arguments='-O')
                    sc_obj = scan['scan'][t]
                    
                    """
                    Check if the host is up before continuing with the output.
                    Currently this is not working and just throwing an exception.
                    """
                    if(not(sc_obj['status']['state'] == "up")):
                        print("[!] {0} is DOWN... Returning...".format(t))
                        continue

                    print("{0:^15}|".format(sc_obj['tcp'][val]['state']))
                    #print('-'*39)
                    if((sc_obj['tcp'][val]['state'] == "open") and (tgtOS == "Unknown")):
                        try:
                            tgtOS = "{0} ( {1} % Chance )".format(sc_obj['osmatch'][0]['name'],sc_obj['osmatch'][0]['accuracy'])
                        except:
                            tgtOS = "Unknown"

                    if(sc_obj['tcp'][val]['state'] == "open"):
                        openPorts.append({"{0}".format(key.upper()) : "{0}".format(val)})

                except Exception as e:
                    print("Something went wrong < {0} >".format(e))
            
            print("-"*39)
            print("\nTarget Operating System : {0}".format(tgtOS))
        return
    else:
        print("[!] INVALID TARGET TYPE")

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
