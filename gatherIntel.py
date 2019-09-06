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
    - ARP
    - SQLite3
Note:
    This must be run as SUDO / root user.
        - sudo python3 gatherIntel.py
        - sudo ./gatherIntel.py
"""

from datetime import datetime
import nmap
import platform
import socket
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
        "nfs_server2" : 2049,
        "KDE_Desktop" : 1024,
        "Kerberos_PWD" : 464,
        "IPP" : 631,
        "KDEConnect" : 1716
        }

targets = ['127.0.0.1']
target = '127.0.0.1'

def addScan(conn,tgt,openPorts,tgtOS):
    """
    Function Name: addScan
    Description:
        Add a new scan to the scan database.
    Input(s):
        conn - database connection. SQLite3 connection object
        tgt - target to add to db (ex: 127.0.0.1). String.
        openPorts - List of DICTs containing target's open ports.
        tgtOS - Operating System of target. String
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

def arpScan(tgtIP):
    """
    Function Name: arpScan
    Description:
        Function to arp-scan a target IP address
        and display MAC Addresses of device(s).
    Input(s):
        tgtIP - target IP address. String.
    Return(s):
        None
    """
    ifaces = checkInterfaces()
    i = 1
    for iface in ifaces:
        print("Interface {0}: {1}".format(i,iface))
        i += 1
    print("")

    try:
        iface_sel = int(input("Select interface number for ARP Scan: "))
        iface_use = ifaces[iface_sel-1]
        _sysINFMSG("Beginning ARP Scan On <{0}> using interface <{1}>".format(tgtIP,iface_use))
    except:
        _sysERRMSG("Something Went Wrong")
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
        _sysSUCMSG("Connected to database < {0} >".format(baseName))
    except Exception as e:
        _sysERRMSG("[!] Something went wrong < {0} >".format(e))
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

def checkInterfaces():
    """
    Function Name: checkInterfaces
    Description:
        Find the network interfaces of system.
    Input(s):
        None
    Return(s):
        ifaces - list of interfaces.
    """
    ifaces = []
    oSys = platform.system()
    linOS = 'Linux'
    winOS = 'Windows'

    if (oSys == linOS):
        for line in open('/proc/net/dev','r'):
            lsplt = line.split(':')
            if (len(lsplt) > 1):
                val = lsplt[0].replace(' ','')
                ifaces.append(val)

    return ifaces

def fingerOS(tgtIP,oPort):
    """
    Function Name: fingerOS
    Description:
        Function to get probable operating system
        of a target IP.
    Input(s):
        tgtIP - target IP address. String.
        oPort - open port to pull info from. Int.
    Return(s):
        osInfo - OS name, Probability. Tuple.
    """
    osName = "Unknown"
    osProb = "0.00 %"
    osInfo = ()

    nm = nmap.PortScanner()

    scan = nm.scan(tgtIP, str(oPort), arguments='-O')

    sc_obj = scan['scan'][tgtIP]['osmatch'][0]
    osName = sc_obj['name']
    osProb = "{0} %".format(sc_obj['accuracy'])

    osInfo += (osName , osProb)
    
    return osInfo

def mainMenu():
    """
    Function Name: mainMenu
    Description:
        Function to display the main menu to the user and
        ask the user to selecet an option.
    Input(s):
        None
    Return(s):
        None
    """
    options = {
            "SCAN TARGET" : 1,
            "FINGERPRINT OS" : 2
            }

    print("Menu Options:")
    _printCHAR('-',20)
    for key,val in options.items():
        print("{0} : {1}".format(val,key))
    print("")

    return

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

def _scanTarget(tgtIP, __portMIN=1, __portMAX=1025):
    """
    Function Name: _scanTARGET
    Inputs:
        tgtIP - IP address of target
        __portMIN - (optional) starting port
        __portMAX - (optional) ending port
    Return Values:
        None
    Functionality:
        Scan a range of Ports specified by the user
        and display which ports are open on the 
        target machine.  A summary of the scan will
        display after it has completed.
    Example:
        _scanTARGET()
        _scanTARGET(__portMIN=10)
        _scanTARGET(__portMAX=100)
        _scanTARGET(_portMIN=10,__portMAX=20)
    """
    nPORTSOPEN = 0
    beginPORT = 1
    endPORT = 1025
    highestPORT = 65535
    openPORTLIST = []
    print("")
    ps = input("Starting Port (leave blank for 1): ")
    pe = input("Ending Port (leave blank for 1025): ")

    """
    Validate Port Start (ps) and Port End (pe)
    """
    if (ps != ""):
        try:
            ps = int(ps)
            __portMIN = abs(ps)
            if (__portMIN > highestPORT):
                __portMIN = highestPORT
                _sysINFMSG("Start Port Exceeds Valid Number. Truncated to {0}".format(highestPORT))
        except ValueError:
            _sysERRMSG("{0} Not A Valid Port. Start Port Remains {1}".format(ps, __portMIN))

    if (pe != ""):
        try:
            pe = int(pe)
            __portMAX = abs(pe)
            if (__portMAX > highestPORT):
                __portMAX = highestPORT
                _sysINFMSG("End Port Exceeds Valid Number. Truncated to {0}".format(highestPORT))
        except ValueError:
            _sysERRMSG("{0} Not A Valid Port. Start Port Remains {1}".format(pe, __portMAX))

    if (__portMIN > __portMAX):
        tmp = __portMAX
        __portMAX = __portMIN
        __portMIN = tmp

    _printCHAR('-',70)
    _sysINFMSG("Scanning Target [{0}] from Port {1} to Port {2}".format(tgtIP, __portMIN, __portMAX))
    _printCHAR('-',70)

    openPorts = 0
    ts = datetime.now()

    try:
        for port in range(__portMIN,__portMAX+1):
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(0.05)
            response = sock.connect_ex((tgtIP,port))
            if (response == 0):
                if (port in common_ports.values()):
                    portUsage = list(common_ports.keys())[list(common_ports.values()).index(port)]
                else:
                    portUsage = "Unknown"
                pstr = "Port {0} ({1})".format(port,portUsage)
                _sysSUCMSG("{0:<20}: OPEN".format(pstr))
                openPORTLIST.append(str(port))
                openPorts += 1
            sock.close()
    except KeyboardInterrupt:
        _sysINFMSG("CTRL+C Pressed. Ending Scan At Port {0}".format(port))
        sock.close()
    except socket.gaierror:
        _sysERRMSG("Hostname could not be resolved")
    except socket.error:
        _sysERRMSG("Could Not Connect To Target")

    te = datetime.now()

    """
    Set up port scan summary variables
    """
    beginPort = __portMIN
    endPort = port
    nPORTSOPEN = str(openPorts)

    if (beginPORT == 1):
        numPorts = (endPort - beginPort) + 1
    else:
        numPorts = endPort - beginPort
    
    """
    Display port scan results to user
    """
    print("\nScan Summary:")
    _printCHAR('-',15)
    _sysINFMSG("Number Of Open Ports: {0}".format(nPORTSOPEN))
    _sysINFMSG("Closed Ports: {0}".format(numPorts-int(nPORTSOPEN)))
    _sysINFMSG("Time Elapsed: {0}\n".format(te-ts))

    """
    Wait for user input and return
    """
    input("Press enter to continue")
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

def _printCHAR(c,n,__newline=True):
    """
    Function Name: _printCHAR
    Inputs:
        c - character to pring
        n - number of times to print (int)
        __newline - (optional) whether to add a newline to the end
    Return Values:
        None
    Functionality:
        Print a specified character n times on
        one line. Useful for making line breaks.
    Example:
        _printCHAR('-',40)
        _printCHAR('-',40,__newline=False)
    """
    print(c*n,end='')
    if (__newline == True):
        print("")
    return

def _sysERRMSG(msg):
    """
    Function Name: _sysERRMSG
    Inputs:
        msg - message to be displayed
    Return Values:
        None
    Functionality:
        Display a formatted error message to the user
    Example:
        _sysERRMSG("There is a problem")
    """
    print("[!] {0:<}".format(msg))
    return


def _sysINFMSG(msg):
    """
    Function Name: _sysINFMSG
    Inputs:
        msg - message to be displayed
    Return Values:
        None
    Functionality:
        Display a formatted informational message to the user
    Example:
        _sysINFMSG("Useful information")
    """
    print("[*] {0:<}".format(msg))
    return


def _sysSUCMSG(msg):
    """
    Function Name: _sysSUCMSG
    Inputs:
        msg - message to be displayed
    Return Values:
        None
    Functionality:
        Display a formatted message to the user indicating success
    Example:
        _sysSUCMSG("Connection Established")
    """
    print("[+] {0:<}".format(msg))
    return


def _sysMSG(msg):
    """
    Function Name: _sysMSG
    Inputs:
        msg - message to be displayed
    Return Values:
        None
    Functionality:
        Display a formatted generic message to the user
    Example:
        _sysMSG("Hello World")
    """
    print("[ ] {0:<80} ...".format(msg))
    return

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

    mainMenu()
    #scanCommon(targets[0])
    _scanTarget(targets[0])
    arpScan(targets[0])
    
    conn = baseConnect()
    if(conn == "FAILED"):
        _sysERRMSG("Database Connection Failed")
    else:
        _sysINFMSG("Database Disconnected")
        conn.close()

    return

if __name__ == '__main__':
    main()
