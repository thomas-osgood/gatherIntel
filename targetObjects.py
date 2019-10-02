#!/usr/bin/python3
"""
Created By: Thomas Osgood
For: gatherIntel.py
Description:
    Library containing the relevant classes for gatherIntel.py
    to operate as intended.
Required Libraries:
    - gatherIntel.py
"""
import gatherIntel

class target:
    """
    Baseclass for the target subclasses.
    The target subclasses (targetDomain, targetIP)
    will inherit from this class.
    """
    domain_name = ""
    target_ip = ""
    open_ports = []
    services = {}

    def __init__(self):
        pass

    def getIP(self):
        """
        Function Name: getIP
        Description:
            Function to get the IP address based off
            of a domain name.
        Input(s):
            self - Class' self item (required)
        Return(s):
            None
        """
        self.target_ip = ""
        return

    def getDomainInfo(self):
        """
        Function Name: getDomainInfo
        Description:
            Function to get the domain information based
            off of either an IP address of a domain name.
        Input(s):
            self - Class' self item (required)
        Return(s):
            None
        """
        self.domain_name = ""
        return

class targetDomain(target):
    """
    Target subclass for a domain.
    Inherits from target baseclass.
    """
    def __init__(self, tgtDomain):
        self.domain_name = tgtDomain
        return

class targetIP(target):
    """
    Target subclass for an IP address.
    Inherits from target baseclass.
    """
    def __init__(self, ipAddr):
        if (gatherIntel._validateIPv4(ipAddr) == False):
            if (gatherIntel._validateIPv6(ipAddr) == False):
                gatherIntel._sysERRMSG("Invalid IP Address. IP Set To 127.0.0.1")
                self.target_ip = '127.0.0.1'
                return
        self.target_ip = ipAddr
        return

    def __del__(self):
        gatherIntel._sysINFMSG("Object Instance {0} Deleted".format(self))
        return

    def changeIP(self):
        new_ip = input("Enter new IP address: ")
        
        if (gatherIntel._validateIPv4(new_ip) == False):
            if (gatherIntel._validateIPv6(new_ip) == False):
                gatherIntel._sysERRMSG("IP Address Invalid. Address Remains {0}".format(self.target_ip))
                return
        else:
            self.target_ip = new_ip
            gatherIntel._sysSUCMSG("IP Address Validated And Successfully Changed To {0}".format(self.target_ip))

        return
