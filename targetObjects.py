#!/usr/bin/python3
"""
Created By: Thomas Osgood
For: gatherIntel.py
Description:
    Library containing the relevant classes for gatherIntel.py
    to operate as intended.
Required Libraries:
    - gatherIntel.py
    - datetime
    - socket
"""
from datetime import datetime
import gatherIntel
import socket
import threading

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

    domain_emails = []
    domain_owner = ""
    domain_org = ""
    domain_renewal = ""

    def __init__(self):
        """
        Function Name: __init__
        Description:
            Function that gets run when the class object is 
            created.
        Input(s):
            self - required for all class functions
        Return(s):
            None
        """
        return

    def __del__(self):
        """
        Function Name: __del__
        Description:
            Function that gets run when the class object is 
            deleted or cleaned up post program.
        Input(s):
            self - required for all class functions.
        Return(s):
            None
        """
        gatherIntel._sysINFMSG("Object Instance {0} Deleted [{1}]".format(self, datetime.now()))
        return

    def getIP(self):
        """
        Function Name: getIP
        Description:
            Function to get the IP address based off
            of a domain name.
        Input(s):
            self - Class' self item (required)
        Return(s):
            target_ip - IP of the target device
        """
        return self.target_ip

    def showTargetInfo(self):
        """
        Function Name: showTargetInfo
        Description:
            Function to display all the information
            collected on the target device.
        Input(s):
            self - Class' self item (required)
        Return(s):
            None
        """
        for key in self.__dict__:
            gatherIntel._sysINFMSG("{0} : {1}".format(key,self.__dict__[key]))
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
            self.__dict__ - dictionary containing all variables.
        """
        return self.__dict__

    def getOperatingSystem(self):
        """
        Function Name: getOperatingSystem
        Description:
            Function to get the operating system information
            stored in the class.
        Input(s):
            self -Class' self item (required)
        Return(s):
            self.operating_system - operating system name
        """
        return self.operating_system

class targetDomain(target):
    """
    Target subclass for a domain.
    Inherits from target baseclass.
    """
    def __init__(self, tgtDomain):
        """
        Function Name: __init__
        Description:
            Function that gets run when the class object is 
            created.
        Input(s):
            self - required for all class functions
            tgtDomain - name of the target domain.
        Return(s):
            None
        """
        self.domain_name = tgtDomain
        self._setDomainVars()
        self.open_ports = []
        self.services = {}
        self.operating_system = gatherIntel.fingerOS(self.target_ip)[0]

        gatherIntel._sysINFMSG("Object Instance {0} Created [{1}]".format(self, datetime.now()))
        return

    def reset(self):
        """
        Function Name: reset
        Description:
            Function to reset the class object and variables.
        Input(s):
            self - required for all class functions
        Return(s):
            None
        """
        new_domain = input("Enter new domain: ")

        if (not (gatherIntel._validateDomain(new_domain))):
            gatherIntel._sysERRMSG("ERROR: DOMAIN NAME NOT VALID. DOMAIN REMAINS {0}".format(self.domain_name))
            return

        self.domain_name = new_domain
        self._setDomainVars()
        return

    def _setDomainVars(self):
        """
        Function Name: _setDomainVars
        Description:
            Function to gather domain information and
            save the info to the related class vars.
        Input(s):
            self - required for all class functions.
        Return(s):
            None
        """
        try:
            domain_info = gatherIntel.getDomainInfo(self.domain_name)
            domain_keys = domain_info.keys()

            try:
                self.target_ip = socket.gethostbyname(self.domain_name)
            except:
                self.target_ip = ""

            self.domain_emails = domain_info["emails"]
            
            if ('updated_date' in domain_keys):
                if (gatherIntel.tgtType(domain_info["updated_date"]) == "LIST"):
                    self.domain_renewal = domain_info["updated_date"][0]
                else:
                    self.domain_renewal = domain_info["updated_date"]
            else:
                self.domain_renewal = ""

            self.domain_org = domain_info["org"]
            self.domain_owner = domain_info["registrar"]

        except Exception as e:
            gatherIntel._sysERRMSG("Something went wrong getting domain information. < {0} >".format(e))
            self.domain_emails = []
            self.domain_org = "Unknown"
            self.domain_owner = "Unknown"
            self.domain_renewal = ""

        return
    
class targetIP(target):
    """
    Target subclass for an IP address.
    Inherits from target baseclass.
    """
    def __init__(self, ipAddr):
        """
        Function Name: __init__
        Description:
            Function that gets run when the class object is 
            created.
        Input(s):
            self - required for all class functions
            ipAddr - target IP address
        Return(s):
            None
        """
        self.domain_emails = []
        self.domain_name = "Unknown"
        self.domain_org = "Unknown"
        self.domain_owner = "Unknown"
        self.domain_renewal = ""
        self.open_ports = []
        self.services = {}

        if (gatherIntel._validateIPv4(ipAddr) == False):
            if (gatherIntel._validateIPv6(ipAddr) == False):
                gatherIntel._sysERRMSG("Invalid IP Address. IP Set To 127.0.0.1")
                self.target_ip = '127.0.0.1'
                self._setDomainVars()
                return
        self.target_ip = ipAddr

        if (gatherIntel._hostOnline(self.target_ip)):
            try:
                self.operating_system = gatherIntel.fingerOS(self.target_ip)[0]
            except:
                self.operating_system = "Unknown"

            self._setDomainVars()
        else:
            gatherIntel._sysERRMSG("HOST NOT ONLINE. TARGET IP CHANGING TO 127.0.0.1")
            self.target_ip = '127.0.0.1'
            self.operating_system = gatherIntel.fingerOS(self.target_ip)[0]
            self._setDomainVars()

        gatherIntel._sysINFMSG("Object Instance {0} Created [{1}]".format(self, datetime.now()))

        return

    def changeIP(self):
        """
        Function Name: changeIP
        Description:
            Function to change and validate the target
            IP address related to this class object.
        Input(s):
            self - required for all class functions
        Return(s):
            None
        """
        new_ip = input("Enter new IP address: ")
        
        if (gatherIntel._validateIPv4(new_ip) == False):
            if (gatherIntel._validateIPv6(new_ip) == False):
                gatherIntel._sysERRMSG("IP Address Invalid. Address Remains {0}".format(self.target_ip))
                return
        else:
            self.target_ip = new_ip
            self.domain_name = socket.gethostname(self.target_ip)
            gatherIntel._sysSUCMSG("IP Address Validated And Successfully Changed To {0}".format(self.target_ip))

        return

    def _setDomainVars(self):
        """
        Function Name: _setDomainVars
        Description:
            Function to gather domain information and
            save the info to the related class vars.
        Input(s):
            self - required for all class functions.
        Return(s):
            None
        """
        try:
            domain_info = gatherIntel.getDomainInfo(self.target_ip)
            domain_keys = domain_info.keys()

            if (gatherIntel.tgtType(domain_info["domain_name"]) == "LIST"):
                self.domain_name = domain_info["domain_name"][0]
            else:
                self.domain_name = domain_info["domain_name"]

            self.domain_emails = domain_info["emails"]
            
            if ('updated_date' in domain_keys):
                if (gatherIntel.tgtType(domain_info["updated_date"]) == "LIST"):
                    self.domain_renewal = domain_info["updated_date"][0]
                else:
                    self.domain_renewal = domain_info["updated_date"]
            else:
                self.domain_renewal = ""

            self.domain_org = domain_info["org"]
            self.domain_owner = domain_info["registrar"]

        except Exception as e:
            gatherIntel._sysERRMSG("Something went wrong getting domain information. < {0} >".format(e))
            self.domain_name = "Unknown"
            self.domain_emails = []
            self.domain_org = "Unknown"
            self.domain_owner = "Unknown"
            self.domain_renewal = ""

        return
