# Readme
---

## 1. GatherIntel

GatherIntel is a library containing functions related to network scanning.

### 1.1 Required Imports 

* Python3

* NMAP - can be installed via pip.

* WHOIS - can be installed via pip.

* SQLITE3 - can be installed via pip.

* targetObjects - included in this repository.

* datetime - included in python.

* os - included in python.

* platform - included in python.

* socket - included in python.

* subprocess - included in python.

* sys - included in python.

* time - included in python.

**Please Note: gatherIntel may still work with some of the listed libraries not installed. However, it is recommended to install all the libraries/packages listed while using gatherIntel.**

### 1.2 Important Functions

* **scanCommon**: Function that uses NMAP to scan a target and see whether any of the most commonly used ports are open. Slow, but very accurate.

* **_quickScanCommon**: Function that uses sockets to determine whether any of the most commonly used ports are open. Much faster than NMAP scan.

* **_scanTarget**: Function that uses sockets to scan a range of ports, specified by the user, and determine which ports are open within that range.

* **fingerOS**: Function that uses an open port and NMAP to attempt to determine what Operating System the target machine is running.

---

## 2. targetObjects

### 2.1 Required Imports

* gatherIntel - included in this repository.


### 2.2 Main Class

* **target**: The main class in the function. The subclasses inherit from this class.


### 2.3 Subclasses

* **targetDomain**: A subclass with the domain as the main target,rather than an IP address as the main target.

* **targetIP**: A subclass with the IP address as the main target, rather than a domain name as the main target.

---