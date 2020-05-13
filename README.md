# About

This is a collection of Python3 scripts to make some particular tasks easier to handle with [QuoLab](https://quolab.com).
It also should help others to learn on using [pyquo](https://github.com/quolab/pyquo) to script tasks with [QuoLab](https://quolab.com).

## Prerequisites

The common denomitator for these scripts to run properly is to have QuoLab REST client package 'pyquo' installed.
The simplest way to get pyquo installed is through pip, for instance for python3 run:
```
pip3 install pyquo
```
You also can find the latest master directy on [QuoLab's github](https://github.com/quolab/pyquo)
Each script have individual requirements, we suggest you check the script imports or give a run to figure.

# ATTCKgroups.py

That script aims at importing [MITRE ATT\&CK groups](https://attack.mitre.org/groups/) as cases into QuoLab.

MITRE is [distributing and maintaining](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via) these intrusion sets, which thanks to [Cyb3rWard0d](https://github.com/Cyb3rWard0g) can directly be used in your python code through the [attackcti package](https://github.com/hunters-forge/ATTACK-Python-Client)

The script will basically will create for each intrusion set a case with the following:
* The case name will be the one of the threat actor, including aliases in parenthesis
* The case will be tagged using the ATT\&CK techniques listed along with the intrusion set
* The case will be popupated with Malware facts listed as ATT\&CK softwares along with the intrusion set
* Each external reference will be used to create folders within the case, the reference URL will be added to the folder
* For external references leading to a PDF document, the document will be stored into the folder as well parsed for indicators, which would also be added to the folder

## Usage

The script should be ran directly from commandline using python3, host and creds parameters are mandatory.
The filter parameter can be used to specify some particular intrusion set, if not set all sets will be imported.

```
$ python3 ./ATTCKgroups.py --help
usage: ATTCKgroups.py [-h] --host HOST --creds CREDS [--filter FILTER]

QuoLab importer for MITRE ATT&CK groups intrusiton set

optional arguments:
  -h, --help       show this help message and exit
  --host HOST      https://qlab.quo
  --creds CREDS    username:password
  --filter FILTER  apt1,...
```

# Acknowledgments

* Hat tip to the [QuoLab](https://quolab.com) for the hard work
* All the inspiration from the InfoSec community over the years
* The amazing work from the [ATT\&CK](https://attack.mitre.org) folks and contributors
