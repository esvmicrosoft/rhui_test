# RHUI Test script.

## Goal

Develop a script to test proper configruation and connectivity to the RHUI repositories in Azure.


Required characteristics:

* It must run on RHEL7, 8 and 9.
* It must support EUS, E4S and non-EUS repositories.
* It must not require additional packages other than found in the plain vanilla installations from Marketplace.
**The python OpenSSL module does not come pre-installed by default**


So far this is the list of completed tests:

- RHUI Package installed
- RHUI repo config file must exist.
- Client certificate and key must exist.
- Client certificate expiration time.
- Microsoft Repository (where the rhui package is installed) must be enabled.
- At least one RHUI repository enabled. (where the software is installed)
- The server must be able to download the repomd.xml file from the Microsoft repository and the RHUI ones.


Tests not yet implemented:

Proper DNS resoultuion of the RHUI servers.
Test for 404 conditions.
Valid values for /etc/yum/vars/releasever. (or /etc/dnf/vars....)
Daily cron job file available.
Anacron daemon enabled.

## Usage:

Since RHEL7 does not come with python3 pre-installed, at this time it is required to select the python interpreter manually and the script **must** be executed 
with root privileges.

- RHEL7.x

```
sudo python ./rhui_test.py
```

- RHEL8.x and above

```
sudo python3 ./rhui_test.py
```

*Happy troubleshooting*


