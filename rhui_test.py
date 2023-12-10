#!/bin/env bash

import argparse
import logging
import os
import re
import subprocess
import time
import sys

###########################################################################################
# 
#   Handling whether the RPM exists or not.
#
###########################################################################################


def rpm_name():
    logging.debug("Entering repo_name()")
    result = subprocess.Popen('rpm -qa | grep rhui', shell=True, stdout=subprocess.PIPE)
    rpm_name = result.stdout.read().decode('utf-8').strip()
    if rpm_name:
        return(rpm_name)
    else:
        logging.critical("could not find a specific RHUI package installed, please refer to the documentation and install the apropriate one")
        logging.critical("Consider using the following document to install RHUI support https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-3-rhui-package-is-missing")
        exit(1)

def get_pkg_info(package_name):
    logging.debug("Entering get_pkg_info()")
    pattern = {}
    pattern['clientcert'] = r'^/[/a-zA-Z0-9_\-]+\.(crt)$'
    pattern['clientkey']  = r'^/[/a-zA-Z0-9_\-]+\.(pem)$'
    pattern['repofile']    = r'^/[/a-zA-Z0-9_\-\.]+\.(repo)$'

    logging.debug("Entering pkg_info function")
    try:
        result = subprocess.Popen(['rpm', '-q', '--list', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info = result.stdout.read().decode('utf-8').strip().split('\n')
        
        hash_info = {}
        for key in pattern.keys():
            logging.debug("checking key {}".format(key))
            for data in info:
                logging.debug("checking key {} and data {}".format(key, data))
                if re.match(pattern[key], data):
                    hash_info[key] = data
                    break
    except:
        logging.critical("Failed to grab RHUI RPM details, rebuild RPM database")
        exit(1)

    errors = 0
    for keyname in pattern.keys():
        if keyname not in hash_info.keys():
            logging.critical("{} file definition not found in RPM metadata, {} rpm needs to be reinstalled".format(keyname, package_name))
            errors += 1
        else: 
            if not os.path.exists(hash_info[keyname]):
                logging.critical("{} file not found in server, {} rpm needs to be reinstalled".format(keyname, package_name))
                errors += 1

    if errors:
        logging.critical("follow {} for information to install the RHUI package".format("https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-2-rhui-certificate-is-missing"))
        exit(1)
    else:
        return(hash_info)

def expiration_time(path):
###########################################################################################
# 
# Checks whether client certificate has expired yet or not.
#
###########################################################################################

    logging.debug("Entering expiration_time()")
    logging.debug('Checking certificate expiration time')
    try:
        result = subprocess.check_call('openssl x509 -in {} -checkend 0 > /dev/null 2>&1 '.format(path),shell=True)
    except subprocess.CalledProcessError:
        logging.critical("Client RHUI Certificate has expired, please update the rhui RPM")
        logging.critical("Refer to: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-1-rhui-client-certificate-is-expired")
        exit(1)
    

def check_rhui_repo_file(path):
    logging.debug("Entering check_rhui_repo_file()")
###########################################################################################
# 
# Handling the consistency of the Red Hat repositories
# path: Indicates where the rhui repo is stored.
#
###########################################################################################
    try:
        import ConfigParser as configparser
    except ImportError:
        import configparser

    class localParser(configparser.ConfigParser):

        def as_dict(self):
            d = dict(self.sections)
            for k in d:
                d[k] = dict(self._defaults, **d[k])
                d[k].pop('__name__', None)
            return d

#################################################
# 
#  fixme()
# 
#################################################
    logging.debug("RHUI repo file is {}".format(path))
    try:
        reposconfig = localParser()
        try:
            with open(path) as stream:
                reposconfig.read_string('[default]\n' + stream.read())
        except AttributeError:
            reposconfig.add_section('[default]')
            reposconfig.read(path)

        logging.debug(reposconfig.sections())
        return reposconfig

    except configparser.ParsingError:
        logging.critical("{} does not follow standard REPO config format, reconsider reinstall RHUI rpm and try again".format(path))
        exit(1)

#################################################
# 
#################################################

def check_microsoft_repo(reposconfig):
    logging.debug("Entering microsoft_repo()")
# Checks whether the rhui-microsoft-azure-* repository exists and tests connectivity to it
    rhuirepo = '^(rhui-)?microsoft.*'

    myreponame = ""
    for repo_name in reposconfig.sections():
        if re.match(rhuirepo, repo_name):
           logging.info("Using Microsoft RHUI repository {}".format(repo_name))
           myreponame = repo_name

    if myreponame:
       try:
           enabled =  int(reposconfig.get(myreponame, 'enabled').strip())
           
       except NoOptionError:
           logging.critical("Critical component of the Microsoft Azure RHUI repo not found, consider resinstalling the RHUI Repo")
           exit(1)
       
       if enabled != 1:
           logging.critical('Microsoft RHUI repository not enbaled, please enable it with the following command')
           logging.critical('yum-config-manager --enable {}'.format(repo_name))
           exit(1)
       
       if re.match('.*(eus|e4s).*', myreponame):
           return 1
       else:
           return 0
    else:
        logging.critical("The Microsoft RHUI repo not found, this will lead to problems")
        logging.critical("Follow this document to reinstall the RHUI Repository RPM: {}".format('https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui#image-update-behavior'))
        exit(1)


def connect_to_microsoft_repo(reposconfig):
# downloads repomd.xml from Microsoft RHUI Repo
    
    logging.debug("Entering connect_to_microsoft_repo()")
    rhuirepo = '^rhui-microsoft.*'
    myreponame = ""

    for repo_name in reposconfig.sections():
        if re.match(rhuirepo, repo_name):
           logging.debug("Microsoft repository name is: {}".format(repo_name))
           myreponame = repo_name

    if myreponame:
       try:
           baseurl_info = reposconfig.get(myreponame, 'baseurl').strip().split('\n')
       except NoOptionError:
           logging.critical("Critical component of the Microsoft Azure RHUI repo not found, consider resinstalling the RHUI Repo")
           exit(1)

       try:
           import requests
       except ImportError:
           logging.critical("Unable to import required communication modules, review your python instalation")
           exit(1) 
       
       successes = 0
       for url in baseurl_info:
           url = url+"/repodata/repomd.xml"
           logging.debug("This is one of links supporting the RHUI infrastructure {}".format(url))

           headers = {'content-type': 'application/json'}
           try:
               r = requests.get(url, headers=headers, timeout=5)
           except requests.exceptions.Timeout:
               logging.warning("PROBLEM: Unable to reach RHUI server, https port is blocked for {}".format(url))
           except requests.exceptions.SSLError:
               logging.warning("PROBLEM: MITM proxy misconfiguration. Proxy cannot intercept certs for {}".format(url))
           else:
                successes += 1
                logging.debug("the RC for this {} link is {}".format(url,r.status_code))

       if successes == 0:
           logging.critical("PROBLEM: Cannot communicate with any RHUI server, you must allow at least one of the IP addresses listed here {}".format("https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel9#the-ips-for-the-rhui-content-delivery-servers"))
           sys.exit(1)

def connect_to_rhui_repos(EUS, reposconfig):
# check if EUS or NON-EUS repos are being used correctly.

    logging.debug("Entering connect_to_rhui_repos()")
    import requests

    rhuirepo='^(rhui-)?microsoft.*'
    default='.*default.*'
    basearch = 'x86_64'

    enabled_repos = []
    for repo_name in reposconfig.sections():
       if not re.match(rhuirepo, repo_name) and not re.match(default, repo_name):
           try:
               if reposconfig.get(repo_name, 'enabled').strip() == '1': 
                   logging.info("Repo {} enabled".format(repo_name))
                   enabled_repos.append(repo_name) 
               else:
                   logging.debug("{} repo not enabled".format(repo_name))

           except NoOptionError:
               logging.error(" Repo {} does not have an enabled attribute skipping".format(repo_name))

    if len(enabled_repos) == 0:
        logging.critical("Did not find any enabled repositories in this repo config")
        exit(1)

    releasever=""

    if EUS:
        if os.path.exists('/etc/yum/vars/releasever'):
           fd = open('/etc/yum/vars/releasever')
           releasever = fd.readline().strip()
        else:
           logging.critical('Server is using EUS repostories but /etc/yum/vars/releasever file not found, please correct and test again')
           logging.critical('Refer to: https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms, to select the appropriate RHUI repo')
           exit(1)

    if not EUS:
        if os.path.exists('/etc/yum/vars/releasever'):
            logging.critical('Server is using non-EUS repos and /etc/yum/vars/releasever file found, correct and try again')
            logging.critical('Refer to: https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms, to select the appropriate RHUI repo')
            exit(1)

        try:
            uname = os.uname()
        except:
            logging.critical("Unknown error")
            exit(1)    

        try:
            baserelease = uname.release
        except AttributeError:
            baserelease = uname[2]

        releasever  = re.sub(r'^.*el([0-9][0-9]*).*',r'\1',baserelease)
        if releasever == '7':
            releasever = '7Server'

            

    for myreponame in enabled_repos:
        try:
           baseurl_info = reposconfig.get(myreponame, 'baseurl').strip().split('\n')
        except NoOptionError:
            logging.critical("baseurl of {} not found, consider reinstalling the corresponding RHUI repo".format(myreponame))
            exit(1)

        for url in baseurl_info:
           url = url+"/repodata/repomd.xml"
           url = url.replace('$releasever',releasever)
           url = url.replace('$basearch',basearch)
           logging.debug("baseurl for repo {} is {}".format(myreponame, url))

           headers = {'content-type': 'application/json'}
           try:
               cert=( reposconfig.get(myreponame, 'sslclientcert'), reposconfig.get(myreponame, 'sslclientkey') )
           except:
               logging.critical("Client certificate and/or client key attribute not found for {}, testing connectivity w/o certificates ".format(myreponame))
               cert=()

           successes = 0
           try:
               r = requests.get(url, headers=headers, cert=cert, timeout=5)
               successes += 1
               logging.debug("the RC for this {} link is {}".format(url,r.status_code))
           except requests.exceptions.Timeout:
               logging.warning("PROBLEM: Unable to reach RHUI server, https port is blocked for {}".format(url))
           except requests.exceptions.SSLError:
              logging.warning("PROBLEM: MITM proxy misconfiguration. Proxy cannot intercept certs for {}".format(url))
           except requests.exceptions.RequestException:
                logging.warning("PROBLEM: Unable to establish communication to {}, please allow SSL traffic to it".format(url))

        if successes == 0:
            logging.critical("PROBLEM: Cannot communicate with any RHUI server, you must allow at least one")
            sys.exit(1)


if os.geteuid() != 0:
   logging.critical("This script needs to execute with root privileges\nPlease use: sudo {}".format(sys.argv[0]))
   exit(1)
       
parser = argparse.ArgumentParser()

parser.add_argument(  '--debug','-d',
                      action='store_true',
                      help='Use DEBUG level')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

package_name                             = rpm_name()
data                                     = get_pkg_info(package_name)
expiration_time(data['clientcert'])
reposconfig                              = check_rhui_repo_file(data['repofile'])
eus = check_microsoft_repo(reposconfig)
connect_to_microsoft_repo(reposconfig)
connect_to_rhui_repos(eus, reposconfig)
