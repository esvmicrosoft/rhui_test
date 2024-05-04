#!/bin/env bash

import argparse
import logging
import os
import re
import subprocess
import time
import sys
rhui3 = ['13.91.47.76', '40.85.190.91', '52.187.75.218']
rhui4 = ['52.136.197.163', '20.225.226.182', '52.142.4.99', '20.248.180.252', '20.24.186.80']
rhuius = ['13.72.186.193', '13.72.14.155', '52.224.249.194']


try:
    import ConfigParser as configparser
except ImportError:
    import configparser


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


try:
    import ConfigParser as configparser
except ImportError:
    import configparser

###########################################################################################
# 
#   Handling whether the RPM exists or not.
#
###########################################################################################
rhui3 = ['13.91.47.76', '40.85.190.91', '52.187.75.218']
rhui4 = ['52.136.197.163', '20.225.226.182', '52.142.4.99', '20.248.180.252', '20.24.186.80']
rhuius = ['13.72.186.193', '13.72.14.155', '52.224.249.194']

def rpm_names():
    logging.debug('{} Entering repo_name() {}'.format(bcolors.BOLD, bcolors.ENDC))
    result = subprocess.Popen('rpm -qa | grep rhui', shell=True, stdout=subprocess.PIPE)
    rpm_names = result.stdout.readlines()
    rpm_names = [ rpm.decode('utf-8').strip() for rpm in rpm_names ]
    if rpm_names:
        for rpm in rpm_names:
            logging.debug('{}Server has this RHUI pkg: {}{}'.format(bcolors.BOLD, rpm, bcolors.ENDC))
        return(rpm_names)
    else:
        logging.critical('{} could not find a specific RHUI package installed, please eefer to the documentation and install the apropriate one {}'.format(bcolors.FAIL, bcolors.ENDC))
        logging.critical('{} Consider using the following document to install RHUI support https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-3-rhui-package-is-missing {}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1) 

def get_pkg_info(package_name):
    logging.debug('{} Entering get_pkg_info() {}'.format(bcolors.BOLD, bcolors.ENDC))
    pattern = {}
    pattern['clientcert'] = r'^/[/a-zA-Z0-9_\-]+\.(crt)$'
    pattern['clientkey']  = r'^/[/a-zA-Z0-9_\-]+\.(pem)$'
    pattern['repofile']    = r'^/[/a-zA-Z0-9_\-\.]+\.(repo)$'

    logging.debug('{} Entering pkg_info function {}'.format(bcolors.BOLD, bcolors.ENDC))
    try:
        result = subprocess.Popen(['rpm', '-q', '--list', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info = result.stdout.read().decode('utf-8').strip().split('\n')
        
        hash_info = {}
        for key in pattern.keys():
            logging.debug('{} checking key {} {}'.format(bcolors.BOLD, key, bcolors.ENDC))
            for data in info:
                logging.debug('{} checking key {} and data {} {}'.format(bcolors.BOLD, key, data, bcolors.ENDC))
                if re.match(pattern[key], data):
                    hash_info[key] = data
                    break
    except:
        logging.critical('{}Failed to grab RHUI RPM details, rebuild RPM database{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1)

    errors = 0
    for keyname in pattern.keys():
        if keyname not in hash_info.keys():
            logging.critical('{}{} file definition not found in RPM metadata, {} rpm needs to be reinstalled{}'.format(bcolors.FAIL, keyname, package_name, bcolors.ENDC))
            errors += 1
        else: 
            if not os.path.exists(hash_info[keyname]):
                logging.critical('{}{} file not found in server, {} rpm needs to be reinstalled{}'.format(bcolors.FAIL, keyname, package_name, bcolors.ENDC))
                errors += 1

    if errors:
        logging.critical('{}follow {} for information to install the RHUI package{}'.format(bcolors.FAIL,"https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-2-rhui-certificate-is-missing", bcolors.ENDC))
        exit(1)
    else:
        return(hash_info)

def default_policy():
# returns a boolean whether the default encryption policies are set to default via the /etc/crypto-policies/config file, if it can't test it, the result will be set to true.

    try:
        uname = os.uname()
    except:
        logging.critical('{} Unable to identify OS version{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1)    

    try:
        baserelease = uname.release
    except AttributeError:
        baserelease = uname[2]

    releasever  = re.sub(r'^.*el([0-9][0-9]*).*',r'\1',baserelease)

    # return true for EL7
    if releasever == '7':
        return True

    try:
        policy = subprocess.check_output('/bin/update-crypto-policies --show', shell=True)
        policy = policy.decode('utf-8').strip()
        if policy != 'DEFAULT':
            return False
    except:
        return True

    return True

def expiration_time(path):
###########################################################################################
# 
# Checks whether client certificate has expired yet or not.
#
###########################################################################################

    logging.debug('{} Entering expiration_time(){}'.format(bcolors.BOLD, bcolors.ENDC))
    logging.debug('{}Checking certificate expiration time{}'.format(bcolors.BOLD, bcolors.ENDC))
    try:
        result = subprocess.check_call('openssl x509 -in {} -checkend 0 > /dev/null 2>&1 '.format(path),shell=True)

    except subprocess.CalledProcessError:
        logging.critical('{}Client RHUI Certificate has expired, please update the rhui RPM{}'.format(bcolors.FAIL, bcolors.ENDC))
        logging.critical('{}Refer to: https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-1-rhui-client-certificate-is-expired{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1)

    if not default_policy():
        logging.critical('{}Client crypto policies not set to DEFAULT{}'.format(bcolors.FAIL, bcolors.ENDC))
        logging.critical('{}Refer to: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?tabs=rhel7-eus%2Crhel7-noneus%2Crhel7-rhel-sap-apps%2Crhel8-rhel-sap-apps%2Crhel9-rhel-sap-apps#cause-5-verification-error-in-rhel-version-8-or-9-ca-certificate-key-too-weak{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1) 

def check_rhui_repo_file(path):
    logging.debug('{}Entering check_rhui_repo_file(){}'.format(bcolors.BOLD, bcolors.ENDC))
###########################################################################################
# 
# Handling the consistency of the Red Hat repositories
# path: Indicates where the rhui repo is stored.
#
###########################################################################################
    class localParser(configparser.ConfigParser):

        def as_dict(self):
            d = dict(self.sections)
            for k in d:
                d[k] = dict(self._defaults, **d[k])
                d[k].pop('__name__', None)
            return d

    logging.debug('{}RHUI repo file is {}{}'.format(bcolors.BOLD, path, bcolors.ENDC))
    try:
        reposconfig = localParser()
        try:
            with open(path) as stream:
                reposconfig.read_string('[default]\n' + stream.read())
        except AttributeError:
            reposconfig.add_section('[default]')
            reposconfig.read(path)

        logging.debug('{} {} {}'.format(bcolors.BOLD, str(reposconfig.sections()), bcolors.ENDC))
        return reposconfig

    except configparser.ParsingError:
        logging.critical('{}{} does not follow standard REPO config format, reconsider reinstall RHUI rpm and try again{}'.format(bcolors.FAIL, path, bcolors.ENDC))
        exit(1)

#################################################
# 
#################################################
def check_microsoft_repo(reposconfig):
    logging.debug('{}Entering microsoft_repo(){}'.format(bcolors.BOLD, bcolors.ENDC))
# Checks whether the rhui-microsoft-azure-* repository exists and tests connectivity to it
    rhuirepo = '^(rhui-)?microsoft.*'
    myreponame = ''

    for repo_name in reposconfig.sections():
        if re.match(rhuirepo, repo_name):
           logging.info('{}Using Microsoft RHUI repository {}{}'.format(bcolors.OKGREEN, repo_name, bcolors.ENDC))
           myreponame = repo_name

    if myreponame:
       try:
           enabled =  int(reposconfig.get(myreponame, 'enabled').strip())
           
       except configparser.NoOptionError:
           enabled = 1
       
       if enabled != 1:
           logging.critical('{}Microsoft RHUI repository not enbaled, please enable it with the following command{}'.format(bcolors.FAIL, bcolors.ENDC))
           logging.critical('{}yum-config-manager --enable {}{}'.format(bcolors.FAIL, repo_name, bcolors.ENDC))
           exit(1)
       else:
            logging.debug('{}Server is using {} repository and it is enabled{}'.format(bcolors.BOLD, repo_name, bcolors.ENDC))

    else:
        logging.critical('{}The Microsoft RHUI repo not found, this will lead to problems{}'.format(bcolors.FAIL, bcolors.ENDC))
        logging.critical('{}Follow this document to reinstall the RHUI Repository RPM: {}{}'.format(bcolors.FAIL, 'https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui#image-update-behavior', bcolors.ENDC))
        exit(1)


def connect_to_microsoft_repo(reposconfig):
# downloads repomd.xml from Microsoft RHUI Repo
    logging.debug('{}Entering connect_to_microsoft_repo(){}'.format(bcolors.BOLD, bcolors.ENDC))
    rhuirepo = '^rhui-microsoft.*'
    myreponame = ""

    try:
        import requests
    except ImportError:
        logging.critical("{}'requests' python module not found but it is required for this test script, review your python instalation{}".format(bcolors.FAIL, bcolors.ENDC))
        exit(1) 
    try:
        import socket
    except ImportError:
        logging.critical("{}'socket' python module not found but it is required for this test script, review your python instalation{}".format(bcolors.FAIL, bcolors.ENDC))
        exit(1) 

    for repo_name in reposconfig.sections():
        if re.match(rhuirepo, repo_name):
           logging.debug('{}Microsoft repository name is: {}{}'.format(bcolors.BOLD, repo_name, bcolors.ENDC))
           myreponame = repo_name

    if myreponame:
       try:
           baseurl_info = reposconfig.get(myreponame, 'baseurl').strip().split('\n')
       except NoOptionError:
           logging.critical('{}Critical component of the Microsoft Azure RHUI repo not found, consider resinstalling the RHUI Repo{}'.format(bcolors.FAIL, bcolors.ENDC))
           exit(1)
      
       successes = 0
       for url in baseurl_info:

           try:
               url_host = url.split('/')[2]
               rhui_ip_address = socket.gethostbyname(url_host)

               if rhui_ip_address in rhui3 + rhuius:
                   warnings = warnings + 1
                   logging.warning('{}RHUI server {} points to old infrastructure, refresh RHUI the RHUI package{}'.format(bcolors.WARNING, url_host, bcolors.ENDC))
               elif rhui_ip_address not in rhui4:
                   logging.critical('{}RHUI server {} points to an invalid destination, validate /etc/hosts file for any static RHUI IPs, reinstall the RHUI package{}'.format(bcolors.FAIL, url_host, bcolors.ENDC))
                   continue
               else:
                   logging.debug('{}RHUI host {} points to RHUI4 infrastructure{}'.format(bcolors.OKGREEN, url_host, bcolors.ENDC))
           except Exception as e:
                logging.warning('{}Unable to resolve IP address for host {}{}'.format(bcolors.WARNING, url_host, bcolors.ENDC))
                logging.warning('{}Please make sure your server is able to resolve {} to one of the ip addresses{}'.format(bcolors.WARNING, url_host, bcolors.ENDC))
                rhui_link = 'https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#the-ips-for-the-rhui-content-delivery-servers'
                logging.warning('{}listed in this document {}{}'.format(bcolors.WARNING, rhui_link, bcolors.ENDC))
                continue

           url = url+'/repodata/repomd.xml'
           logging.debug('{}This is one of links supporting the RHUI infrastructure {}{}'.format(bcolors.BOLD, url, bcolors.ENDC))


           headers = {'content-type': 'application/json'}
           try:
               r = requests.get(url, headers=headers, timeout=5)
           except requests.exceptions.Timeout:
               logging.warning('{}PROBLEM: Unable to reach RHUI server, https port is blocked for {}{}'.format(bcolors.WARNING, url, bcolors.ENDC))
           except requests.exceptions.SSLError:
               logging.warning('{}PROBLEM: MITM proxy misconfiguration. Proxy cannot intercept certs for {}{}'.format(bcolors.WARNING, url, bcolors.ENDC))
           except Exception as e:
               logging.warning('{}PROBLEM: Unable to reach RHUI server, https port is blocked for {}{}'.format(bcolors.WARNING, url, bcolors.ENDC))
           else:
                successes += 1
                logging.debug('{}The RC for this {} link is {}{}'.format(bcolors.OKGREEN, url, r.status_code, bcolors.ENDC))

       if successes == 0:
           error_link = 'https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel9#the-ips-for-the-rhui-content-delivery-servers'
           logging.critical('{}PROBLEM: Cannot communicate with any RHUI server, you must allow at least one of the IP addresses listed here {}{}'.format(bcolors.FAIL, error_link, bcolors.ENDC))
           sys.exit(1)

def connect_to_rhui_repos(reposconfig):
# check if EUS or NON-EUS repos are being used correctly.

    logging.debug('{}Entering connect_to_rhui_repos(){}'.format(bcolors.BOLD, bcolors.ENDC))
    import requests

    EUS = 0
    rhuirepo = '^(rhui-)?microsoft.*'
    eusrepo  = '.*-(eus|e4s)-.*'
    default= '.*default.*'
    #  fixme: Add support for ARM infrastructure

    enabled_repos = []
    for repo_name in reposconfig.sections():
       if not (re.match(rhuirepo, repo_name) or re.match(default, repo_name)):
           try:
               if reposconfig.get(repo_name, 'enabled').strip() == '1': 
                   logging.info('{} Repo {} enabled{}'.format(bcolors.OKGREEN, repo_name, bcolors.ENDC))
                   if re.match(eusrepo, repo_name):
                       EUS = 1
                   enabled_repos.append(repo_name) 
               else:
                   logging.debug('{}{} repo not enabled{}'.format(bcolors.BOLD, repo_name, bcolors.ENDC))

           except configparser.NoOptionError:
               logging.error('{}Repo {} does not have an enabled attribute skipping{}'.format(bcolors.FAIL, repo_name, bcolors.ENDC))

    if len(enabled_repos) == 0:
        logging.critical('{}Did not find any enabled repositories in this repo config{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1)

    releasever=""

    try:
        uname = os.uname()
    except:
        logging.critical('{} Unable to identify OS version{}'.format(bcolors.FAIL, bcolors.ENDC))
        exit(1)    

    try:
        basearch = uname.machine
    except AttributeError:
        basearch = uname[-1]

    try:
        baserelease = uname.release
    except AttributeError:
        baserelease = uname[2]

    if EUS:
        if os.path.exists('/etc/yum/vars/releasever'):
           fd = open('/etc/yum/vars/releasever')
           releasever = fd.readline().strip()
        else:
           logging.critical('{} Server is using EUS repostories but /etc/yum/vars/releasever file not found, please correct and test again{}'.format(bcolors.FAIL, bcolors.ENDC))
           logging.critical('{} Refer to: https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms, to select the appropriate RHUI repo{}'.format(bcolors.FAIL, bcolors.ENDC))
           exit(1)

    if not EUS:
        if os.path.exists('/etc/yum/vars/releasever'):
            logging.critical('{} Server is using non-EUS repos and /etc/yum/vars/releasever file found, correct and try again'.format(bcolors.FAIL, bcolors.ENDC))
            logging.critical('{} Refer to: https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms, to select the appropriate RHUI repo{}'.format(bcolors.FAIL, bcolors.ENDC))

            exit(1)

        releasever  = re.sub(r'^.*el([0-9][0-9]*).*',r'\1',baserelease)
        if releasever == '7':
            releasever = '7Server'
            

    for myreponame in enabled_repos:
        try:
           baseurl_info = reposconfig.get(myreponame, 'baseurl').strip().split('\n')
        except configparser.NoOptionError:
            logging.critical('{} baseurl of {} not found, consider reinstalling the corresponding RHUI repo{}'.format(bcolors.FAIL, myreponame, bcolors.ENDC))
            exit(1)

        for url in baseurl_info:

           url = url+"/repodata/repomd.xml"
           url = url.replace('$releasever',releasever)
           url = url.replace('$basearch',basearch)
           logging.debug('{}baseurl for repo {} is {}{}'.format(bcolors.BOLD, myreponame, url, bcolors.ENDC))

           headers = {'content-type': 'application/json'}
           try:
               cert=( reposconfig.get(myreponame, 'sslclientcert'), reposconfig.get(myreponame, 'sslclientkey') )
           except:
               logging.critical('{} Client certificate and/or client key attribute not found for {}, testing connectivity w/o certificates{}'.format(bcolors.FAIL, myreponame, bcolors.ENDC))
               cert=()

           successes = 0
           try:
               r = requests.get(url, headers=headers, cert=cert, timeout=5)
               successes += 1
               logging.debug('{}the RC for this {} link is {}{}'.format(bcolors.OKGREEN, url,r.status_code, bcolors.ENDC))
           except requests.exceptions.Timeout:
               logging.warning('{} PROBLEM: Unable to reach RHUI server, https port is blocked for {}{}'.format(bcolors.WARNING, url, bcolors.ENDC))
           except requests.exceptions.SSLError:
               logging.warning('{} PROBLEM: MITM proxy misconfiguration. Proxy cannot intercept certs for {}{}'.format(bcolors.WARNING, url, bcolors.ENDC))
           except requests.exceptions.RequestException:
                logging.warning('{} PROBLEM: Unable to establish communication to {}, please allow SSL traffic to it{}'.format(bcolors.WARNING, url, bcolors.ENDC))

        if successes == 0:
            logging.critical('{} PROBLEM: Cannot communicate with any RHUI server, you must allow at least one{}'.format(bcolors.FAIL, bcolors.ENDC))
            sys.exit(1)

######################################################
# Logging the output of the script into /var/log/rhuicheck.log file
######################################################
def start_logging():
    """This function sets up the logging configuration for the script and writes the log to /var/log/rhuicheck.log"""
    log_filename = '/var/log/rhuicheck.log'
    file_handler = logging.FileHandler(filename=log_filename)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

if os.geteuid() != 0:
   logging.critical('{} This script needs to execute with root privileges\nPlease use: sudo {} {}'.format(bcolors.FAIL, sys.argv[0], bcolors.ENDC))
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
start_logging()

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

for package_name in rpm_names():
    data                                     = get_pkg_info(package_name)
    expiration_time(data['clientcert'])
    reposconfig                              = check_rhui_repo_file(data['repofile'])
    check_microsoft_repo(reposconfig)
    connect_to_microsoft_repo(reposconfig)
    connect_to_rhui_repos(reposconfig)

logging.critical('{}All communication tests to the RHUI infrastructure have passed, if problems persisit, remove third party repositories and test again{}'.format(bcolors.OKGREEN, bcolors.ENDC))
logging.critical('{}The RHUI repository configuration file is {}, move any other configuration file to a temporary location and test again{}'.format(bcolors.OKGREEN, data['repofile'], bcolors.ENDC))
