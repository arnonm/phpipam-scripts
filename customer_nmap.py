#!/usr/bin/env python3
"""
Name         : nmap_scanner.py
Author       : litebito (converted to Python)
Created      : 07-apr-2018 (PHP version)
Converted    : 2025 (Python version)
Version      : 2.1-py
Description  : This script performs a similar function as pingScanner.php, but using nmap.
               This script will do a scan and discovery in one, so this script should find 
               hosts which are not found by the standard scanner.
               It also will be able to find all MAC addresses (which the standard discovery 
               does not seem to be able to do)
               
               ATTENTION: This script may overwrite some information which is written by 
               other discovery or scanning scripts from PHPIPAM, like:
                 - lastseen, notes, MAC address, hostname, custom variables

Disclaimer   : USE AT YOUR OWN RISK !!
               The author is NOT responsible for any data or system losses caused by this 
               script. Do NOT use this script if you cannot read/understand Python.

Requirements :
    - nmap 7.0+ installed
    - PHPIPAM 1.5+ (and PHPIPAM api setup correctly)
    - PHPIPAM ip address custom fields:
        cAgeOffline, cLastSeen, cNmapInfo, cDiscoveryScanComment
    - Python 3.6+
    - requests library (pip install requests)
    - lxml library (pip install lxml)
    
Script can be run from cron:
    */15 * * * * /usr/bin/python3 /path/to/nmap_scanner.py > /dev/null 2>&1
"""

import sys
import os
import time
import json
import subprocess
import logging
from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET
import requests
from requests.auth import HTTPBasicAuth
import tempfile

# Check if running from CLI
if hasattr(sys, 'ps1'):
    print("This script can only be run from CLI!")
    sys.exit(1)

class PHPIPAMScanner:
    def __init__(self):
        """Initialize the scanner with configuration"""
        # Configuration - Update these values
        self.api_server = os.getenv('IPAM_SERVER', 'localhost')
        self.api_url = self.api_server + "/api/"
        self.api_app_id = os.getenv('IPAM_CLIENT', "apiclient")
        #self.api_key = "ClSJ3sL11f-j7NUKnj5Qq3_nYU5Fyd3t"
        self.api_key = os.getenv('IPAM_API_KEY', "false")
        self.api_username = os.getenv('IPAM_API_USER', "user")
        self.api_password = os.getenv('IPAM_API_PASSWORD', "password")
        self.token_file = "token.txt"
        self.result_format = "json"
        
        # Script configuration
        self.script_name = os.path.basename(__file__)
        self.log_dir = tempfile.gettempdir()
        self.log_file = f"{self.log_dir}/phpipam_{self.script_name}.log"
        self.debug_level = 3  # 1 = errors, 2 = info, 3 = debug
        self.nmap_dir = tempfile.gettempdir()
        self.dns_servers = os.getenv('IPAM_DNS_SERVERS', '')
        self.nmap_dns = "-dns-servers " + self.dns_servers
        
        # Runtime variables
        self.now = int(time.time())
        self.now_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mem_start = self._get_memory_usage()
        self.session = requests.Session()
        self.token = None
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.DEBUG if self.debug_level >= 3 else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _get_memory_usage(self):
        """Get current memory usage in KB"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return round(process.memory_info().rss / 1024, 2)
        except ImportError:
            return 0
            
    def log_message(self, level, message):
        """Log message with memory usage"""
        mem_current = self._get_memory_usage() - self.mem_start
        log_msg = f"{message} [{mem_current}kb]"
        
        if level == 1 and self.debug_level >= 1:
            self.logger.error(log_msg)
        elif level == 2 and self.debug_level >= 2:
            self.logger.info(log_msg)
        elif level == 3 and self.debug_level >= 3:
            self.logger.debug(log_msg)
            
    def authenticate(self):
        """Authenticate with PHPIPAM API"""
        #auth_url = f"{self.api_url}{self.api_app_id}/user/"
        auth_url = f"{self.api_url}{self.api_app_id}/user/"
        
        try:
            if self.api_key and self.api_key != "false":
                # Encrypted authentication
                headers = {'Content-Type': 'application/json'}
                response = self.session.post(auth_url, headers=headers)
            else:
                # Basic authentication
                self.logger.info("Basic Authentication")
                auth = HTTPBasicAuth(self.api_username, self.api_password)
                response = self.session.post(auth_url, auth=auth)
                #response = requests.post(auth_url, auth=(self.api_username, self.api_password), verify = False)
                
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.token = result['data']['token']
                    self.session.headers.update({'token': self.token})
                    self.log_message(2, "API authentication successful")
                    return True
            
            self.log_message(1, f"Authentication failed: {response.text}")
            return False
            
        except Exception as e:
            self.log_message(1, f"Authentication error: {str(e)}")
            return False
            
    def api_request(self, method, endpoint, data=None):
        """Make API request to PHPIPAM"""
        url = f"{self.api_url}{self.api_app_id}/{endpoint}/"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
                
            return response.json()
            
        except Exception as e:
            self.log_message(1, f"API request error: {str(e)}")
            return None
            
    def run_nmap_scan(self, subnet, mask, nmap_dns=None):
        """Run nmap scan on subnet"""
        target = f"{subnet}/{mask}"
        output_file = f"{self.nmap_dir}/nmapscan_{subnet}_{mask}.xml"
        
        cmd = f"nmap -sn -PR -PE -R -oX {output_file} {nmap_dns} {target}"
        
        try:
            self.log_message(3, f"Running nmap scan: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_message(2, f"Nmap scan completed for {target}")
                return output_file
            else:
                self.log_message(1, f"Nmap scan failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.log_message(1, f"Nmap execution error: {str(e)}")
            return None
            
    def parse_nmap_xml(self, xml_file):
        """Parse nmap XML output"""
        hosts = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Get scan start time
            scan_start = root.get('start')
            last_seen = datetime.fromtimestamp(int(scan_start)).strftime('%Y-%m-%d %H:%M:%S')
            
            for host in root.findall('host'):
                host_data = {
                    'ipv4': 'NA',
                    'mac': '00:00:00:00:00:00',
                    'hostname': 'NA',
                    'reason': 'NA',
                    'last_seen': last_seen
                }
                
                # Get addresses
                for address in host.findall('address'):
                    addr_type = address.get('addrtype')
                    addr = address.get('addr')
                    
                    if addr_type == 'ipv4':
                        host_data['ipv4'] = addr
                    elif addr_type == 'mac':
                        host_data['mac'] = addr
                
                # Get hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                   hostname = hostnames.find('hostname')
                   if hostname is not None:
                      host_data['hostname'] = hostname.get('name', None)
                        
                # Get status
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    host_data['reason'] = status.get('reason', 'NA')
                    
                if host_data['ipv4'] != 'NA':
                    hosts.append(host_data)
                    
            return hosts
            
        except Exception as e:
            self.log_message(1, f"XML parsing error: {str(e)}")
            return []
            
    def update_host_in_phpipam(self, host_id, host_data, is_new=False):
        """Update or create host in PHPIPAM"""
        nmap_info = f"Type: {host_data['reason']} / MAC: {host_data['mac']}"
        #if not 'hostname' in host_data:
        #    hostdata['hostname']='NA'
        log_line = f"Updated by nmap scanner: {host_data['hostname']}, {host_data['mac']}, {host_data['last_seen']}"
        
        update_data = {
            'tag': 2,  # Online
            'lastSeen': host_data['last_seen'],
            'hostname': host_data['hostname'],
            'custom_cAgeOffline': '0',
            'custom_cNmapInfo': nmap_info,
            'custom_cLastSeen': host_data['last_seen'],
            'custom_cDiscoveryComment': log_line
        }
        
        if is_new:
            update_data.update({
                'subnetId': host_data['subnet_id'],
                'ip': host_data['ipv4']
            })
            
        # Update MAC address separately if valid
        if host_data['mac'] != '00:00:00:00:00:00':
            update_data['mac'] = host_data['mac']
            
        if is_new:
            result = self.api_request('POST', 'addresses', update_data)
            action = "INSERT"
        else:
            result = self.api_request('PATCH', f'addresses/{host_id}', update_data)
            action = "UPDATE"
            
        if result and result.get('code') == 200:
            self.log_message(3, f"{action} successful for {host_data['ipv4']}: {result.get('message', '')}")
            return True
        else:
            self.log_message(1, f"{action} failed for {host_data['ipv4']}: {result.get('message', '') if result else 'No response'}")
            return False
            
    def update_offline_hosts(self, subnet_hosts, scan_time):
        """Update hosts that weren't found in scan as offline"""
        scan_datetime = datetime.strptime(scan_time, '%Y-%m-%d %H:%M:%S')
        
        for host in subnet_hosts:
            if host.get('excludePing') == '1':
                self.log_message(3, f"Host {host['ip']} excluded from ping/scan")
                continue
                
            # Compare last seen times
            last_seen_db = host.get('lastSeen', '')
            last_seen_custom = host.get('custom_cLastSeen', '')
            
            # Use the most recent date
            last_seen = last_seen_custom if last_seen_custom else last_seen_db
            
            if last_seen:
                try:
                    host_datetime = datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S')
                    age_days = (scan_datetime - host_datetime).days
                    
                    if age_days > 0:
                        self.log_message(2, f"Updating offline status for {host['ip']}, age: {age_days} days")
                        
                        update_data = {
                            'tag': 1,  # Offline
                            'custom_cAgeOffline': str(age_days)
                        }
                        
                        result = self.api_request('PATCH', f'addresses/{host["id"]}', update_data)
                        
                        if result and result.get('code') == 200:
                            self.log_message(3, f"Offline update successful for {host['ip']}")
                        else:
                            self.log_message(1, f"Offline update failed for {host['ip']}")
                            
                except ValueError as e:
                    self.log_message(1, f"Date parsing error for {host['ip']}: {str(e)}")
                    
    def scan_subnet(self, subnet_info):
        """Scan a single subnet"""
        subnet = subnet_info['subnet']
        mask = subnet_info['mask']
        subnet_id = subnet_info['id']
        nameservers = []
        nameserver_string=None
        if 'nameservers' in subnet_info:
            names = subnet_info['nameservers']
            if 'namesrv1' in names:
               nameservers.append(names['namesrv1'].replace(";",","))
            if 'namesrv2' in names:
               nameservers.append(names['namesrv2'].replace(";",","))

            if len(nameservers) > 0:
                nameserver_string = '-dns-servers "' . ','.join(nameservers) +'"'
            else:
                nameserver_string = None
        
        self.log_message(2, f"Starting scan for subnet {subnet}/{mask} (ID: {subnet_id})")
        self.log_message(2, f"with dns-servers: {nameserver_string}")
        
        # Run nmap scan
        xml_file = self.run_nmap_scan(subnet, mask, nameserver_string)
        if not xml_file:
            return False
            
        # Get existing hosts from PHPIPAM
        result = self.api_request('GET', f'subnets/{subnet_id}/addresses')
        phpipam_hosts = result.get('data', []) if result else []
        
        # Parse nmap results
        nmap_hosts = self.parse_nmap_xml(xml_file)
        
        # Phase 1: Update/add hosts found by nmap
        self.log_message(3, f"PHASE 1: Processing {len(nmap_hosts)} hosts from nmap scan")
        
        scan_time = nmap_hosts[0]['last_seen'] if nmap_hosts else self.now_date
        
        for nmap_host in nmap_hosts:
            found = False
            
            # Look for existing host in PHPIPAM
            for phpipam_host in phpipam_hosts:
                if nmap_host['ipv4'] == phpipam_host['ip']:
                    found = True
                    if phpipam_host.get('excludePing') != '1':
                        self.log_message(2, f"Updating existing host {nmap_host['ipv4']}")
                        self.update_host_in_phpipam(phpipam_host['id'], nmap_host)
                    break
                    
            # Add new host if not found
            if not found:
                self.log_message(2, f"Adding new host {nmap_host['ipv4']}")
                nmap_host['subnet_id'] = subnet_id
                self.update_host_in_phpipam(None, nmap_host, is_new=True)
                
        # Phase 2: Mark offline hosts that weren't found in scan
        self.log_message(3, f"PHASE 2: Checking for offline hosts in subnet {subnet}/{mask}")
        self.update_offline_hosts(phpipam_hosts, scan_time)
        
        # Cleanup
        try:
            os.remove(xml_file)
        except OSError:
            pass
            
        return True
        
    def run(self):
        """Main scanner execution"""
        print("\n")
        self.log_message(2, "=" * 100)
        self.log_message(2, f"{self.script_name} STARTED...")
        self.log_message(2, "=" * 100)
        print("\n")
        
        # Authenticate
        if not self.authenticate():
            self.log_message(1, "Authentication failed, exiting")
            return False
            
        # Get all sections
        sections_result = self.api_request('GET', 'sections')
        if not sections_result or not sections_result.get('data'):
            self.log_message(1, "Failed to get sections from PHPIPAM")
            return False
            
        sections = sections_result['data']
        
        # Process each section
        for section in sections:
            print("\n")
            self.log_message(2, "=" * 100)
            self.log_message(2, f"Processing section: {section['name']}")
            self.log_message(2, "=" * 100)
            
            # Get subnets for this section
            subnets_result = self.api_request('GET', f'sections/{section["id"]}/subnets')
            if not subnets_result or not subnets_result.get('data'):
                self.log_message(2, f"No subnets found in section {section['name']}")
                continue
                
            subnets = subnets_result['data']
            
            # Process each subnet
            for subnet in subnets:
                discover_flag = subnet.get('discoverSubnet')
                print('discoverSubnet='+str(discover_flag))
                if discover_flag == 1:
                    print("\n")
                    self.log_message(2, "-" * 80)
                    self.log_message(2, f"Scanning subnet {subnet['subnet']}/{subnet['mask']}")
                    self.log_message(2, "-" * 80)
                    
                    self.scan_subnet(subnet)
                else:
                    self.log_message(2, f"Subnet {subnet['subnet']}/{subnet['mask']} not flagged for discovery")
                    
        print("\n")
        self.log_message(2, "=" * 100)
        self.log_message(2, f"{self.script_name} COMPLETED")
        self.log_message(2, "=" * 100)
        print("\n")
        
        return True

def main():
    """Main function"""
    scanner = PHPIPAMScanner()
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.log_message(2, "Scanner interrupted by user")
    except Exception as e:
        scanner.log_message(1, f"Unexpected error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
