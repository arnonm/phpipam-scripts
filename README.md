This is a fork of litebito/phpipam-scripts, rewritten in php
It now works with PHP PHPIpam 1.6+ 


# nmapScanner.php: 
script to use Nmap as scanning tool besides ping/fping


This script does the following:
 
* fetches flagged subnets for scanning
 
* scans the whole subnet witn Nmap, this will also scan hosts which do not respond to ping and discover missing MAC

* FOR EACH scan enabled/toggled SUBNET from PHPIPAM, there are 2 phases and assumes that this nmap scanner script is "the boss" (it will overwrite any other scan/discovery in case of conflicts.)

* Phase 1 : 
Start from the nmap output of the subnet, and update or add to PHPIPAM, that way, we need to read the file only once. 
Updates lastseen (this is important for phase 2), hostname, MAC address, other info (notes or comments)

* Phase 2 : walk through the subnet from PHPIPAM, and compare the lastseen from the script with the lastseen from PHPIPAM:
If the one in the database is older, we assume the ip was no longer seen by nmap, and thus considered offline, change the status to offline (not yet as fine grained as in the pingCheck script with the grace period), calculate the Age Offline

I use this either to run from command line or as a cron docker container. I use to scan my various docker networks as well

