When testing this code in WSL the following output was observed

——> sudo ./Jailer
Starting Jailer application...
Loading jail rules from /home/edward/test/jails.json
 <HostService>: Starting up...
 <LogMonitorService>: Starting monitoring for jail: test on file: ./fakelogfile.log
 <IptablesService>: Cleaning up all Jailer-marked rules...
 <IptablesService>: Cleanup complete. Removed 0 rules.
 <HostService>: Finished Start up
 <LogMonitorService>: IP 10.20.30.40 matched pattern in jail test. Count: 1/2
 <LogMonitorService>: IP 10.20.30.40 matched pattern in jail test. Count: 2/2
 <LogMonitorService>: Violation detected for IP: 10.20.30.40 in jail test
^C <HostService>: Stopping service...
 <HostService>: Cleanup loop cancelled.
 <HostService>: Log check loop cancelled.

- There seems to be an issue with the period timer and also while the Log Monitor service flagged correctly that an ip should be jailed it didnt seem like IptablesService was called to jail that IP 

- It seems the regex to extract IP Addresses from the Log line isnt working

- When any new IP is banned we should also the state of the jails like so
{jail name}
  {ip}  {time left till unblock in mins} mins
{next jail name}
  {ip}  {time left till unblock in mins} mins
  {ip}  {time left till unblock in mins} mins
{next jail name}
  empty

- there is no search period for the jail if a user makes 1 bad attempt a day and the threshold is 3 on the 3rd day that user gets banned. we should drop any count older than 24 hours

- jails.json has been updated with a real regex for sshd jail but this seems to be causing some issues, (i dont mind if the regex needs to change slightly to say include wildcards in place of host but it should provide the same functionality as fail2ban)

- README.md needs updating to reflect what this project is, should include that its similar to fail2ban, a small section on how to build and deploy the solution, what its limitations are, its license (MIT license), some example output. this README should have a sensible look and feel