When testing this code in WSL the following output was observed

——> sudo ./Jailer
Starting Jailer application...
Loading jail rules from /home/edward/test/jails.json
 <HostService>: Starting up...
 <LogMonitorService>: Starting monitoring for jail: test on file: ./fakelogfile.log
 <IptablesService>: Cleaning up all Jailer-marked rules...
 <IptablesService>: Cleanup complete. Removed 0 rules.
 <HostService>: Finished Start up
 <HostService>: Checking for expired jail entries to remove...
 <HostService>: An error occurred in the main loop. System.InvalidOperationException: Operation is not valid due to the current state of the object.
   at System.Threading.PeriodicTimer.State.WaitForNextTickAsync(PeriodicTimer owner, CancellationToken cancellationToken)
   at Jailer.Services.HostService.RunMainLoopAsync(CancellationToken ct) in B:\Projects\Jailer\Services\HostService.cs:line 66
 <LogMonitorService>: IP Test log 10.20.30.40 matched pattern in jail test. Count: 1/2
 <LogMonitorService>: IP Test log 10.20.30.40 matched pattern in jail test. Count: 2/2
 <LogMonitorService>: Violation detected for IP: Test log 10.20.30.40 in jail test
^C <HostService>: Stopping service...


There seems to be an issue with the period timer
And also while the Log Monitor service flagged correctly that an ip should be jailed it didnt seem like IptablesService was called to jail that IP 
It seems the regex to extract IP Addresses from the Log line isnt working