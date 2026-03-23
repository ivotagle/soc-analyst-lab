
DNS Log Analysis

First scenario: We cross information of two logs, DNS and Firewall:

DNS log: Feb 5 09:12:11 ns1 named[80090]: client 192.168.10.3#3261: query: dns.google IN A 
First finds: internal IP host (192.168.10.3) and querying Google DNS. It's a type A, so is requesting a IPV4 address.

Firewall log; date=2022-05-21 time=09:12:13 type="traffic" subtype="forward" srcip=192.168.10.3 srcport=50495 srcintfrole="lan" dstip=8.8.4.4 dstport=853 dstintfrole="wan" proto=6 action="accept"
Then, again, the internal IP, Google's destination (8844), this is different, Port 853. Protocol is #6 = TCP and was accepted.

Port 853 confirms DNS over TLS (DoT), normally would be Port 53. We can say that the request to this port 853 is bypassing the internal DNS and possibly using an encrypted DNS. 
So, it's suspicious because bypass normal monitoring, pottentially skips DNS filtering. Seems like malware.
Next steps: check the number and volume of connections. Look if requesting not common subdomains, other DNS providers like 1.1.1.1 or 9.9.9.9. Check User Agent: browser or not.


Doh v DoT

Protocol	   Port	  Transport
Classic DNS	 53	    UDP/TCP
DoT	         853	  TLS
DoH	         443	  HTTPS


Second scenario
This DNS Log: Mar 5 19:12:11 ns1 named[80090]: client 172.16.11.34#3261: query: am4wuz3zifexz5u.onion IN A

In this case, looking at the domain that ends in ".onion" gives away the involvement of the TOR Network. So the IP is requesting something in that Network, then it is suspicious. More if it comes from IP 172, which is usually a private DNS.

Next steps: Look for TOR ports used (9150, 9050 or 9001). TOR installation in the end device. Recall the number of queries. High number = suspicious.
