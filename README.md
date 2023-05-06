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
