# Use the tool NMAP [Command line only]to perform the below task. Run Wireshark in the background and capture only the necessary packets to showcase for the corresponding question.

### NMAP is an open-source monitoring tool that can help scan and discover networks and network problems respectively. Nmap is very flexible, portable, well-documented, and easy to use. 

## a) Explain the subnet and use the NMAP Command to scan the services for the whole subnet.
### A subnet, or subnetwork, is a segmented piece of a larger network. More specifically, subnets are a logical partition of an IP network into multiple, smaller network segments. The Internet Protocol (IP) is the method for sending data from one computer to another over the internet. Each computer, or host, on the internet has at least one IP address as a unique identifier.

Command to scan entire subnet - `nmap -sn <network address>/<subnet prefix/CIDR notation>`

![image](https://user-images.githubusercontent.com/68326118/226402566-708ee988-f3b2-48a3-a94c-dfbb6753eb3a.png)


## b) What is a firewall andmention its types. Use the NMAP command to detect that a firewall protects the host.

<p align="center">
  <img src="https://static.javatpoint.com/tutorial/firewall/images/types-of-firewall.png" width="250" alt="dnsenum"/> <br/>
</p>

### A Firewall is a network security device that monitors and filters incoming and outgoing network traffic based on an organization’s previously established security policies. At its most basic, a firewall is essentially the barrier that sits between a private internal network and the public Internet. A firewall’s main purpose is to allow non-threatening traffic in and to keep dangerous traffic out.
### The following are types of firewall techniques that can be implemented as software or hardware:
- Packet-filtering Firewalls
- Circuit-level Gateways
- Application-level Gateways (Proxy Firewalls)
- Stateful Multi-layer Inspection (SMLI) Firewalls
- Next-generation Firewalls (NGFW)
- Threat-focused NGFW
- Network Address Translation (NAT) Firewalls
- Cloud Firewalls
- Unified Threat Management (UTM) Firewalls

we use the `Standard SYN Scan`

![image](https://user-images.githubusercontent.com/68326118/226404166-5af6f047-d61f-419b-884b-ea5710337f4a.png)


## c) Use the NMAP command to scan a network and determine which devices are up and running.
 
 Command - `nmap -sn <ip>/<CIDR>`
 
![image](https://user-images.githubusercontent.com/68326118/226405154-eadd1431-0b58-4105-9186-90bb1bb29309.png)


## d) What are vertical and horizontal scanning?
### Port scanning is a method of detecting vulnerable nodes in a network by accessing different ports on a host (a device connected to the network) or the same port on different hosts. It can be used by cybercriminals in the preparatory phase of an attack to harvest information about the target host, as well as by information security experts as a tool for locating vulnerable nodes in IT infrastructure.
### Types of port scanning

<p align="center">
  <img src="https://images.slideplayer.com/31/9668175/slides/slide_34.jpg" width="300" alt="dnsenum"/> <br/>
</p>

- Horizontal scanning or network scanning sends requests to the same port on different hosts. Attackers use horizontal scanning to prepare for a mass attack.

<p align="center">
  <img src="https://images.slideplayer.com/31/9668175/slides/slide_36.jpg" width="300" alt="dnsenum"/> <br/>
</p>

- Vertical scanning sends requests to different ports on the same host. Attackers typically use vertical scanning to look for vulnerabilities in a preselected target.

## e) Use the NMAP command to scan multiple hosts. 

Adding the ip address to `/etc/hosts` file.

![image](https://user-images.githubusercontent.com/68326118/226408280-3333d605-4af5-4bce-a8de-fe7d2d7fbc13.png)

![image](https://user-images.githubusercontent.com/68326118/226408055-4e45e53c-a02b-4457-a86c-75ed038b074b.png)

## f) Use NMAP commands to export the output inXML format.

Here we use the `-oX` flag.

![image](https://user-images.githubusercontent.com/68326118/226409293-1db9dbe0-8395-48fe-9c80-e7980746ba36.png)

## g) Use the NMAP command to getOS information about a host. 

![image](https://user-images.githubusercontent.com/68326118/226415054-7ccd3eee-91ec-4ea8-8421-daf567712765.png)

## h) Explain ping sweeping and Perform ping sweeping using Nmap.

### Ping sweep is just a technique that can be used to find out which hosts are alive in a network or large number of IP addresses. In contrast to a single ping, a ping sweep uses ICMP (Internet Control Message Protocol) ECHO requests to communicate with multiple hosts at the same time. Ping sweeping will provide the following benefits such as Discover live hosts and inactive IP addresses on the network. Create a map of live hosts from the DHCP environment. Perform network security audits and detect rogue devices on the network.

Nmap command to perform ping sweep - `nmap -sn <network address>/<CIDR>`.


![image](https://user-images.githubusercontent.com/68326118/226416598-b3b323a6-5d21-4ea6-9b6b-e77db969767c.png)

![image](https://user-images.githubusercontent.com/68326118/226416420-3080e76f-25d1-42e5-94be-9bee16c5a0b9.png)

_________________________________________________________________________________________
# Try these below questions after completing the above commands.
## 1.What is a web application firewall? How do you use Nmap to detect a WAF? Perform WAF fingerprint detection using NMAP.

Command - `nmap --script http-waf-detect`

![image](https://user-images.githubusercontent.com/68326118/226420121-4b664b90-bce3-4494-942d-4ce278d160df.png)

## 2.What is EXIF data? Try to find EXIF data of images on a website using NMAP NSE. 
### EXIF (Exchangeable Image File Format) files store important data about photographs. Almost all digital cameras create these data files each time when we snap a new picture. An EXIF file holds all the information about the image itself — such as the exposure level, where you took the photo, and any settings we used.

![image](https://user-images.githubusercontent.com/68326118/226420543-855e29df-6b4b-4433-876a-e0e416b9eab4.png)


## 3.Use NMAP NSE to find all subdomains of the website. 

All the nse scripts are loacated in /usr/share/nmap/scripts/

![image](https://user-images.githubusercontent.com/68326118/226421600-0d2bd885-42a2-4761-988c-079684541984.png)


## 4.Perform a vulnerability scan on the target host using NMAP NSE.
Command -  `nmap -sV --script=vuln <target ip>`

![image](https://user-images.githubusercontent.com/68326118/226423349-e6face19-3339-44fd-b70c-d61813fce7b6.png)


