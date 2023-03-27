# <p align="center"> LAN based Insider Attacks and Analysis </p>
## Tools Used:
- Oracle VM
- Kali Purple
- Kali Linux
- Ettercap  
- Wireshark

# <p align="center"> Tasks description </p>
### In This Projects I have tried some attacks within the network where the attacker node is the part of the network. For this I have setup two systems and used ettercap for performing some LAN attackes in detecting it while capture the packet traffic using WireShark.

# 1. Perform Password stealing (over plaintext) using ARP Cache Poisoning attacks
- In this attack I first started the ettercap and listout the hosts in the attacker system.
<p align="center">
          <img src=""/> <br/>
</p>
- Then check the IP address in victim and match with the list in attacker and set that victim IP as target 1.
<p align="center">
          <img src=""/> <br/>
</p>
- After that, I activated the plugin "ARP Poisoning" and open the test vulnweb link in target system.
<p align="center">
          <img src=""/> <br/>
</p>
- Here we can get the login credentials of target system via Ettercap in attacker system.
<p align="center">
          <img src=""/> <br/>
</p>
