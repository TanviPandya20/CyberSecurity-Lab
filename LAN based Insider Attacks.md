# <p align="center"> LAN based Insider Attacks and Analysis </p>
## Tools Used:
- Oracle VM
- Kali Purple
- Kali Linux
- Ettercap  
- Wireshark

# <p align="center"> Tasks description </p>
### In This Projects I have tried some attacks within the network where the attacker node is the part of the network. For this I have setup two systems and used ettercap for performing some LAN attackes in detecting it while capture the packet traffic using WireShark.
![w jpg](https://user-images.githubusercontent.com/67452535/228026749-f9485da9-823a-4544-91ee-980df103aac5.png)


# 1. Perform Password stealing (over plaintext) using ARP Cache Poisoning attacks
- In this attack I first started the ettercap and listout the hosts in the attacker system.
          ![1 jpg](https://user-images.githubusercontent.com/67452535/228023569-c95fda76-5559-44b3-92ca-c8d03f760022.png)
          <br/>
- Then check the IP address in victim and match with the list in attacker and set that victim IP as target 1.
![11 jpg](https://user-images.githubusercontent.com/67452535/228024577-795c4711-5284-420d-902a-0bd8fc3f14df.png)
<br/>

- After that, I activated the plugin "ARP Poisoning" and open the test vulnweb link in target system.
- Here we can get the login credentials of target system via Ettercap in attacker system.
- In attacker system, WireShark captured the web traffic in target system.

![w1 jpg](https://user-images.githubusercontent.com/67452535/228026297-f6ffa1e7-c4c8-4ba9-a72d-fd8fc1ad5cb1.png)
<br/>
- This is how I stole the password of target system by ARP cache poisoning attack.

<br/>

# 2. Perform Denial of Service (DoS) attacks using ARP Cache Poisoning attacks
- In attacker system we open the ettercap config file and then set the ec_uid and ec_gid value 0.
![image](https://user-images.githubusercontent.com/67452535/228027651-2753264e-3e11-41db-9814-5887a908a4e2.png)
<br/>

![image](https://user-images.githubusercontent.com/67452535/228027765-2b914e5f-4650-4acf-8342-9db065d93605.png)
<br/>

- Then as per the image I open the dns file and remove the hash from the redir_commands.
![image](https://user-images.githubusercontent.com/67452535/228028049-fe4c09c6-10d7-4485-811f-1d029021be7a.png)
<br/>

- Then add the dummy web address so that it will redirect to the attacker ettercap and wireshark.
![image](https://user-images.githubusercontent.com/67452535/228028496-1e0a3580-13aa-497a-ad0e-5e791cdc1601.png)

<br/>

![image](https://user-images.githubusercontent.com/67452535/228028568-2aca5e7c-85bc-4012-bfb8-11e172cdc2bd.png)

<br/>

- When I ran that dummy file in target system it couldn't open but wireshark captured the traffic of that file.
![image](https://user-images.githubusercontent.com/67452535/228028996-919b7331-8710-4b2e-b59b-6139c2afa8b0.png)

<br/>

- This is how I performed the DoS attack and ARP poisoning attack.

# 3. Perform DNS Spoofing attack using ARP Cache Poisoning attacks
- As We saw in the previous attack, We have made change in Ettercap DNS file and it will leads to the Dos attack for the given system. So we can make changes in DNS file or track the domain names of the traffic by this.
![image](https://user-images.githubusercontent.com/67452535/228031417-70cb1bbf-9284-4e29-a963-c0e572afb90f.png)

<br/>

- This is how I performed the DNS spoofing attack in target system.

# 4. Invoke ‘sslstrip tool’ for stealing passwords from any machine that is connected to a LAN by 
stripping the HTTPS connection.
- In SSL striping we basically remove the digital certificate given to the web in the target system.
- It will remove the HTTPS security and make HTTP website so it will be vulnerable to many web attacks.
![image](https://user-images.githubusercontent.com/67452535/228033017-d37da1ed-b245-461a-97a1-39d6818512b6.png)

<br/>

# 5. Use arp_cop and scan_poisoner plugins to learn about the detection of ARP attacks.
- In this we will detact the attacker by using ettercap in target system. 
- We will download ettercap in taget system and actvate "arp_cop" plugin. It will show the warnings that which system is trying to attack or facking the IP address.
![image](https://user-images.githubusercontent.com/67452535/228033701-ff7268d6-e748-4aaf-b91b-8e03ea03841e.png)

<br/>

![image](https://user-images.githubusercontent.com/67452535/228033863-19574bfd-989f-4379-9b9b-eba83d35969f.png)

<br/>

- Then I had activate the plugin "scan_poisoner" that will show the systems which are trying send the spam requests or attacking the network.
![image](https://user-images.githubusercontent.com/67452535/228034553-683bba56-aa47-4b8f-aa20-6cd9b36cfe35.png)

<br/>

# Conclusion
## From this assignment I had clear idea about the various LAN insider attacks and how can we perform and detect those attacks with the use of Ettercap and WireShark. How we can use these tools both offensive an defensive way. Also I got the clear idea of working LAN system.
