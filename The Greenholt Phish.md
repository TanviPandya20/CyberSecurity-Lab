# The Greenholt Phish

### 1. What is the email's timestamp?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/a8e76b36-244f-4d02-a797-13f623e044d8)

    06/10/2020 05:58

### 2. Who is the email from?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/fbca8033-017b-4b3f-8803-f5e0a0fa283f)

    Mr. James Jackson

### 3. What is his email address?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/18083f17-064f-4c55-881f-c5a10046d99c)

    info@mutawamarine.com

### 4. What email address will receive a reply to this email?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/1d7ee72a-c891-40c5-8bf7-972bee0bbdbd) 

    info.mutawamarine@mail.com

### 5. What is the Originating IP?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/2e08fa71-899a-4a39-b32e-c5db05382b7e)

    192.119.71.157

Click on `View` tab. Go to `headers` and select `All`.

As the more header information is shown, scroll down to find out Originating IP.

Look for the `Received` field to find out the Originating IP.

### 6. Who is the owner of the Originating IP?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/afe5a163-7203-4ccb-b015-f6476cf0de9c)
    hostwinds LLC

### 7. What is the SPF record for the Return-Path domain?
Go to the `whois` domain lookup page. (https://whois.domaintools.com/)

Give the IP (`192.119.71.157`) to find out the details.

![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/2a305fa5-580a-47ef-9d35-95b1f2fbdf41)

As we can see, `hostwinds LLC` is the owner of the Originating IP.

      v=spf1 include:spf.protection.outlook.com -all
    
We got the domain name `mutawamarine.com` from previous tasks.

Go to a SPF checker page (https://dmarcian.com/domain-checker/)

Give the domain name as input and we can see the SPF record details.

![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/548a5e00-428d-43fc-b50a-a691608b4677)

### 8. What is the DMARC record for the Return-Path domain?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/9b438c48-a825-43a7-a446-8f6453f59c86)


      v=DMARC1; p=quarantine; fo=1

### 9. What is the name of the attachment?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/0fb137f2-d9b3-4857-8d7f-c746524a1183)

      SWT_#09674321____PDF__.CAB
      
Click on `Save` button at the right down side.

We can see the filename while saving.

### 10. What is the SHA256 hash of the file attachment?
![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/70fe6110-1381-4287-ab39-03db7fa50af7)

      2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f

### 11. What is the attachments file size?

![image](https://github.com/tousif13/TryHackMe_Writeups/assets/33444140/1e31d45a-b338-49b6-80fe-8ad32fa27c09)

    400.26 KB

Enter the hash retreived from previous task in the `VirusTotal`.

### 12. What is the actual file extension of the attachment?

    Rar
