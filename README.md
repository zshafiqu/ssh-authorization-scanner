# SSH SCANNER
## WARNING
- *ACCESSING SYSTEMS WITHOUT PERMISSION IS ILLEGAL*  

## Use Cases
* You have some credential (could be a combination of a username and/or password, token, etc) that got exposed to the public
* You need to check if any of your systems (could be local or remote) use this credential for SSH access
* If this credential is used, you need to gather system details in order to respond to the vulnerability

**This command line utility can efficiently scan hundreds of thousands of systems using multithreading, and return all
exposed system details in JSON format. The system details that are provided are :**

1. Node name
2. Kernel name
3. Kernel version

## Notes
- Simply provide a list of target remote hosts in a .txt file, each host separated by a new line
- Output will be provided in a JSON file named 'output.json'
- This repository provides a .gitignore to ensure that you don't accidentally commit your system details should you fork this repository
- See provided usage and options below, username and timeout values are optional with predefined defaults

## Usage
  ssh_scanner.py -h | --help  
  ssh_scanner.py (--sshpass=&lt;sshpass&gt; --rhosts=&lt;rhosts&gt;) [--sshtimeout=&lt;sshtimeout&gt;] [--sshuser=&lt;sshuser&gt;]  

## Options
  --sshuser=&lt;sshuser&gt;        Username [default: root]  
  --sshpass=&lt;sshpass&gt;        Password  
  --rhosts=&lt;rhosts&gt;          List of targets single ip per line (similar to nmap -iL)  
  --sshtimeout=&lt;sshtimeout&gt;  Timeout for each ssh attempt [default: 5]  
