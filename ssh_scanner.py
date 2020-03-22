#!/usr/bin/python3
"""
Usage:
  ssh_scanner.py -h | --help
  ssh_scanner.py (--sshpass=<sshpass> --rhosts=<rhosts>) [--sshtimeout=<sshtimeout>] [--sshuser=<sshuser>]

Options:
  --sshuser=<sshuser>        Username [default: root]
  --sshpass=<sshpass>        Password
  --rhosts=<rhosts>          List of targets single ip per line (similar to nmap -iL)
  --sshtimeout=<sshtimeout>  Timeout for each ssh attempt [default: 5]
"""
# ----------------------
import json
import paramiko
import concurrent.futures
from docopt import docopt
# ----------------------
'''
Preliminary notes –
    Program Requirements :
        We have some credential (could be a password, token, etc) that got exposed to the public
        We want to check if any internal systems use this credential for SSH
        If this credential is used, we need to get sys details and dump them to a JSON file
        We have a list of remote hosts to check, expect to scan 200,000 systems

    Procedure :
        Create a pool of workers to give a remote host
            For each target remote host
                Attempt an SSH connection using the paramiko module
                If connection is successful, this credential is being used
                    Gather OS details, dump to JSON file
'''
# ----------------------
def get_hosts_from_file(filename):
    # For each line in the file, parse as list item
    with open(filename) as file:
        lines = [line.rstrip('\n') for line in file]
    return lines
# ----------------------
def parse_sys_info(std_out):
    # Clear output and strip on second instance of whitespace
    std_out = str(std_out).strip("['']\\n").split(' ', 2)
    details = dict()

    # We have 3 details, kernel name, nodename, and kernel version
    details['Kernel Name'] = std_out[0]
    details['Nodename'] = std_out[1]
    details['Kernel Version'] = std_out[2]
    return details
# ----------------------
def build_response(results):
    # Build JSON response for list of accesses
    response = dict()
    response['Count'] = len(results)
    response['Message'] = 'SSH access found!'
    response['System Details'] = results
    return response
# ----------------------
def default_response():
    # Build default JSON response if no accesses
    response = dict()
    response['Count'] = 0
    response['Message'] = 'No access found for these credentials'
    response['System Details'] = []
    return response
# ----------------------
def check_access(access_info, host):
    # Create SSH client object
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Access data from CLI
    username = str(access_info['--sshuser'])
    key = str(access_info['--sshpass'])
    timeout = int(access_info['--sshtimeout'])

    # Make SSH connection, no need for try/except as we check inside of sweep() func
    ssh_connection.connect(host, port=22, username=username, password=key, timeout=timeout)
    # Execute uname command to get sys details and parse, then close connection
    stdin, stdout, stderr = ssh_connection.exec_command('uname -s -n -v')
    result = parse_sys_info(stdout.readlines())
    ssh_connection.close()

    return result
# ----------------------
def write_output(results):
    # Make JSON response based on results
    with open('output.json', 'w', encoding='utf-8') as out:
        # If results isn't empty, we had a hit with the credentials
        if len(results) > 0:
            response = build_response(results)
        else:
            response = default_response()
        # Write response wih formatting
        json.dump(response, out, ensure_ascii=False, indent=4)
    return None
# ----------------------
def sweep(access_info):
    # Parse hosts and initialize results list
    remote_hosts = get_hosts_from_file(access_info['--rhosts'])
    results = []

    # Use thread pool to execute multiple requests concurrently, also max_workers can be set depending on system env
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        # Begin load operations, each dict entry looks like {<Future at 'address' state=pending>: host}
        check_access_futures = {executor.submit(check_access, access_info, host): host for host in remote_hosts}

        # Get result as futures finish, result looks like {<Future at 'address' state=finished returned 'result'>}
        for thread_result in concurrent.futures.as_completed(check_access_futures):
            try:
                # Attempt to extract result from check_access() call & add to our list
                data = thread_result.result()
                results.append(data)
            except Exception as e:
                continue

    # Finished traversing all hosts, write result
    write_output(results)
    return None
# ----------------------
def main():
    # NOTE : configure max open file descriptors (network sockets) using 'ulimit -n'
    # Otherwise, you'll get a OS error for too many open files, check kernel imposed limit for max
    opts = docopt(__doc__)
    sweep(opts)
# ----------------------
if __name__ == '__main__':
    main()
