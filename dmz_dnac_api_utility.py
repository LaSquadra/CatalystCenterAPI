#! /usr/bin/env python3
# coding=utf-8
"""
File: dmz_dnac_api_utility.py
Author: Ryan Kroetch
Date: February 2024
Purpose: This will test for DNAC integration and functionality via the API
"""
#  Basic Python package imports
from sys import argv
from time import sleep
from pprint import pprint
import requests
from requests.auth import HTTPBasicAuth
import argparse
import urllib3

urllib3.disable_warnings()


#  Class containing the API calls for the DNAC server
class DnacApi:
    """
    This module facilitates DNA-C operations within test scripts.  It is intended to be used for TESTING and not for
    production environments.
    NOTE:  DNAC TOKENs expire after 1 hour so long tests may require re-authentication.  This has been built into the
           base function calls (get, post, put, delete) and should not require manual intervention.
    """
    
    def __init__(self, dnac_ip, username, password):
        self.dnac_ip = dnac_ip
        self.username = username
        self.password = password
        self.TOKEN = ""  # Token is valid for 1 hour
        self.DNAC_base_url = ""
        self.headers = {}
        self.authenticate_dnac(dnac_ip, username, password)
    
    def authenticate_dnac(self, dnac_ip, username, password):
        """
        method: authenticates the DNAC server with the given credentials,
            returns Token on the successful authentication
        param dnac_ip:    IP address of the DNAC
        param username:    Username for the DNAC
        param password:    Password for the given Username
        """
        base_url = "https://" + str(dnac_ip)
        auth_url = "/dna/system/api/v1/auth/token"
        url = base_url + auth_url
        
        response = requests.post(url, auth=HTTPBasicAuth(username, password), verify=False)
        
        if response.status_code == 200:
            
            # global TOKEN, DNAC_base_url, headers
            self.TOKEN = response.json()['Token']
            self.DNAC_base_url = base_url
            self.headers = {'X-Auth-Token': self.TOKEN, 'Content-Type': 'application/json'}
            return response.status_code
        else:
            print("DNAC Authentication Status Code : {}".format(response.status_code))
            print(response.json())
            print('DNAC Authentication failed')
            return response.status_code
    
    def get_api(self, get_url, query_string=None):
        """
        method: All the GET API calls will be executed by this method
        param: get_url - GET url for the resource
               query_string - Query Parameter to the Get API call (if necessary)
        """
        url = self.DNAC_base_url + get_url
        if query_string:
            response = requests.get(url, headers=self.headers, params=query_string, verify=False)
        else:
            response = requests.get(url, headers=self.headers, verify=False)
        
        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            return response
        elif response.status_code in (401, 403):
            print(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.username, self.password)
            # resubmitting request after authentication
            if query_string:
                response = requests.get(url, headers=self.headers, params=query_string, verify=False)
            else:
                response = requests.get(url, headers=self.headers, verify=False)
            return response
        else:
            print(response)
            print(response.json())
            return False
    
    def post_api(self, post_url, json_payload):
        """
        method: All the POST API calls will be executed by this method
        param: post_url - POST url for the resource
               json_payload - Input payload for that API call
        """
        url = self.DNAC_base_url + post_url
        response = requests.post(url, headers=self.headers, json=json_payload, verify=False)
        
        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            return response
        elif response.status_code in (401, 403):
            print(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.username, self.password)
            # resubmitting request after authentication
            response = requests.post(url, headers=self.headers, json=json_payload, verify=False)
            return response
        else:
            print(response)
            print(response.json())
            return False
    
    def put_api(self, put_url, payload):
        """
        method: All the PUT API calls will be executed by this method
        param: put_url - PUT url for the resource
               payload - Input payload for that API call
        """
        url = self.DNAC_base_url + put_url
        response = requests.put(url, headers=self.headers, json=payload, verify=False)
        
        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            return response
        elif response.status_code in (401, 403):
            print(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.username, self.password)
            # resubmitting request after authentication
            response = requests.put(url, headers=self.headers, json=payload, verify=False)
            return response
        else:
            print(response)
            print(response.json())
            return False
    
    def delete_api(self, delete_url, query_string=None):
        """
        method: All the DELETE API calls will be executed by this method
        param: delete_url - Delete url for the resource
               query_string - Query Parameter to the Delete API call (if necessary)
        """
        url = self.DNAC_base_url + delete_url
        if query_string:
            response = requests.delete(url, headers=self.headers, params=query_string, verify=False)
        else:
            response = requests.delete(url, headers=self.headers, verify=False)
        
        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            print(response.json())
            return response
        elif response.status_code in (401, 403):
            print(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.username, self.password)
            # resubmitting request after authentication
            if query_string:
                response = requests.delete(url, headers=self.headers, params=query_string, verify=False)
            else:
                response = requests.delete(url, headers=self.headers, verify=False)
            return response
        else:
            print(response)
            print(response.json())
            return False
    
    def get_site_info(self):
        """
        method: Get the Site Info
        """
        site_url = '/dna/intent/api/v1/site'
        response = self.get_api(site_url)
        return response
    
    def get_device_list(self):
        """
        :method:    Get all devices (and device details) that DNAC has discovered
        """
        device_list_url = '/dna/intent/api/v1/network-device'
        response = self.get_api(device_list_url)
        return response
    
    def get_device_id_by_name(self, device_name):
        """
        :method:    Get the device UUID given a specific device name
        :param device_name:    The hostname of the device
        :return:    Returns the device ID (or status code if not successful)
        """
        device_list = self.get_device_list()
        for device in device_list.json()['response']:
            if device['hostname'] == device_name or device['hostname'].split('.')[0] == device_name:
                return device['id']
        print(f"{device_name} was not found.")
        return device_list
    
    def execute_command(self, payload):
        """
        Example Payload:
        {
            "name": "command-runner",
            "description": "command-runner-network-poller",
            "deviceUuids": ["babb5704-4a9e-4bc2-8a88-3534f7dbc7dc"],
            "commands": ["sh logging"],
            "timeout": 120
        }
         """
        site_url = '/api/v1/network-device-poller/cli/read-request'
        response = self.post_api(site_url, payload)
        return response
    
    def get_device_details_by_id(self, device_id):
        """
        method: Returns detailed Network Device information retrieved by Device UUID for any given point of time.
        param: device_id - Device UUID

        """
        get_url = '/dna/intent/api/v1/device-detail'
        query_param = {"searchBy": device_id, "identifier": "uuid"}
        response = self.get_api(get_url, query_param)
        if response is False:
            return False
        return response.json()['response']
    
    def get_task_by_id(self, task_id):
        """
        method: To check the status of the DNAC Task by the task ID
        param: task_id : Task ID to check the Status of the task
        """
        task_id_by_url = '/dna/intent/api/v1/task/{task_id}'.format(task_id=task_id)
        response = self.get_api(task_id_by_url)
        if response is False:
            return False
        
        if response.json()['response']['isError']:
            if 'failureReason' in response.json()['response']:
                print("{}".format(response.json()['response']['failureReason']))
            return False
        return response.json()['response']
    
    def get_file(self, file_id):
        """
        :method:    Returns the file for the specified file ID
        :param file_id:
        :return:
        """
        site_url = f"/api/v1/file/{file_id}"
        response = self.get_api(site_url)
        return response
    
    def get_interface_info_by_device_id(self, device_uuid):
        """
        :method:   Returns information of all interfaces on specified device
        :param device_uuid:    The UUID of the device to be queried
        """
        get_url = f"/dna/intent/api/v1/interface/network-device/{device_uuid}"
        response = self.get_api(get_url)
        return response


#  Class containing the methods to test the DNAC API
class DnacTesting:
    """
    This class contains methods to test DNAC functionality via the API
    """
    dnac_methods = None
    
    def authenticate(self, dnac_device: dict):
        """
        :method:    Initiates the Authentication process
        :param dnac_device:    Dictionary containing the IP, Username, and Password of the DNAC device
        :return:    Returns True if authenticated successfully
        """
        dnac_ip = dnac_device["address"]
        username = dnac_device["username"]
        password = dnac_device["password"]
        
        self.dnac_methods = DnacApi(dnac_ip, username, password)
        
        #  If the TOKEN exists, then the Authentication was successful.
        if self.dnac_methods.TOKEN:
            return True
        return False
    
    def get_site_info(self):
        """
        :method:    Retrieves info on ALL sites associated with the server
        """
        response = self.dnac_methods.get_site_info()
        return response.json()
    
    def get_all_devices(self):
        """
        :method:    Retrieves ALL devices that have been discovered by DNAC
        """
        device_list = self.dnac_methods.get_device_list().json()
        device_dict = {}
        testing_devices = ["FOC2436V05E.cpwe-ra-cisco.local",
                           "SN-FOC2436V05G.cpwe-ra-cisco.local",
                           "SN-FOC2350V00A",
                           "SN-FOC2316V09L",
                           "C9500-N15-1.cpwe-ra-cisco.local",
                           "C9500-N15-2.cpwe-ra-cisco.local",
                           "C9300-N15-2.cpwe-ra-cisco.local",
                           "C9300-N15-1.cpwe-ra-cisco.local",
                           "C9300-N15-4.cpwe-ra-cisco.local",
                           "C9300-N14-Stack-1.cpwe-ra-cisco.local",
                           "C9500-N12-T1.cpwe-ra-cisco.local",
                           "C9500-N12-T2.cpwe-ra-cisco.local",
                           "C9300-N15-3.cpwe-ra-cisco.local",
                           "C9300-N12-stack-2.cpwe-ra-cisco.local",
                           "C9300-N12-Stack-3-Site2.cpwe-ra-cisco.local"
                           ]
        for item in device_list['response']:
            try:
                if item['hostname'] in testing_devices:
                    device_dict[item['hostname']] = {
                        "id": item['id'],
                        "managementIpAddress": item['managementIpAddress'],
                        "softwareVersion": item['softwareVersion']
                    }
            except KeyError:
                print(f"Caught an exception while trying to parse: {item}.")
                continue
            except AttributeError:
                print(f"Caught an exception while trying to parse: {item}.")
                print("Failed to parse the output.")
        return device_dict  # .keys()
    
    def command_runner(self, device_name, command):
        """
        :method:    This method will execute a command on a specific device
        :param device_name:    The hostname of the device
        :param command:    The command to be executed
        """
        
        device_id = self.dnac_methods.get_device_id_by_name(device_name)
        payload = {
            "name": "command-runner",
            "description": "command-runner-network-poller",
            "deviceUuids": [device_id],
            "commands": [command],
            "timeout": 120
        }
        response = self.dnac_methods.execute_command(payload)
        task_id = response.json()['response']['taskId']
        task_status = self.dnac_methods.get_task_by_id(task_id)
        attempt = 1
        while "CLI Runner request creation" in task_status['progress'] and attempt <= 5:
            sleep(2)
            task_status = self.dnac_methods.get_task_by_id(task_id)
            attempt += 1
        if "fileId" in task_status['progress']:
            file_id = task_status['progress'][11:-2]
            command_output = self.dnac_methods.get_file(file_id)
            command_output = command_output.json()[0]['commandResponses']['SUCCESS'][command]
            command_output = command_output.split('\n')
            return command_output[1:-1]
        else:
            print(f"Task Status: {task_status['progress']}\n"
                  f"Task failed to complete.  Please check the DNAC server for more information.")
            exit(1)
            # return task_status['progress']
    
    def get_device_info(self, device_name):
        """
        :method:    This method will retrieve the device details for a specific device
        :param device_name:    The hostname of the device
        """
        device_id = self.dnac_methods.get_device_id_by_name(device_name)
        response = self.dnac_methods.get_device_details_by_id(device_id)
        # pprint(response)
        return response
    
    def get_interface_list(self, device_name):
        """
        :method:    This method will retrieve the interface list for a specific device
        :param device_name:    The hostname of the device
        """
        device_id = self.dnac_methods.get_device_id_by_name(device_name)
        response = self.dnac_methods.get_interface_info_by_device_id(device_id)
        return response


#  The main function
def main():
    """
    This is the main function for the DNAC API testing
    """
    # Parsing the arguments
    parser = argparse.ArgumentParser()
    
    # Arguments for Catalyst Center Authentication:
    parser.add_argument('-ip', dest='ip_address',
                        help='The IP of the DNAC Server',
                        type=str, default='')
    parser.add_argument('-u', '--username', dest='username',
                        help='The username of the DNAC Server',
                        type=str, default='')
    parser.add_argument('-p', '--password', dest='password',
                        help='The password of the User selected',
                        type=str, default='')
    parser.add_argument('-d', '--device_name', dest='device_name',
                        help='The hostname of the device',
                        type=str, default='')
    parser.add_argument('-i', '--device_info', dest='device_info',
                        help='Show the device info for a specific device. '
                             'Requires the -d flag to be set.',
                        action='store_true')
    parser.add_argument('-c', '--command', dest='command',
                        help='The command to be executed on the device. '
                             'NOTE: commands with spaces must be enclosed in quotes. '
                             'Example: -c "sh logging"',
                        type=str, default='')
    parser.add_argument('-sd', '--show_drops', dest='show_drops',
                        help='Custom shortcut command for "show platform hardware qos..."',
                        action='store_true')
    parser.add_argument('-int', '--interface', dest='custom_interface',
                        help='NOTE: Only used with the custom "show drops" command. '
                             'The interface the user would like to run the command against. '
                             'Please provide the complete interface name (GigabitEthernet1/1 vs Gi1/1)',
                        type=str, default='')
    parser.add_argument('-s', '--site_info', dest='site_info',
                        help='Check the site info',
                        action='store_true')
    parser.add_argument('-l', '--show_devices', dest='show_devices',
                        help='Show all the devices in the Site',
                        action='store_true')
    # ip_address = parser.parse_args().ip_address
    # username = parser.parse_args().username
    # password = parser.parse_args().password
    args, argv[1:] = parser.parse_known_args(argv[1:])
    
    #  Create an instance of the DnacSetup class
    dnac = DnacTesting()
    
    #  Authenticate to DNAC
    try:
        ip_address = args.ip_address
        username = args.username
        password = args.password
        
        if ip_address and username and password:
            pass
        else:
            print("Not all required arguments have been provided")
            parser.print_help()
            exit(1)
        dnac_device = {
            "address": ip_address,
            "username": username,
            "password": password
        }
        is_authenticated = dnac.authenticate(dnac_device)
        if is_authenticated:
            pass
        else:
            print("The DNAC device has not been authenticated.")
            exit(1)
    except Exception as e:
        print(f"An error occurred while trying to authenticate the DNAC device: {e}\n"
              "Please check the provided ip address and credentials then try again.")
        exit(1)
    
    """
    FOR IE switches:
        This one needs to be run by interface, not sure if that can be done dynamically.
            Idea is to identify if there are any drops on the queues
        show platform hardware qos asic 0 int x  <--run for specific interface
        show prp stat egr
        show prp stat ing
        show prp stat nodeTableStatistics
        show prp channel 1 det

    For catalyst
        Same, this is per interface:
            show platform hardware fed switch active qos queue stats interface x  <--run for specific interface
    """
    # Customer requested custom commands for the IE and Catalyst devices.
    ie_device_commands = {
        "show drops": "show platform hardware qos asic 0 int {}"
    }
    catalyst_device_commands = {
        "show drops": "show platform hardware fed switch active qos queue stats interface {}"
    }
    # Customer only wanted specific devices to be used for the demonstration.
    # This can be modified to include all devices if needed.
    ie_switches = ["FOC2436V05E.cpwe-ra-cisco.local",
                   "SN-FOC2436V05G.cpwe-ra-cisco.local",
                   "SN-FOC2350V00A",
                   "SN-FOC2316V09L"
                   ]
    catalyst_switches = ["C9500-N15-1.cpwe-ra-cisco.local",
                         "C9500-N15-2.cpwe-ra-cisco.local",
                         "C9300-N15-2.cpwe-ra-cisco.local",
                         "C9300-N15-1.cpwe-ra-cisco.local",
                         "C9300-N15-4.cpwe-ra-cisco.local",
                         "C9300-N14-Stack-1.cpwe-ra-cisco.local",
                         "C9500-N12-T1.cpwe-ra-cisco.local",
                         "C9500-N12-T2.cpwe-ra-cisco.local",
                         "C9300-N15-3.cpwe-ra-cisco.local",
                         "C9300-N12-stack-2.cpwe-ra-cisco.local",
                         "C9300-N12-Stack-3-Site2.cpwe-ra-cisco.local"
                         ]
    
    #  Once authenticated, we can start testing the DNAC API
    try:
        def show_drops(device, drops_command, custom_interface=""):
            """
            :method:    This method will run the custom "show drops" command on the device
            :param device:    The hostname of the device
            :param drops_command:    The command to be executed
            :param custom_interface:    The interface the command will be run against
            EXAMPLE:
                On IE devices:
                    "drops_command" = "show platform hardware qos asic 0 int XXXXX"
                On Catalyst devices:
                    "drops_command" = "show platform hardware fed switch active qos queue stats interface XXXXX"
            """
            #  If a specific interface is specified, test against that interface
            if custom_interface:
                #  Get the list of interfaces on the physical device:
                interface_list = dnac.get_interface_list(device).json()
                interface_port_list = []
                for interface in interface_list['response']:
                    interface_port_list.append(interface['portName'])
                #  Verify that the interface(s) is/are valid
                for interface in custom_interface.split(','):
                    #  If the interface is not found, skip it
                    if interface not in interface_port_list:
                        # for device_interface in interface_list['response']:
                        #     if interface in device_interface['portName']:
                        print(f"The interface '{interface}' was not found on {device}.\nSkipping this interface.")
                        continue
                    else:
                        port_command = drops_command.format(interface)
                        print(f"\n\nRunning the command '{port_command}' on {device}:"
                              f"\n________{device}________{interface}________\n")
                        command_response = dnac.command_runner(device, port_command)
                        for _line in command_response:
                            print(_line)
            #  If no interface is specified, test against all interfaces
            else:
                interface_list = dnac.get_interface_list(device).json()
                for interface in interface_list['response']:
                    if "AppGigabitEthernet" in interface['portName']:
                        continue
                    elif "Gig" in interface['portName']:
                        port_command = drops_command.format(interface['portName'])
                        # print(f"{port_command=}")
                        print(f"\n\nRunning the command '{port_command}' on {device}:"
                              f"\n________{device}________{interface['portName']}________\n")
                        command_response = dnac.command_runner(device, port_command)
                        for _line in command_response:
                            print(_line)
        
        # Running user requested tests:
        if args.site_info:
            print("Retrieving site info:")
            pprint(dnac.get_site_info())
        if args.show_devices:
            print("Retrieving list of all devices:")
            all_devices = dnac.get_all_devices()
            for host in all_devices:
                print(f" -  {host}")
            # pprint(all_devices)
        if args.show_drops and args.device_name:
            raw_device_list = args.device_name.split(',')
            raw_command = "show drops"
            for device_name in raw_device_list:
                command = ""
                if device_name in catalyst_switches:
                    command = catalyst_device_commands[raw_command]
                elif device_name in ie_switches:
                    command = ie_device_commands[raw_command]
                if not command:
                    print("Unable to determine the device type.")
                    exit(1)
                show_drops(device_name, command, args.custom_interface)
        if args.device_name and args.command:
            raw_device_list = args.device_name
            raw_command_list = args.command
            device_list = []
            for device_name in raw_device_list.split(','):
                device_list.append(device_name)
            for command in raw_command_list.split(','):
                for device_name in device_list:
                    #  This is built to handle multiple custom commands.
                    #  If only using one, this can be greatly simplified.
                    raw_command = command
                    custom_command = ""
                    if device_name in catalyst_switches:
                        if command in catalyst_device_commands:
                            custom_command = catalyst_device_commands[command]
                            # print(f"{custom_command=}")
                    elif device_name in ie_switches:
                        if command in ie_device_commands:
                            custom_command = ie_device_commands[command]
                            # print(f"{custom_command=}")
                    
                    if raw_command == "show drops":
                        if not custom_command:
                            print("Unable to determine the device type.")
                            exit(1)
                        if args.custom_interface:
                            show_drops(device_name, custom_command, args.custom_interface)
                        else:
                            show_drops(device_name, custom_command)
                    #  If the command is not a "show drops" command, run it as is
                    else:
                        print(f"Running the command '{command}' on {device_name}:")
                        response = dnac.command_runner(device_name, command)
                        for line in response:
                            print(line)
        if args.device_info:
            if not args.device_name:
                print("The device name has not been provided. [-d]")
                parser.print_help()
                exit(1)
            print(f"Retrieving device info for {args.device_name}:")
            pprint(dnac.get_device_info(args.device_name))
        
        # If no arguments are provided, print the help menu
        for option, value in vars(args).items():
            if value:
                exit(0)
        # print("No arguments provided. Displaying help menu:")
        parser.print_help()
        exit(1)
    except Exception as e:
        print(f"An error occurred while trying to test the DNAC API: {e}")
        exit(1)


#  Run the main function
if __name__ == "__main__":
    main()
