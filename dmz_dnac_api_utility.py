#! /usr/bin/env python3
# coding=utf-8
"""
File: dmz_dnac_api_utility.py
Author: Ryan Kroetch
Date: February 2024
Purpose: This will test for DNAC integration and functionality via the API
"""
#  Basic Python package imports
# from time import sleep
# import time
from sys import argv
# import re
import json
from pprint import pprint
import logging
import requests
from requests.auth import HTTPBasicAuth
import argparse
import urllib3

urllib3.disable_warnings()
log = logging.getLogger(__name__)


#  Class containing the API calls for the DNAC server
class DnacApi:
    """
    This module facilitates DNA-C operations within test scripts.  It is intended to be used for TESTING and not for
    production environments.
    NOTE:  DNAC TOKENs expire after 1 hour so long tests may require re-authentication.  This has been built into the
           base function calls (get, post, put, delete) and should not require manual intervention.
    """

    def __init__(self, dnac_ip, USERNAME, PASSWORD):
        self.dnac_ip = dnac_ip
        self.USERNAME = USERNAME
        self.PASSWORD = PASSWORD
        self.TOKEN = ""  # Token is valid for 1 hour
        self.DNAC_BASE_URL = ""
        self.HEADERS = ""
        self.authenticate_dnac(dnac_ip, USERNAME, PASSWORD)

    def authenticate_dnac(self, dnac_ip, USERNAME, PASSWORD):
        """
        method: authenticates the DNAC server with the given credentials,
            returns Token on the successful authentication
        param dnac_ip:    IP address of the DNAC
        param USERNAME:    Username for the DNAC
        param PASSWORD:    Password for the given Username
        """
        BASE_URL = "https://" + str(dnac_ip)
        AUTH_URL = "/dna/system/api/v1/auth/token"
        URL = BASE_URL + AUTH_URL
        log.info("POST {}".format(URL))
        response = requests.post(URL, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)

        if response.status_code == 200:
            log.info("DNAC Authentication Status Code : {}".format(response.status_code))
            # global TOKEN, DNAC_BASE_URL, HEADERS
            self.TOKEN = response.json()['Token']
            self.DNAC_BASE_URL = BASE_URL
            self.HEADERS = {'X-Auth-Token': self.TOKEN, 'Content-Type': 'application/json'}
            return response.status_code
        else:
            log.error("DNAC Authentication Status Code : {}".format(response.status_code))
            log.error(response.json())
            log.error('DNAC Authentication failed')
            return response.status_code

    def get_API(self, get_url, query_string={}):
        """
        method: All the GET API calls will be excuted by this method
        param: get_url - GET URL for the resource
               query_string - Query Paramter to the Get API call (if necessary)
        """
        URL = self.DNAC_BASE_URL + get_url
        log.info("GET {}".format(URL))
        if query_string:
            log.info("Query Parameters : {}".format(query_string))
            response = requests.get(URL, headers=self.HEADERS, params=query_string, verify=False)
        else:
            response = requests.get(URL, headers=self.HEADERS, verify=False)

        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            # log.info(response.json())
            return response
        elif response.status_code in (401, 403):
            log.warning(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.USERNAME, self.PASSWORD)
            # resubmitting request after authentication
            if query_string:
                log.info("Query Parameters : {}".format(query_string))
                response = requests.get(URL, headers=self.HEADERS, params=query_string, verify=False)
            else:
                response = requests.get(URL, headers=self.HEADERS, verify=False)
            return response
        else:
            log.error(response)
            log.error(response.json())
            return False

    def post_API(self, post_url, json_payload):
        """
        method: All the POST API calls will be excuted by this method
        param: post_url - POST URL for the resource
               json_payload - Input payload for that API call
        """
        URL = self.DNAC_BASE_URL + post_url
        log.info("POST {}".format(URL))
        log.info("Payload : {}".format(json_payload))
        response = requests.post(URL, headers=self.HEADERS, json=json_payload, verify=False)

        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            return response
        elif response.status_code in (401, 403):
            log.warning(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.USERNAME, self.PASSWORD)
            # resubmitting request after authentication
            response = requests.post(URL, headers=self.HEADERS, json=json_payload, verify=False)
            return response
        else:
            log.error(response)
            log.error(response.json())
            return False

    def put_API(self, put_url, payload):
        """
        method: All the PUT API calls will be excuted by this method
        param: put_url - PUT URL for the resource
               payload - Input payload for that API call
        """
        URL = self.DNAC_BASE_URL + put_url
        log.info("PUT {}".format(URL))
        log.debug("Payload : {}".format(payload))
        response = requests.put(URL, headers=self.HEADERS, json=payload, verify=False)

        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            return response
        elif response.status_code in (401, 403):
            log.warning(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.USERNAME, self.PASSWORD)
            # resubmitting request after authentication
            response = requests.put(URL, headers=self.HEADERS, json=payload, verify=False)
            return response
        else:
            log.error(response)
            log.error(response.json())
            return False

    def delete_API(self, delete_url, query_string={}):
        """
        method: All the DELETE API calls will be excuted by this method
        param: delete_url - Delete URL for the resource
               query_string - Query Paramter to the Delete API call (if necessary)
        """
        URL = self.DNAC_BASE_URL + delete_url
        log.info("DELETE {}".format(URL))
        if query_string:
            log.info("Query Parameters : {}".format(query_string))
            response = requests.delete(URL, headers=self.HEADERS, params=query_string, verify=False)
        else:
            response = requests.delete(URL, headers=self.HEADERS, verify=False)

        # Checking if re-authentication is needed
        if response.status_code == 200 or response.status_code == 202:
            log.info(response.json())
            return response
        elif response.status_code in (401, 403):
            log.warning(f"status code: {response.status_code}  |  Token has expired.  Re-authenticating to DNAC.")
            self.authenticate_dnac(self.dnac_ip, self.USERNAME, self.PASSWORD)
            # resubmitting request after authentication
            if query_string:
                log.info("Query Parameters : {}".format(query_string))
                response = requests.delete(URL, headers=self.HEADERS, params=query_string, verify=False)
            else:
                response = requests.delete(URL, headers=self.HEADERS, verify=False)
            return response
        else:
            log.error(response)
            log.error(response.json())
            return False
    
    def get_site_info(self):
        """
        method: Get the Site Info
        """
        SITE_URL = '/dna/intent/api/v1/site'
        response = self.get_API(SITE_URL)
        # log.debug(response.json())
        return response

    def get_device_list(self):
        """
        :method:    Get all devices (and device details) that DNAC has discovered
        """
        log.info("Retrieving list of discovered devices")
        DEVICE_LIST_URL = '/dna/intent/api/v1/network-device'
        response = self.get_API(DEVICE_LIST_URL)
        # log.debug(response.json())
        return response
    
    def get_device_id_by_name(self, device_name):
        """
        :method:    Get the device UUID given a specific device name
        :param device_name:    The hostname of the device
        :return:    Returns the device ID (or status code if not successful)
        """
        device_list = self.get_device_list()
        for device in device_list.json()['response']:
            # log.info(device)
            if device['hostname'].split('.')[0] == device_name:
                log.info(device['id'])
                return device['id']
        log.info(f"{device_name} was not found.")
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
        response = self.post_API(site_url, payload)
        return response
    
    def get_device_details_by_id(self, device_id):
        """
        method: Returns detailed Network Device information retrieved by Device UUID for any given point of time.
        param: device_id - Device UUID

        """
        get_url = '/dna/intent/api/v1/device-detail'
        query_param = {"searchBy": device_id, "identifier": "uuid"}
        response = self.get_API(get_url, query_param)
        if response is False:
            return False
        return response.json()['response']

    def get_device_health(self, device_id):
        """
        method: return the overall health score of the given device
        param: device_id - Device ID
        """
        device_details = self.get_device_details_by_id(device_id)
        log.info(json.dumps(device_details, indent=2))
        if 'overallHealth' in device_details:
            return device_details['overallHealth']
        return None


#  Class containing the methods to test the DNAC API
class DnacTesting:
    """
    This class contains methods to test DNAC functionality via the API
    """

    def authenticate(self, dnac_device: dict):
        """
        :method:    Initiates the Authentication process
        :param dnac_device:    Dictionary containing the IP, Username, and Password of the DNAC device
        :return:    Returns True if authenticated successfully
        """
        dnac_ip = dnac_device["address"]
        username = dnac_device["username"]
        password = dnac_device["password"]
        # log.debug(dnac_ip, username, password)
        self.dnac_methods = DnacApi(dnac_ip, username, password)
        
        #  If the TOKEN exists, then the Authentication was successful.
        if self.dnac_methods.TOKEN:
            print("The Token has been created successfully")
            return True
        return False

    def get_site_info(self):
        """
        :method:    Retrieves info on ALL sites associated with the server
        """
        log.info("Retrieving site info")
        response = self.dnac_methods.get_site_info()
        log.debug(response.json())
        pprint(response.json())
        return response

    def get_all_devices(self):
        """
        :method:    Retrieves ALL devices that have been discovered by DNAC
        """
        log.info("Retrieving list of all devices.")
        device_list = self.dnac_methods.get_device_list().json()
        # log.debug(device_list)
        log.info("parsing the output")
        device_dict = {}
        for item in device_list['response']:
            try:
                if item['hostname']:
                    device_dict[item['hostname'].split('.')[0]] = {
                        "id": item['id'],
                        "managementIpAddress": item['managementIpAddress'],
                        "softwareVersion": item['softwareVersion']
                    }
            except KeyError:
                log.exception(f"Caught an exception while trying to parse: {item}.")
                continue
            except AttributeError:
                log.exception(f"Caught an exception while trying to parse: {item}.")
                print("Failed to parse the output.")
        log.info(device_dict.keys())
    
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
        log.debug(response.json())
        return response
    
    def get_device_info(self, device_name):
        """
        :method:    This method will retrieve the device details for a specific device
        :param device_name:    The hostname of the device
        """
        device_id = self.dnac_methods.get_device_id_by_name(device_name)
        response = self.dnac_methods.get_device_details_by_id(device_id)
        log.debug(response)
        return response
    
    def get_device_health(self, device_name):
        """
        :method:    This method will retrieve the health score for a specific device
        :param device_name:    The hostname of the device
        """
        device_id = self.dnac_methods.get_device_id_by_name(device_name)
        response = self.dnac_methods.get_device_health(device_id)
        log.debug(response)
        return response


#  The main function
def main():
    """
    This is the main function for the DNAC API testing
    """
    # Parsing the arguments
    try:
        parser = argparse.ArgumentParser()
        
        # Arguments for Catalyst Center Authentication:
        parser.add_argument('-ip', dest='ip_address',
                            help='The IP of the DNAC Server',
                            type=str, default=''
                            )
        parser.add_argument('-u', '--username', dest='username',
                            help='The username of the DNAC Server',
                            type=str, default=''
                            )
        parser.add_argument('-p', '--password', dest='password',
                            help='The password of the User selected',
                            type=str, default=''
                            )
        parser.add_argument('--run_command', dest='run_command',
                            help='Takes input as "device_name|command"  Example: "device1|sh logging"',
                            type=str, default=''
                            )
        parser.add_argument('-d', '--device_hostname', dest='device_name',
                            help='The hostname of the device',
                            type=str, default=''
                            )
        parser.add_argument('-c', '--command', dest='command',
                            help='The command to be executed on the device.  Example: "sh logging"',
                            type=str, default=''
                            )
        parser.add_argument('--site_info', dest='site_info',
                            help='Check the site info',
                            type=str, default=''
                            )
        parser.add_argument('--show_devices', dest='show_devices',
                            help='Show all the devices in the Site',
                            type=str, default=''
                            )
        parser.add_argument('--show_device_info', dest='show_device_info',
                            help='Show the device info for a specific device.  Requires the -d flag to be set.',
                            type=str, default=''
                            )
        parser.add_argument('--show_device_health', dest='show_device_health',
                            help='Show the device health for a specific device.  Requires the -d flag to be set.',
                            type=str, default=''
                            )
                            
        ip_address = parser.parse_args().ip_address
        username = parser.parse_args().username
        password = parser.parse_args().password
        args, argv[1:] = parser.parse_known_args(argv[1:])
    except Exception as e:
        print(f"An error occurred while trying to parse the arguments: {e}")
        parser.print_help()
        exit(1)
        
    #  Create an instance of the DnacSetup class
    dnac = DnacTesting()
    
    #  Authenticate to DNAC
    try:
        if ip_address and username and password:
            print("All required arguments have been provided")
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
            print("The DNAC device has been authenticated.")
        else:
            print("The DNAC device has not been authenticated.")
            exit(1)
    except Exception as e:
        print(f"An error occurred while trying to authenticate the DNAC device: {e}")
        exit(1)
    
    #  Once authenticated, we can start testing the DNAC API
    try:
        if args.site_info:
            dnac.get_site_info()
        if args.show_devices:
            dnac.get_all_devices()
        if args.run_command:
            if args.device_name and args.command:
                device_name = args.device_name
                command = args.command
            elif '|' not in args.run_command:
                print("The command should be in the format '<device_name>|<command>'.  Example: 'device1|sh logging'")
                exit(1)
            else:
                device_name, command = args.run_command.split('|')
            dnac.command_runner(device_name, command)
        if args.show_device_info:
            if not args.device_name:
                print("The device name has not been provided. [-d]")
                parser.print_help()
                exit(1)
            dnac.get_device_info(args.device_name)
        if args.show_device_health:
            if not args.device_name:
                print("The device name has not been provided. [-d]")
                parser.print_help()
                exit(1)
            dnac.dnac_methods.get_device_health(args.device_name)
    except Exception as e:
        print(f"An error occurred while trying to test the DNAC API: {e}")
        exit(1)
    

#  Run the main function
if __name__ == "__main__":
    main()
    