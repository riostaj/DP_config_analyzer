from requests import Session
import requests
import json
from logging_helper import logging
import config as cfg

raw_data_path = "./Raw Data/"
config_path = "./Config/"


class Vision:

	def __init__(self, ip, username, password):
		self.ip = ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + ip
		self.sess = Session()
		self.sess.headers.update({"Content-Type": "application/json"})
		self.login()
		logging.info('Connecting to Vision')
		print('Connecting to Vision')
		self.device_list = self.getDeviceList()
		logging.info('Collecting DefensePro device list')
		print('Collecting DefensePro device list')		

	def login(self):

		login_url = self.base_url + '/mgmt/system/user/login'
		try:
			r = self.sess.post(url=login_url, json=self.login_data, verify=False)
			r.raise_for_status()
			response = r.json()
		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:
			logging.info(str(err))
			raise SystemExit(err)

		if response['status'] == 'ok':
			self.sess.headers.update({"JSESSIONID": response['jsessionid']})
			# print("Auth Cookie is:  " + response['jsessionid'])
		else:
			logging.info('Login error: ' + response['message'])
			exit(1)

	def getDeviceList(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self.sess.get(url=devices_url, verify=False)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}
		return dev_list

	
	def getSignatureProfileListByDevice(self, dp_ip):
		# Returns Signature profile list with rules
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSignaturesProfilesTable?props=rsIDSSignaturesProfileName,rsIDSSignaturesProfileRuleName,rsIDSSignaturesProfileRuleAttributeType,rsIDSSignaturesProfileRuleAttributeName"
		r = self.sess.get(url=policy_url, verify=False)
		sig_list = r.json()
		
		if sig_list.get("status") == "error":
			logging.info("Error: " + sig_list['message'])
			return []
		return sig_list

	def getBDOSProfileConfigByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNetFloodProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
		bdos_config = r.json()
		
		if bdos_config.get("status") == "error":
			logging.info("Error: " + bdos_config['message'])
			return []
		return bdos_config

	def getNetClassListByDevice(self, dp_ip):
		#Returns Network Class list with networks

		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsBWMNetworkTable/"
		r = self.sess.get(url=policy_url, verify=False)
		net_list = r.json()
		
		if net_list.get("status") == "error":
			logging.info("Error: " + net_list['message'])
			print("Error: " + net_list['message'])
			return []
		return net_list

	def getPolicyListByDevice(self, dp_ip):
		# Returns policies list with all its attributes
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSNewRulesTable"
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self.sess.get(url=policy_url, verify=False)
		policy_list = r.json()

		if policy_list.get("status") == "error":
			logging.info("Error: " + policy_list['message'])
			return []

		return policy_list

	def getDPConfigByDevice(self, dp_ip):
		# Downloads DefensePro configuration file
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/getcfg?saveToDb=false&includePrivateKeys=false&passphrase="
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self.sess.get(url=policy_url, verify=False)

		with open(config_path + f'{dp_ip}_config.txt', 'wb') as f:
			f.write(r.content) #Write to file

		return


	def getAllDPConfigs(self):
		# Download DefensePro configuration file for all DefensePro

		for key in self.device_list:
			self.getDPConfigByDevice(key)
		
		return

	def getFullPolicyDictionary(self):
		# Create Full Policies list with attributes dictionary per DefensePro

		full_pol_dic = {}
		for key, val in self.device_list.items():
			full_pol_dic[key] = {}
			full_pol_dic[key]['Name'] = val['Name']
			full_pol_dic[key]['Version'] = val['Version']
			full_pol_dic[key]['Policies'] = self.getPolicyListByDevice(key)
		
		with open(raw_data_path + 'full_pol_dic.json', 'w') as full_pol_dic_file:
			json.dump(full_pol_dic,full_pol_dic_file)

		return full_pol_dic

	def getFullSignatureProfileDictionary(self):
		# Create Full Signature profile list with rules dictionary per DefensePro
		full_sig_dic = {}
		for key in self.device_list:
			full_sig_dic[key] = self.getSignatureProfileListByDevice(key)
		
		with open(raw_data_path + 'full_sig_dic.json', 'w') as full_sig_dic_file:
			json.dump(full_sig_dic,full_sig_dic_file)
			
		return full_sig_dic

	def getFullNetClassDictionary(self):
		# Create Full Network class profile list with networks dictionary per DefensePro
		print(self.device_list)
		full_net_dic = {}
		for key,value in self.device_list.items():
			full_net_dic[key] = {}
			if self.getNetClassListByDevice(key) == ([]): #If DefensePro is unreachable
				full_net_dic[key]['rsBWMNetworkTable'] = []
			else:
				full_net_dic[key] = self.getNetClassListByDevice(key)

			full_net_dic[key]['Name'] = value['Name']
			
			
		with open(raw_data_path + 'full_net_dic.json', 'w') as full_net_dic_file:
			json.dump(full_net_dic,full_net_dic_file)
		
		return full_net_dic

	def getFullBDOSProfConfigDictionary(self):
		# Create Full BDOS Profile config list with all BDOS attributes dictionary per DefensePro

		full_bdosprofconf_dic = {}
		for key, val in self.device_list.items():
			full_bdosprofconf_dic[key] = {}
			full_bdosprofconf_dic[key]['Name'] = val['Name']
			full_bdosprofconf_dic[key]['Version'] = val['Version']
			full_bdosprofconf_dic[key]['Policies'] = self.getBDOSProfileConfigByDevice(key)
		
		with open(raw_data_path + 'full_bdosprofconf_dic.json', 'w') as full_bdosprofconf_dic_file:
			json.dump(full_bdosprofconf_dic,full_bdosprofconf_dic_file)

		return full_bdosprofconf_dic