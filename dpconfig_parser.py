import csv
import logging_helper
import config as cfg
import ipaddress

reports_path = "./Reports/"
config_path = "./Config/"

class DataParser():
	def __init__(self, full_pol_dic, full_sig_dic, full_net_dic, full_bdosprofconf_dic):
		# with open('ful_pol_dic.txt') as fp:
		# 	self.full_pol_dic = fp.read()
		self.full_pol_dic = full_pol_dic
		self.full_sig_dic = full_sig_dic
		self.full_net_dic = full_net_dic
		self.full_bdosprofconf_dic = full_bdosprofconf_dic
		self.parseDict = {}

		with open(reports_path + 'dpconfig_report.csv', mode='w', newline="") as dpconfig_report:
				bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
				bdos_writer.writerow(['DefensePro Name' , 'DefensePro IP' ,	'Policy' , 'Recommendation'])

	def run(self):
		for dp_ip,dp_attr in self.full_pol_dic.items():
			dp_name = dp_attr['Name']
			self.initParser(dp_ip)

			if not self.isDPAvailable(dp_ip, dp_attr):
				continue

			#Variables For Per DP Iteration
			dp_version = self.getDPVersion(dp_attr['Version'])

			if dp_version != 6:
				lowest_pol_priority = self.getPolPriorities(dp_attr['Policies']['rsIDSNewRulesTable']) #for collecting list of policy priorities and further checking if catchall is has the least priority.

			catchall_glob = False
			hb_glob = False

			for policy in dp_attr['Policies']['rsIDSNewRulesTable']: #key is rsIDSNewRulesTable, value is list of dictionary objects (each object is a dictionary which contains policy name and its attributes )
				pol_name = policy['rsIDSNewRulesName']
				bdos_prof_name = policy['rsIDSNewRulesProfileNetflood']
				#Variables For Per Policy Iteration
				no_prof_pol = False #used for defining policy with no profiles applied
				# hbpolicy_src_net = False #used to identify Silicom bypass heartbeat policy
				# hbpolicy_dst_net = False #used to identify Silicom bypass heartbeat policy
				catchall_pol = False
				hb_pol = False

				#Init Policy Name
				self.parseDict[dp_ip][policy['rsIDSNewRulesName']] = []

				#Checks


				if not catchall_glob:
					#Necessary for catchall policy existance on DefensePro
					catchall_glob = self.iscatchAllPolicy(dp_ip, policy['rsIDSNewRulesSource'], policy['rsIDSNewRulesDestination']) 

				if not catchall_pol:
					#Necessary to check if specific policy is cathcall
					catchall_pol = self.iscatchAllPolicy(dp_ip, policy['rsIDSNewRulesSource'], policy['rsIDSNewRulesDestination']) 


				if not no_prof_pol:
					# Check if no profiles applied on policy
					no_prof_pol = self.isProfExistsPolicy(dp_name,dp_ip,policy)
				
				if self.isTwoWayPolicy(dp_ip,policy['rsIDSNewRulesDirection']):
					# Check if policy direction is Two Way
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Policy direction is Two way")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Policy direction is Two way'])


				if self.isReportModePolicy(dp_ip,policy['rsIDSNewRulesAction']):
					# Check if policy direction is Two Way
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Policy is in Report Only mode")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Policy is in Report Only mode'])

				if self.isDisabledPolicy(dp_ip,policy['rsIDSNewRulesState']):
					# Check if policy is disabled
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Policy is disabled")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Policy is disabled'])

				if self.isPacketReportingEnabledPolicy(dp_ip,policy['rsIDSNewRulesPacketReportingStatus']):
					# Check if packet reporting is disabled
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Packet reporting is disabled")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Packet reporting is disabled'])

				if self.isBDOSProfileAppliedPolicy(dp_ip,policy['rsIDSNewRulesProfileNetflood']) and not no_prof_pol:
					# Check if BDOS profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("BDOS profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'BDOS profile is not applied'])

				if self.isSignatureProfileAppliedPolicy(dp_ip,policy['rsIDSNewRulesProfileAppsec']) and not no_prof_pol:
					# Check if Signature profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Signature profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Signature profile is not applied'])
		
				if not no_prof_pol:
					self.isSignatureDOSAllAppliedPolicy(dp_name,dp_ip, policy, self.full_sig_dic)
						# Check if all Dos-All rules are applied on signature profile


				if self.isOOSAppliedPolicy(dp_ip,policy['rsIDSNewRulesProfileStateful']) and not no_prof_pol:
					# Check if Signature profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Out of State profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Out of State profile is not applied'])

				if self.isConnLimAppliedPolicy(dp_ip,policy['rsIDSNewRulesProfileConlmt']) and not no_prof_pol:
					# Check if Connection Limit profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Connection Limit profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Connection Limit profile is not applied'])

				if self.isSYNFloodAppliedPolicy(dp_ip,policy['rsIDSNewRulesProfileSynprotection']) and not no_prof_pol:
					# Check if SYN Flood profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("SYN Flood profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'SYN Flood profile is not applied'])

				if not self.isEAAFAppliedPolicy(dp_ip,policy) and not no_prof_pol:
					# Check if EAAF profile is applied on the policy
					# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("ERT Active Attacker Feed profile is not applied")
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'ERT Active Attacker Feed profile is not applied'])

				if not no_prof_pol:
					self.isDNSSigProfAppliedPolicy(dp_name, dp_ip,policy, self.full_sig_dic)
						# Check if DNS Services Signature + DOS-All profile exists on the DNS policy

				if not hb_pol:
					if no_prof_pol and not catchall_pol:
						hb_pol = self.isHBPolicy(dp_ip,policy,self.full_net_dic)

				if not hb_glob:
					if no_prof_pol and not catchall_pol:
						hb_glob = self.isHBPolicy(dp_ip,policy,self.full_net_dic)

				if catchall_pol and dp_version !=6:
					if int(policy['rsIDSNewRulesPriority']) != lowest_pol_priority:
						# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append(f'Catchall policy is not the least priority policy')
						with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
							bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
							bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'Catchall policy is not the least priority policy'])


			

			self.checkBDOSProf( dp_ip, dp_name, dp_attr['Policies']['rsIDSNewRulesTable'], self.full_bdosprofconf_dic)
			
				


			if not hb_glob and not catchall_glob:
				# self.parseDict[dp_ip]['N/A'].append(f'If DefensePro is deployed with Silicom Bypass switch, recommended policy for the heartbeat monitoring does not exist')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'If DefensePro is deployed with Silicom Bypass switch, recommended policy for the heartbeat monitoring does not exist'])


			if not catchall_glob: # Check if DP has no catchall policy
				# self.parseDict[dp_ip]['N/A'].append(f'No catchall policy')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , 'No catchall policy'])

			if dp_version == 7: # Check if DP v7.x has unequal instance distribution across the policies
				self.v7CountInstance(dp_name, dp_ip, dp_attr['Policies']['rsIDSNewRulesTable'])

			self.parseDPConfig(dp_ip, dp_name) #Perform DP config files checks

		self.netClassDuplication(self.full_net_dic, self.full_pol_dic) #Check if network class is unused, shared, duplicate or subnet of another class


		report = reports_path + 'dpconfig_report.csv'
		logging_helper.logging.info('Data parsing is complete')
		print('Data parsing is complete')
		return report



	def initParser(self, dp_ip):
		#Create dictionary with recommendations
		self.parseDict[dp_ip] = {}
		self.parseDict[dp_ip]['N/A'] = []

	def isDPAvailable(self, dp_ip, dp_attr):
		# DP is considerd unavailable if DP is unreachable or no policy exists
		dp_name = dp_attr['Name']
		if dp_attr['Policies'] == ([]):
			# self.parseDict[dp_ip] = "DefensePro is unreachable"
			with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'N/A' , 'DefensePro is unreachable'])
			return False

		if dp_attr['Policies'] == ({'rsIDSNewRulesTable': []}):
			# self.parseDict[dp_ip] = "DefensePro has no policies"
			with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'N/A' , 'DefensePro has no policies'])
			return False

		return True
	
	def getDPVersion(self, dp_version):
		#Get DP Version
		return int(dp_version.split('.')[0])

	def iscatchAllPolicy(self, dp_ip, src_net, dst_net):
		#Checks if the policy is catchall (any source and any in destination)
		if ("any" in src_net and "any" in dst_net):
			return True
	
		return False
	
	def isProfExistsPolicy(self, dp_name, dp_ip, policy):
		#Checks if policy has no security profiles applied
		pol_name = policy['rsIDSNewRulesName']
		for pol_key, pol_val in policy.items():
			if 'rsIDSNewRulesProfile' in pol_key:
				if pol_val != '' and pol_val !='OBSOLETE':
					return False

		# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Policy has no protection profiles applied")
		with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
			bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'{pol_name}' , 'Policy has no protection profiles applied'])
		return True

	def v7CountInstance(self, dp_name,dp_ip, policies_list):
		#Checks v7.x policies instances are distributed unequally across policies
		count_inst0 = 0
		count_inst1 = 0

		for policy in policies_list:

			if policy['rsIDSNewRulesInstanceId'] == "0": 
				# Count instance 0 for ver 7.x
				count_inst0 += 1

			if policy['rsIDSNewRulesInstanceId'] == "1": 
				# Count instance 0 for ver 7.x
				count_inst1 += 1
		if abs(count_inst0 - count_inst1) >=3:
			# self.parseDict[dp_ip]['N/A'].append("Unequal instance distribution across policies")
			with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
				bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
				bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'N/A' , 'Unequal instance distribution across policies'])

	def isTwoWayPolicy(self, dp_ip, pol_direction):
		# Checks if policy direction is two way
		if pol_direction == "2": #Two Way
			return True
		return False

	def isReportModePolicy(self, dp_ip, pol_mode):
		# Checks if policy direction is two way
		if pol_mode == "0": #Report mode
			return True
		return False
	def isDisabledPolicy(self, dp_ip, pol_state):
		# Checks if policy is disabled
		if pol_state == "2": #Disabled
			return True
		return False

	def isPacketReportingEnabledPolicy(self, dp_ip, pol_pack_rep_stat):
		# Checks if packet reporting is disabled
		if pol_pack_rep_stat == "2": #Disabled
			return True
		return False

	def isBDOSProfileAppliedPolicy(self, dp_ip, pol_bdos):
		# Checks if BDOS profile is applied on the policy
		if pol_bdos == "": #Empty = No BDOS profile is applied
			return True
		return False

	def isSignatureProfileAppliedPolicy(self, dp_ip, pol_signature):
		# Checks if Signature profile is applied on the policy
		if pol_signature == "": #Empty = No Signature profile is applied
			return True
		return False

	def isSignatureDOSAllAppliedPolicy(self, dp_name,dp_ip, policy, sig_list):
		# Check if all Dos-All rules are applied on signature profile which is not DNS, not empty and not DoS-All
		pol_name = policy['rsIDSNewRulesName']
		pol_dosall_sig_prof = False
		pol_sig_prof_name = policy['rsIDSNewRulesProfileAppsec']
		pol_sig_prof_dns = policy['rsIDSNewRulesProfileDNS']
		
		if pol_sig_prof_name != 'DoS-All' and pol_sig_prof_name != '' and pol_sig_prof_dns == '':  # if not "Dos-All", not empty and not a DNS policy
			for rule in sig_list[dp_ip]['rsIDSSignaturesProfilesTable']:
				rule_prof_name = rule['rsIDSSignaturesProfileName']
				rule_prof_attr = rule['rsIDSSignaturesProfileRuleAttributeName']
				if pol_sig_prof_name == rule_prof_name:
					if 'DoS - Slow Rate' and 'DoS - Floods' and 'DoS - Vulnerability' in rule_prof_attr:
						pol_dosall_sig_prof = True
			
			if pol_dosall_sig_prof == False:
				# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append("Signature profile " + policy['rsIDSNewRulesProfileAppsec'] + " does not have all Dos-All rules")
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'{pol_name}' , f'Signature profile "{pol_sig_prof_name}" does not include all the recommended "Dos-All" profile rules'])

	def checkBDOSProf(self, pol_dp_ip, pol_dp_name, policy_list , full_bdosprofconf_dic):
		#Check if BDOS profile configuration best practice
			
		for bdos_dp_ip, dp_attr in full_bdosprofconf_dic.items():


			if dp_attr['Policies'] == ([]):
				# "DefensePro is unreachable"
				continue

			if dp_attr['Policies'] == ({'rsNetFloodProfileTable': []}):
				# "DefensePro has no BDOS profiles"
				continue

			for bdos_prof in dp_attr['Policies']['rsNetFloodProfileTable']:
				bdos_count = 0
				nomatch = False

				for policy in policy_list:
					
					pol_prof_name = policy['rsIDSNewRulesProfileNetflood']
					pol_name = policy['rsIDSNewRulesName']

					bdos_prof_name = bdos_prof['rsNetFloodProfileName']

					if pol_dp_ip == bdos_dp_ip:
						
						if bdos_prof_name == pol_prof_name:
							bdos_count +=1
							
							if 'rsNetFloodProfileAction' in bdos_prof: #BDOS protection status (Block/Report)
								if bdos_prof['rsNetFloodProfileAction'] == "0": # 0 = Report
									# print(f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" is in Report-Only mode')
									with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
										bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" is in Report-Only mode'])

							if 'rsNetFloodProfileFootprintStrictness' in bdos_prof: #BDOS Strictness
								if bdos_prof['rsNetFloodProfileFootprintStrictness'] != "1": # 0= Low, 1 = Medium, 2 = Hight
									# print(f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" Strictness is not Medium')
									with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
										bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" Footprint Strictness is not Medium'])
						
							if 'rsNetFloodProfileLearningSuppressionThreshold' in bdos_prof: #BDOS Learning suppression
								if int(bdos_prof['rsNetFloodProfileLearningSuppressionThreshold']) < 50: #Less than 50%
									# print(f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" Learning suppression is set to ' + bdos_prof['rsNetFloodProfileLearningSuppressionThreshold'] + '%. Recommended setting is 50%')
									with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
										bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" Learning suppression is set to ' + bdos_prof['rsNetFloodProfileLearningSuppressionThreshold'] + '%. Recommended setting is 50%'])

							if 'rsNetFloodProfileLevelOfReuglarzation' in bdos_prof: #BDOS UDP Sensitivity
								if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '3': #1 = Ignore or Disable, 2 = Low , 3 = Medium, 4 = High
									#print(f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" UDP Packet Rate Detection Sensitivity is set to "Medium" while recommended setting is "Low" or "Ignore or Disable".')
									with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
										bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile {bdos_prof_name} UDP Packet Rate Detection Sensitivity is set to "Medium" while recommended setting is "Low" or "Ignore or Disable".'])

								if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '4': #1 = Ignore or Disable, 2 = Low , 3 = Medium, 4 = High
									# print(f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" UDP Packet Rate Detection Sensitivity is set to "High" while recommended setting is "Low" or "Ignore or Disable".')
									with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
										bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile {bdos_prof_name} UDP Packet Rate Detection Sensitivity is set to "High" while recommended setting is "Low" or "Ignore or Disable".'])

						else:
							nomatch = True

		



				if bdos_count == 0 and nomatch:
					#Checks if the BDOS profile is not applied on any policy
					# print (f'{pol_dp_name} - BDOS profile "{bdos_prof_name}" is orphaned ')
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'N/A' , f'BDOS Profile "{bdos_prof_name}" is not applied on any policy (orphaned)'])

		return

	def isOOSAppliedPolicy(self, dp_ip, pol_oos):
		# Checks if Out of State profile is applied on the policy
		if pol_oos == "": #Empty = No Out of State profile is applied
			return True
		return False

	def isConnLimAppliedPolicy(self, dp_ip, pol_connlim):
		# Checks if Out of State profile is applied on the policy
		if pol_connlim == "": #Empty = Connection limit profile is not applied
			return True
		return False

	def isSYNFloodAppliedPolicy(self, dp_ip, pol_synflood):
		# Checks if SYN Flood profile is applied on the policy
		if pol_synflood == "": #Empty = Connection limit profile is not applied
			return True
		return False

	def isEAAFAppliedPolicy(self, dp_ip, policy):
		# Checks if EAAF profile is applied on the policy
		if 'rsIDSNewRulesProfileErtAttackersFeed' in policy and policy['rsIDSNewRulesProfileErtAttackersFeed'] == '':
			return False
		return True

	def isDNSSigProfAppliedPolicy(self, dp_name, dp_ip,policy, sig_list):
		# Check if DNS Services Signature + DOS-All profile exists on the DNS policy
		pol_name = policy['rsIDSNewRulesName']
		dns_sig_prof = False
		# Check if all Dos-All rules are applied on signature profile which is not DNS, not empty and not DoS-All
		pol_dnsdosall_sig_prof = False
		pol_sig_prof_name = policy['rsIDSNewRulesProfileAppsec']
		pol_sig_prof_dns = policy['rsIDSNewRulesProfileDNS']
		

		if pol_sig_prof_name != '' and pol_sig_prof_name !='null' and pol_sig_prof_dns != '':
			# Define DNS policy - If policy has Signature Profile applied and has DNS Flood profile applied = DNS policy

			for rule in sig_list[dp_ip]['rsIDSSignaturesProfilesTable']:
				rule_prof_name = rule['rsIDSSignaturesProfileName']
				rule_prof_attr = rule['rsIDSSignaturesProfileRuleAttributeName']
				if pol_sig_prof_name == rule_prof_name:
					if 'DoS - Slow Rate' and 'DoS - Floods' and 'DoS - Vulnerability' and 'Network Services-DNS' in rule_prof_attr:
						dns_sig_prof = True

			
			if dns_sig_prof == False:
				# self.parseDict[dp_ip][policy['rsIDSNewRulesName']].append(f'DNS policy has Signature profile "{pol_sig_prof_name}" which does not include all the recommended DoS-All and Network Services-DNS rules')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'{pol_name}' , f'DNS policy has Signature profile "{pol_sig_prof_name}" which does not include all the recommended "DoS-All" and "Network Services-DNS" rules'])

	def isHBPolicy(self, dp_ip, policy, net_list):
		#Check if this policy is Silicom Bypass switch Heart Beat policy

		pol_src_net = policy['rsIDSNewRulesSource']
		pol_dst_net = policy['rsIDSNewRulesDestination']

		hbpolicy_src_net = False
		hbpolicy_dst_net = False

		if pol_src_net == '192.168.8.105' or pol_src_net == '1.1.1.1':
			hbpolicy_src_net = True

		if pol_dst_net == '192.168.8.100' or pol_dst_net == '1.1.1.2':
			hbpolicy_dst_net = True


		for netcl in net_list[dp_ip]['rsBWMNetworkTable']:
			net_name = netcl['rsBWMNetworkName']
			net_addr = netcl['rsBWMNetworkAddress']

			if pol_src_net == net_name:
				if net_addr == '192.168.8.105' or net_addr == '1.1.1.1':
					hbpolicy_src_net = True


			if pol_dst_net == net_name:
				if net_addr == '192.168.8.100' or net_addr == '1.1.1.2':
					hbpolicy_dst_net = True
					# print(f'dp {dp_ip} and policy ' + policy['rsIDSNewRulesName'] + 'hbpolicy_src_net ' + hbpolicy_src_net)


		if hbpolicy_src_net	and hbpolicy_dst_net:
			return True
		return False

	def getPolPriorities(self, pol_list):
		priorities_lst = []
		for policy in pol_list:
			if policy['rsIDSNewRulesName'] != 'null' and policy['rsIDSNewRulesPriority'] != 'null':
				pol_priority = int(policy['rsIDSNewRulesPriority'])
				priorities_lst.append(pol_priority)
				lowest_priority = min(priorities_lst)

		return lowest_priority

	def parseDPConfig(self, dp_ip, dp_name):
		#Parse DP config file for best practice configuration
	##########Normalize config file############
		with open(config_path + f'{dp_ip}_config.txt', 'r') as f:
			config = f.read()
		
			config = config.replace('\\'"\n","") #Normalize splitted lines (\\\r\n)

		with open(config_path + f'{dp_ip}_config.txt', 'w') as f:
			f.write(config) #Write updated lines
	############################################


		with open(config_path + f'{dp_ip}_config.txt') as f:
			
			content = f.read()

			if "\"status\":\"error\"" in content:
				print(f'{dp_name} - Error downloading configuration file - {content}')
				logging_helper.logging.info(f'{dp_name} - Error downloading configuration file - {content}')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'{dp_name} - Error downloading configuration file - {content}'])
	
			if "!Software Version: 8" in content: # For software versions other than 8.x
				if "manage web-services status set enable" in content:
					# print(f'{dp_ip} Web-services access is enabled. In most cases this service is required for external automation through SOAP calls. Disable if unnecessary. To disable - > "manage web-services status set disable"')
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'Web-services access is enabled. In most cases this service is required for external automation through SOAP calls. Disable if unnecessary. To disable - > "manage web-services status set disable"'])


			if not "!Software Version: 8" in content: # For software versions other than 8.x
				# print(dp_ip +' is not v8.x')
				if "manage web status set enable" in content:
					# print(f'{dp_ip} HTTP Access on port 80 is enabled. To disable - > "manage web status set disable"')
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'HTTP Access on port 80 is enabled. To disable - > "manage web status set disable"'])


			if "manage ssh session-timeout set" not in content:
				# print(f'{dp_ip} - SSH Timeout is set to default (v8.x 10 min, v6.x 5 min). Recommended timeout is {str(cfg.SSH_TIMEOUT)} min. To set SSH timeout -> manage ssh session-timeout set 120')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'SSH Timeout is set to default (v8.x 10 min, v6.x 5 min). Recommended timeout is {str(cfg.SSH_TIMEOUT)} min. To set SSH timeout -> manage ssh session-timeout set {str(cfg.SSH_TIMEOUT)}'])
		
			if "services auditing status set Enabled" not in content:
				# print(f'{dp_name} - Service auditing is not enabled. To enable -> services auditing status set enable')

				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'Service auditing is not enabled. To enable -> services auditing status set enable'])

			if "services auditing type set Extended" not in content:
				# print(f'{dp_name} - Extended service auditing is not enabled. To enable -> services auditing type set Extended')

				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'Extended service auditing is not enabled. To enable -> services auditing type set Extended'])


			if "manage telnet status set enable" in content:
				# print(f'{dp_ip} Telnet Access on port 23 is enabled. To disable - > "manage telnet status set disable"')
				with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
					bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'Telnet Access on port 23 is enabled. To disable - > "manage telnet status set disable"'])

			f.seek(0) #back to first line to parse line by line

			for line in f:
				if "manage ssh session-timeout set" in line and f'manage ssh session-timeout set {str(cfg.SSH_TIMEOUT)}' not in line:
					# print(f'{dp_ip} - SSH timeout is set to -' + str(line.split()[4]) + f' minutes. Recommended SSH timeout is {str(cfg.SSH_TIMEOUT)} min. To set SSH timeout -> manage ssh session-timeout set 120')
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' , f'N/A' , f'SSH timeout is set to ' + str(line.split()[4]) + f' minutes. Recommended SSH timeout is {str(cfg.SSH_TIMEOUT)} min. To set SSH timeout -> manage ssh session-timeout set {str(cfg.SSH_TIMEOUT)}'])

	
		return

	def netClassDuplication(self, full_net_dic, full_pol_dic):

		uniq_net_name_dic = {}

		for net_dic_dp_ip,net_dic_dp_ip_attr in full_net_dic.items():
		#Create unique list of network class names in order to identify orphaned network classes later one
			
			uniq_net_name_dic[net_dic_dp_ip] = {}
			uniq_net_name_dic[net_dic_dp_ip]['Name'] = net_dic_dp_ip_attr['Name']
			uniq_net_name_dic[net_dic_dp_ip]['Policies'] = []


			if net_dic_dp_ip_attr == ([]):
				#if unreachable do not perform other tests
				continue

			for net in net_dic_dp_ip_attr['rsBWMNetworkTable']:
				net_name = net['rsBWMNetworkName']
				if net_name != 'any' and net_name != 'any_ipv4' and net_name != 'any_ipv6' and net_name not in uniq_net_name_dic[net_dic_dp_ip]['Policies']:
					uniq_net_name_dic[net_dic_dp_ip]['Policies'].append(net_name)


		###########################Check unused or shared network classes across policies###############

		for unique_name_dic_dp_ip,unique_net_dic_attr in uniq_net_name_dic.items():
			#Check unused network classes
			unique_dp_name = unique_net_dic_attr['Name']
			

			for net in unique_net_dic_attr['Policies']:
				timesfound = 0 

				for pol_dic_dp_ip,pol_dic_dp_ip_attr in full_pol_dic.items():

					pol_dic_dp_name = pol_dic_dp_ip_attr['Name']

					if pol_dic_dp_ip_attr['Policies'] == ([]):
						#if unreachable
						continue

					if pol_dic_dp_ip_attr['Policies'] == ({'rsIDSNewRulesTable': []}):
						#if no policies
						continue

					if unique_name_dic_dp_ip == pol_dic_dp_ip:
						pol_count_list = []

						for pol_attr in pol_dic_dp_ip_attr['Policies']['rsIDSNewRulesTable']:
							pol_dic_pol_name = pol_attr['rsIDSNewRulesName']
							pol_dic_src = pol_attr['rsIDSNewRulesSource']
							pol_dic_dst = pol_attr['rsIDSNewRulesDestination']
							if net != 'any' and net != 'any_ipv4' and net != 'any_ipv6':
								
								if net == pol_dic_src:
									timesfound +=1
									pol_count_list.append(pol_dic_pol_name)
			
								if net == pol_dic_dst:
									timesfound +=1
									pol_count_list.append(pol_dic_pol_name)



				if timesfound == 0 and net != 'any' and net != 'any_ipv4' and net != 'any_ipv6':

					# print(f'{unique_dp_name} - Network class "{net}" is not applied on any policy')	
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{unique_dp_name}' , f'{unique_name_dic_dp_ip}' , f'N/A' , f'Network class "{net}" is not applied on any policy'])

				if timesfound > 1:

					# print(f'{unique_dp_name} - Network classss "{net}" is shared across multiple policies {pol_count_list}')
					with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
						bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{unique_dp_name}' , f'{unique_name_dic_dp_ip}' , f'N/A' , f'Network classss "{net}" is shared across multiple policies {pol_count_list}'])

		##########################Check if netclass is subnet of superclass or there are duplicate network classes###########

		for pol_dic_dp_ip,pol_dic_dp_ip_attr in full_pol_dic.items(): ###Iterate through network classes
			pol_dic_dp_name = pol_dic_dp_ip_attr['Name']

			if pol_dic_dp_ip_attr['Policies'] == ([]):
				#if unreachable
				continue

			if pol_dic_dp_ip_attr['Policies'] == ({'rsIDSNewRulesTable': []}):
				#if no policies
				continue

			for pol_attr in pol_dic_dp_ip_attr['Policies']['rsIDSNewRulesTable']:
				pol_dic_pol_name = pol_attr['rsIDSNewRulesName']
				pol_dic_src = pol_attr['rsIDSNewRulesSource']
				pol_dic_dst = pol_attr['rsIDSNewRulesDestination']



				for net_dic_dp_ip,net_dic_dp_ip_attr in full_net_dic.items(): ###Iterate through policy list 
					duplicate = 0
					if net_dic_dp_ip_attr == ([]):
						#if unreachable do not perform other tests
						continue

					for net_attr in net_dic_dp_ip_attr['rsBWMNetworkTable']: #for each netclass element

						net_cl_name = net_attr['rsBWMNetworkName']
						net_cl_address = net_attr['rsBWMNetworkAddress']
						net_cl_mask = net_attr['rsBWMNetworkMask']
						net_mode = net_attr['rsBWMNetworkMode']

						ipv6 = False

						if net_cl_name == 'any' or net_cl_name == 'any_ipv4' or net_cl_name == 'any_ipv6':
							continue
					
						if net_dic_dp_ip == pol_dic_dp_ip:
							
							if net_cl_name == pol_dic_src or net_cl_name == pol_dic_dst: #only if netclass applied on policy

								if net_mode == '2': #Corner case for network classes configured as ip ranges. Currently skip it
									continue

								if ":" in net_cl_address:
									net_addrandmask = ipaddress.IPv6Network(net_cl_address + "/" + net_cl_mask)
									ipv6 = True

								else:
									net_addrandmask = ipaddress.IPv4Network(net_cl_address + "/" + net_cl_mask)


								for net_attr_2 in net_dic_dp_ip_attr['rsBWMNetworkTable']:#for each netclass element
									net_mode_2 = net_attr_2['rsBWMNetworkMode']
									net_cl_name_2 = net_attr_2['rsBWMNetworkName']
									net_cl_address_2 = net_attr_2['rsBWMNetworkAddress']
									net_cl_mask_2 = net_attr_2['rsBWMNetworkMask']


									if net_cl_name_2 == 'any' or net_cl_name_2 == 'any_ipv4' or net_cl_name_2 == 'any_ipv6':
										continue

									if net_mode_2 == '2': #Corner case for network classes configured as ip ranges. Currently skip it
										continue			
									


									if ":" in net_cl_address_2:
										net_addrandmask_2 = ipaddress.IPv6Network(net_cl_address_2 + "/" + net_cl_mask_2)
										ipv6 = True

									else:
										net_addrandmask_2 = ipaddress.IPv4Network(net_cl_address_2 + "/" + net_cl_mask_2)

									if net_attr == net_attr_2:
										continue

									if (type(net_addrandmask) == ipaddress.IPv6Network) and (type(net_addrandmask_2) == ipaddress.IPv6Network):
										if net_addrandmask.subnet_of(net_addrandmask_2) and net_addrandmask !=net_addrandmask_2: # search for subnet of
											# print(f'{pol_dic_dp_name} Network class "{net_cl_name}" has a network subnet "{net_addrandmask}" which is subnet of "{net_addrandmask_2}" in another network class ' + net_cl_name_2)
											with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
												bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
												bdos_writer.writerow([f'{pol_dic_dp_name}' , f'{pol_dic_dp_ip}' , f'{pol_dic_pol_name}' , f'Network class "{net_cl_name}" has a network subnet "{net_addrandmask}" which is subnet of "{net_addrandmask_2}" in another network class "{net_cl_name_2}"'])


										if net_addrandmask == net_addrandmask_2 and duplicate == 0: # search for duplicate networks
											duplicate +=1
											# print(f'{pol_dic_dp_name} Duplicate network {net_addrandmask} in network classes {net_cl_name} and ' + net_cl_name_2)
											with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
												bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
												bdos_writer.writerow([f'{pol_dic_dp_name}' , f'{pol_dic_dp_ip}' , f'{pol_dic_pol_name}' , f'Duplicate network {net_addrandmask} in network classes {net_cl_name} and "{net_cl_name_2}"'])




									if (type(net_addrandmask) == ipaddress.IPv4Network) and (type(net_addrandmask_2) == ipaddress.IPv4Network):

										if net_addrandmask.subnet_of(net_addrandmask_2) and net_addrandmask !=net_addrandmask_2: # search for subnet of
											# print(f'{pol_dic_dp_name} Network class "{net_cl_name}" has a network subnet "{net_addrandmask}" which is subnet of "{net_addrandmask_2}" in another network class ' + net_cl_name_2)
											with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
												bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
												bdos_writer.writerow([f'{pol_dic_dp_name}' , f'{pol_dic_dp_ip}' , f'{pol_dic_pol_name}' , f'Network class "{net_cl_name}" has a network subnet "{net_addrandmask}" which is subnet of "{net_addrandmask_2}" in another network class "{net_cl_name_2}"'])


										if net_addrandmask == net_addrandmask_2 and duplicate == 0: # search for duplicate networks
											duplicate +=1
											# print(f'{pol_dic_dp_name} Duplicate network {net_addrandmask} in network classes {net_cl_name} and ' + net_cl_name_2)
											with open(reports_path + 'dpconfig_report.csv', mode='a', newline="") as dpconfig_report:
												bdos_writer = csv.writer(dpconfig_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
												bdos_writer.writerow([f'{pol_dic_dp_name}' , f'{pol_dic_dp_ip}' , f'{pol_dic_pol_name}' , f'Duplicate network {net_addrandmask} in network classes {net_cl_name} and "{net_cl_name_2}"'])

		return