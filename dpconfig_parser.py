import csv
import logging_helper

reports_path = "./Reports/"

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
		#Check if BDOS profile is in report mode
			
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
										bdos_writer.writerow([f'{pol_dp_name}' , f'{pol_dp_ip}' , f'{pol_name}' , f'BDOS Profile "{bdos_prof_name}" Learning suppression is less than 50%'])



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