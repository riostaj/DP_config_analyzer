import config as cfg
import csv
import logging_helper


reports_path = cfg.REPORTS_PATH

class DataMapper():
	def __init__(self, full_pol_dic, full_sig_dic, full_net_dic, full_bdosprofconf_dic,full_synprofconf_dic,full_dnsprofconf_dic):
		self.full_pol_dic = full_pol_dic
		self.full_sig_dic = full_sig_dic
		self.full_net_dic = full_net_dic
		self.full_bdosprofconf_dic = full_bdosprofconf_dic
		self.full_dnsprofconf_dic = full_dnsprofconf_dic
		self.full_synprofconf_dic = full_synprofconf_dic


		with open(reports_path + 'dpconfig_map.csv', mode='w', newline="") as dpconfigmap_report:
			dp_configmap_writer = csv.writer(dpconfigmap_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			dp_configmap_writer.writerow(['DefensePro Name' , 'DefensePro IP' ,	'DefensePro Version' , 'Policy Name','Policy Block/Report', 'Policy Packet Reporting','BDOS Profile Name','BDOS Profile Block/Report','BDOS Profile Bandwidth','BDOS TCP Quota','BDOS UDP Quota','BDOS ICMP Quota','BDOS Transparent Optimization','BDOS Packet Reporting','BDOS Learning Suppression','BDOS Footprint Strictness','BDOS UDP Packet Rate Detection Sensitivity','BDOS Burst-Attack Protection'])

	def isDPAvailable(self, dp_ip,dp_attr):
		# DP is considerd unavailable if DP is unreachable or no policy exists

		if dp_attr['Policies'] == ([]):
			return False
		return True

	def map_bdos(self,dp_ip,pol_bdos_prof_name):
		#This function maps the bdos profiles to dpconfig_map.csv
		bdos_settings = []

		if pol_bdos_prof_name == "":
			bdos_settings.append('N/A - No BDOS Profile')

		for bdos_dp_ip, bdos_dp_attr in self.full_bdosprofconf_dic.items():

			if not self.isDPAvailable(bdos_dp_ip, bdos_dp_attr):
				continue

			for bdos_prof in bdos_dp_attr['Policies']['rsNetFloodProfileTable']:
				bdos_prof_name = bdos_prof['rsNetFloodProfileName']
				
				if dp_ip == bdos_dp_ip and pol_bdos_prof_name == bdos_prof_name:
					bdos_settings.append(bdos_prof_name)
					
					########## Block/Report check#########
					if 'rsNetFloodProfileAction' in bdos_prof:
						if bdos_prof['rsNetFloodProfileAction'] == '0':
							bdos_settings.append('Report')
						elif bdos_prof['rsNetFloodProfileAction'] == '1':
							bdos_settings.append('Block')
						
					else:
						bdos_settings.append('N/A in this version')
					########## Map BDOS Bandwidth and Quota #########
					bdos_settings.append(bdos_prof['rsNetFloodProfileBandwidthIn']) # Bandwidth
					bdos_settings.append(bdos_prof['rsNetFloodProfileTcpInQuota'])
					bdos_settings.append(bdos_prof['rsNetFloodProfileUdpInQuota'])
					bdos_settings.append(bdos_prof['rsNetFloodProfileIcmpInQuota'])

					########## BDOS Transparent optimization check#########
					if 'rsNetFloodProfileTransparentOptimization' in bdos_prof:
						if bdos_prof['rsNetFloodProfileTransparentOptimization'] == '1':
							bdos_settings.append('Enabled')
						if bdos_prof['rsNetFloodProfileTransparentOptimization'] == '2':
							bdos_settings.append('Disabled')
					else:
						bdos_settings.append('N/A')
					#####################################


					########## BDOS Packet reporting check#########
					if 'rsNetFloodProfilePacketReportStatus' in bdos_prof:
						if bdos_prof['rsNetFloodProfilePacketReportStatus'] == '1':
							bdos_settings.append('Enabled')
						if bdos_prof['rsNetFloodProfilePacketReportStatus'] == '2':
							bdos_settings.append('Disabled')
					else:
						bdos_settings.append('N/A')
					#####################################

					########## BDOS Learning Suppression mapping #########
					if 'rsNetFloodProfileLearningSuppressionThreshold' in bdos_prof:
						bdos_settings.append(bdos_prof['rsNetFloodProfileLearningSuppressionThreshold'])
					else:
						bdos_settings.append('N/A in this version')

					########## BDOS Footprint Strictness #########
					if 'rsNetFloodProfileFootprintStrictness' in bdos_prof:
						if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '0':
							bdos_settings.append('Low')
						if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '1':
							bdos_settings.append('Medium')
						if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '2':
							bdos_settings.append('High')
					else:
						bdos_settings.append('N/A in this version')
					#####################################

					########## BDOS UDP Packet Rate Detection Sensitivity #########
					if 'rsNetFloodProfileLevelOfReuglarzation' in bdos_prof:
						if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '1':
							bdos_settings.append('Ignore or Disable')
						if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '2':
							bdos_settings.append('Low')
						if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '3':
							bdos_settings.append('Medium')
						if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '4':
							bdos_settings.append('High')
					else:
						bdos_settings.append('N/A in this version')
					#####################################

					########## BDOS Burst-Attack Protection #########
					if 'rsNetFloodProfileBurstEnabled' in bdos_prof:
						if bdos_prof['rsNetFloodProfileBurstEnabled'] == '1':
							bdos_settings.append('Enabled')
						if bdos_prof['rsNetFloodProfileBurstEnabled'] == '2':
							bdos_settings.append('Disabled')
					else:
						bdos_settings.append('N/A in this version')

		return bdos_settings

					

	def map_policy(self,dp_name,dp_ver,dp_ip,pol_name,policy):
		policy_settings = []
		policy_settings.append(dp_name)
		policy_settings.append(dp_ip)
		policy_settings.append(dp_ver)
		policy_settings.append(pol_name)

		if 'rsIDSNewRulesAction' in policy: # Check policy block/report action
			if policy['rsIDSNewRulesAction'] == '0':
				policy_settings.append('Report')
			elif policy['rsIDSNewRulesAction'] == '1':
				policy_settings.append('Block')

		else:
			policy_settings.append('N/A')

		if 'rsIDSNewRulesPacketReportingStatus'	in policy: # Check packet reporting enabled/Disabled
			if policy['rsIDSNewRulesPacketReportingStatus'] == '1':
				policy_settings.append('Enabled')
			elif policy['rsIDSNewRulesPacketReportingStatus'] == '2':
				policy_settings.append('Disabled')
		else:
			policy_settings.append('N/A')


		############Mapping BDOS Profile################
		if 'rsIDSNewRulesProfileNetflood' in policy: # Check if BDOS profile is configured
			pol_bdos_prof_name = policy['rsIDSNewRulesProfileNetflood']
			policy_settings = policy_settings + self.map_bdos(dp_ip,pol_bdos_prof_name)
				

		else:
			policy_settings.append('N/A')
		###############################################

		with open(reports_path + 'dpconfig_map.csv', mode='a', newline="") as dpconfigmap_report:
			dp_configmap_writer = csv.writer(dpconfigmap_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			dp_configmap_writer.writerow(policy_settings)

		policy_settings.clear()





	def run(self):
		for dp_ip,dp_attr in self.full_pol_dic.items():
			dp_name = dp_attr['Name']
			dp_ver = dp_attr['Version']

			if not self.isDPAvailable(dp_ip,dp_attr):
				continue

			for policy in dp_attr['Policies']['rsIDSNewRulesTable']: #key is rsIDSNewRulesTable, value is list of dictionary objects (each object is a dictionary which contains policy name and its attributes )
				pol_name = policy['rsIDSNewRulesName']
				pol_bdos_prof_name = policy['rsIDSNewRulesProfileNetflood']
				if pol_name != 'null':
					self.map_policy(dp_name,dp_ver,dp_ip,pol_name,policy)

	


		report = reports_path + 'dpconfig_mapper.csv'
		logging_helper.logging.info('Config mapping is complete')
		print('Config mapping is complete')

		return report
		