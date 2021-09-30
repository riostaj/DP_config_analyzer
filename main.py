import config as cfg
import json
from vision import Vision
from dpconfig_parser import DataParser
import bdos_parser
import traffic_stats_parser
import urllib3

import logging_helper
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#Arguments variables
nobdosreport = False
nodpconfigparsing = False
getdatafromvision = True
alarm = True
test_email_alarm = False
notraffic_stats = False
report = []

reports_path = "./Reports/"
raw_data_path = "./Raw Data/"
requests_path = "./Requests/"


logging_helper.log_setup(cfg.LOG_FILE_PATH, cfg.SYSLOG_SERVER, cfg.SYSLOG_PORT)


for i in sys.argv:
	#Running script with arguments
	if i.lower() == "--no-bdos":
		#Running script without BDOS report (DP config parsing config only)
		nobdosreport = True
		logging_helper.logging.info('Running script without BDOS report')
		with open('no-bdos.txt', 'w') as no_bdos:
			no_bdos.write('Script run with no bdos report')
		report.append('no-bdos.txt')

	if i.lower() == "--no-dp-config-parsing":
		#Running script without dp config parsing (BDOS report only)
		nodpconfigparsing = True
		logging_helper.logging.info('Running script without parsing DP config')

	if i.lower() == "--use-cache-data":
		#No data collection from vision- running script using previously collected data
		getdatafromvision = False
		logging_helper.logging.info('Running script using cache data only')
		
	if i.lower() == "--no-alarm":
		#Run script without sending email alert.
		alarm = False
		logging_helper.logging.info('Running script without email alarm')

	if i.lower() == "--test-alarm":
		#Run script- test email alert only
		logging_helper.logging.info('Running script to test email alarm only')
		getdatafromvision = False
		test_email_alarm = True
		nobdosreport = True
		nodpconfigparsing = True

	if i.lower() == "--no-traffic-stats":
		#Running script without writing all traffic and bdos stats in a separate file
		notraffic_stats = True
		logging_helper.logging.info('Running script without writing all traffic and bdos stats in a separate file')



def getBDOSReportFromVision():

	bdos_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		bdos_dict[dp_ip] = {}
		bdos_dict[dp_ip]['Name'] = dp_attr['Name']
		bdos_dict[dp_ip]['BDOS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileNetflood"] != "" and pol_attr["rsIDSNewRulesName"] != "null":
				bdos_report = v.getBDOSTrafficReport(dp_ip,pol_attr,full_net_dic)
				bdos_dict[dp_ip]['BDOS Report'].append(bdos_report)

	with open(raw_data_path + 'BDOS_traffic_report.json', 'w') as outfile:
		json.dump(bdos_dict,outfile)
	
	return

def getDNSReportFromVision():

	dns_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		dns_dict[dp_ip] = {}
		dns_dict[dp_ip]['Name'] = dp_attr['Name']
		dns_dict[dp_ip]['DNS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileDNS"] != "":
				dns_report = v.getDNStrafficReport(dp_ip,pol_attr,full_net_dic)
				dns_dict[dp_ip]['DNS Report'].append(dns_report)

	with open(raw_data_path + 'DNS_traffic_report.json', 'w') as outfile:
		json.dump(dns_dict,outfile)
	
	return


def getTrafficUtilizationStatsFromVision():

	traffic_stats_dict_bps = {}
	traffic_stats_dict_pps = {}
	traffic_stats_dict_cps = {}


	for dp_ip,dp_attr in full_pol_dic.items():

		traffic_stats_dict_bps[dp_ip] = {}
		traffic_stats_dict_bps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_bps[dp_ip]['Traffic Report BPS'] = []

		traffic_stats_dict_pps[dp_ip] = {}
		traffic_stats_dict_pps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_pps[dp_ip]['Traffic Report PPS'] = []

		traffic_stats_dict_cps[dp_ip] = {}
		traffic_stats_dict_cps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_cps[dp_ip]['Traffic Report CPS'] = []

		if not dp_attr['Policies']:
			continue

		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			pol_name = pol_attr["rsIDSNewRulesName"]

			traffic_report_bps = v.getTrafficStatsBPS(dp_ip,pol_name)
			traffic_report_pps = v.getTrafficStatsPPS(dp_ip,pol_name)
			traffic_report_cps = v.getTrafficStatsCPS(dp_ip,pol_name)

			traffic_stats_dict_bps[dp_ip]['Traffic Report BPS'].append(traffic_report_bps)
			traffic_stats_dict_pps[dp_ip]['Traffic Report PPS'].append(traffic_report_pps)
			traffic_stats_dict_cps[dp_ip]['Traffic Report CPS'].append(traffic_report_cps)

	with open(raw_data_path + 'Traffic_report_BPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_bps,outfile)
	
	with open(raw_data_path + 'Traffic_report_PPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_pps,outfile)

	with open(raw_data_path + 'Traffic_report_CPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_cps,outfile)

	getCEC()
	
	return

def getCEC():
	#Get CEC - Concurrent Established Connections per DefensePro

	traffic_stats_dict_cec = {}


	for dp_ip,dp_attr in full_pol_dic.items():

		traffic_stats_dict_cec[dp_ip] = {}
		traffic_stats_dict_cec[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_cec[dp_ip]['Traffic Report CEC'] = []

		if not dp_attr['Policies']:
			continue

	
		traffic_report_cec = v.getTrafficStatsCEC(dp_ip)

		traffic_stats_dict_cec[dp_ip]['Traffic Report CEC'].append(traffic_report_cec)


	with open(raw_data_path + 'Traffic_report_CEC.json', 'w') as outfile:
		json.dump(traffic_stats_dict_cec,outfile)

	return


if not getdatafromvision:
	#If Script run with argument "--use-cache-data"
	with open(raw_data_path + 'full_pol_dic.json') as full_pol_dic_file:
		full_pol_dic = json.load(full_pol_dic_file)

	with open(raw_data_path + 'full_sig_dic.json') as full_sig_dic_file:
		full_sig_dic = json.load(full_sig_dic_file)

	with open(raw_data_path + 'full_net_dic.json') as full_net_dic_file:
		full_net_dic = json.load(full_net_dic_file)

	with open(raw_data_path + 'full_bdosprofconf_dic.json') as full_bdosprofconf_dic_file:
		full_bdosprofconf_dic = json.load(full_bdosprofconf_dic_file)

if getdatafromvision:
	v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
	
	full_pol_dic = v.getFullPolicyDictionary()
	full_sig_dic = v.getFullSignatureProfileDictionary()
	full_net_dic = v.getFullNetClassDictionary()
	full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary()
	
	getBDOSReportFromVision()
	getTrafficUtilizationStatsFromVision()
	getDNSReportFromVision()

if not nodpconfigparsing:
	#parse dp config raw data
	report.append(DataParser(full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic).run())

if not nobdosreport:
	#parse bdos baselines raw data
	#report.append(bdos_parser.parse())
	report = report + bdos_parser.parse()

if not notraffic_stats:
	#generate traffic statistics report "traffic_stats.csv"
	report.append(traffic_stats_parser.parse())

if test_email_alarm:
	report = ['test']

if alarm:
	logging_helper.send_report(report)