import config as cfg
import json
from vision import Vision
from dpconfig_parser import DataParser
import urllib3
import logging_helper
import sys


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#Arguments variables

getdatafromvision = True
alarm = True
test_email_alarm = False
report = []

raw_data_path = "./Raw Data/"


logging_helper.log_setup(cfg.LOG_FILE_PATH, cfg.SYSLOG_SERVER, cfg.SYSLOG_PORT)


for i in sys.argv:
	#Running script with arguments

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
	logging_helper.logging.info('Collecting policies data from all DefensePro')
	print('Collecting policies data from all DefensePro')

	full_sig_dic = v.getFullSignatureProfileDictionary()
	logging_helper.logging.info('Collecting signature profiles data from all DefensePro')
	print('Collecting signature profiles data from all DefensePro')
	full_net_dic = v.getFullNetClassDictionary()
	logging_helper.logging.info('Collecting network classes data from all DefensePro')
	print('Collecting network classes data from all DefensePro')
	full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary()
	logging_helper.logging.info('Collecting BDOS configuration data from all DefensePro')
	print('Collecting BDOS configuration data from all DefensePro')
	
	logging_helper.logging.info('Data collection is complete')
	print('Data collection is complete')

logging_helper.logging.info('Starting data parsing')
print('Starting data parsing')
report.append(DataParser(full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic).run())


if test_email_alarm:
	report = ['test']

if alarm:
	logging_helper.send_report(report)