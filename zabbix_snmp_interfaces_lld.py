#!/usr/bin/env python
# -*- coding: utf8 -*-

__author__ = "Arnis Civciss (arnis.civciss@gmail.com)"
__copyright__ = "Copyright (c) 2015 Arnis Civciss"

DEBUG = 0

"""Some examples and notes

Description walk example:
snmpbulkwalk -v2c -c public 192.168.180.100 1.3.6.1.2.1.31.1.1.1.18 | grep -i "LTK_"
Alias walk:
snmpbulkwalk -v2c -c public 192.168.180.100 .1.3.6.1.2.1.31.1.1.1.1

Siemens Hid example:
snmpbulkwalk -v2c -c Ziemen5Power 192.168.182.34 .1.3.6.1.2.1.31.1.1.1.1
snmpbulkwalk -v2c -c Ziemen5Power 192.168.182.34 .1.3.6.1.2.1.31.1.1.1.18

OmniSwitch example:
snmpbulkwalk -v2c -c public 192.168.181.59 .1.3.6.1.2.1.31.1.1.1.1
snmpbulkwalk -v2c -c public 192.168.181.59 .1.3.6.1.2.1.31.1.1.1.18
snmpbulkwalk -v2c -c public 192.168.181.59 .1.3.6.1.2.1.31.1.1.1.15

ASR example:
snmpbulkwalk -v2c -c lan2lan 192.168.148.56 1.3.6.1.2.1.31.1.1.1.18 | grep -i "LTK_"

OIDs for items:
  in_oct_oid = '1.3.6.1.2.1.31.1.1.1.6.%s' % subif_idx
  out_oct_oid = '1.3.6.1.2.1.31.1.1.1.10.%s' % subif_idx

  in_ucast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.7.%s' % subif_idx
  out_ucast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.11.%s' % subif_idx

  in_mcast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.8.%s' % subif_idx
  out_mcast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.12.%s' % subif_idx

  in_bcast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.9.%s' % subif_idx
  out_bcast_pkts_oid = '1.3.6.1.2.1.31.1.1.1.13.%s' % subif_idx

  in_errors_oid = '.1.3.6.1.2.1.2.2.1.14.%s' % subif_idx
  out_errors_oid = '.1.3.6.1.2.1.2.2.1.20.%s' % subif_idx

  in_discards_oid = '.1.3.6.1.2.1.2.2.1.13.%s' % subif_idx
  out_discards_oid = '.1.3.6.1.2.1.2.2.1.19.%s' % subif_idx

  oper_state = '.1.3.6.1.2.1.2.2.1.8.%s' % subif_idx

XR example - all phy interfaces
python zabbix_snmp_interfaces_lld.py cisco_xr 192.168.133.24 public SA_riga-sa9-iptv4-3750e

XR example with custom descrp regexp and alias regexp - both are optional but if alias is needed, then descr is mandatory
python zabbix_snmp_interfaces_lld.py cisco_xr 192.168.133.249 public SA_riga-sa8-sw-4900 "^(\s+)?(LTK\_BGP\_|L3\_BGP\_)" "^(TenGigE|Bundle\-Ether)"

Input parameters: type, host, community, hostname, [descr_reg_string, alias_reg_string]
type can be - false. In that case you need to specify both: descr_reg_string, alias_reg_string as last parameters.

You can use predefined types as: cisco_ios, cisco_xr, hid, omni - for phy interface scanning. 
In that case descr and alias regexps are predefined.

If you need e.g. on crs to scan all phy interfaces without BGP labels, then you need to specify custom regexps.

ZAB_ can be used in description to include find that host in discovery.

"""
import subprocess
import re
import sys
import json

TYPE = sys.argv[1]
HOST = sys.argv[2]
COMMUNITY = sys.argv[3]
HOSTNAME = sys.argv[4]

#so far description regexp is one for all types. ZAB_ can be added in case some
DESCR_REG_STRING = '^(\s+)?(LTK\_|ZAB\_)'
if len(sys.argv) > 5:
  DESCR_REG_STRING = sys.argv[5]

ALIAS_REG_STRING = False
if len(sys.argv) > 5:
  ALIAS_REG_STRING = sys.argv[6]

IF_OPER_STATUS_OID = '.1.3.6.1.2.1.2.2.1.8'
IF_ALIAS_OID = '.1.3.6.1.2.1.31.1.1.1.1'
IF_DESCR_OID = '.1.3.6.1.2.1.31.1.1.1.18'
IF_SPEED_OID = '.1.3.6.1.2.1.31.1.1.1.15' #if high speed

#interface alias depends on the device type
#cisco_ios_phy cisco_ios_po: 4948, 4900, 3750 etc.
#cisco_xr: asr9K
if TYPE == 'false':
  pass

elif TYPE == 'cisco_ios':
  ALIAS_REG_STRING = '^(Gi|Te|Po)[^\.]+$' 

elif TYPE == 'cisco_xr':
  ALIAS_REG_STRING = '^(TenGigE|Bundle\-Ether)[^\.]+$' 

elif TYPE == 'cisco_xr_bgp':
  DESCR_REG_STRING = '^(\s+)?(LTK\_BGP\_|L3\_BGP\_)'
  ALIAS_REG_STRING = '(TenGigE|Bundle\-Ether)' 

elif TYPE == 'hid':
  ALIAS_REG_STRING = '^(port\d+)'

elif TYPE == 'omni':
  ALIAS_REG_STRING = '^(\d+)'

else:
  sys.exit('Error: type is incorrect.')

DESCR_REGEXP = re.compile(DESCR_REG_STRING)
ALIAS_REGEXP = re.compile(ALIAS_REG_STRING)

def get_table(OID, TYPE="STRING"):
  '''Does snmpwalk on a given oid with appropriate type and returns dictionary of idxs and values'''

  re_nameoid = re.compile('\.(\d+)\s\=\s%s\:\s\"?([^\"]+)\"?' % TYPE)
  out = subprocess.Popen(['snmpbulkwalk', '-v2c', '-c', COMMUNITY, HOST, OID], stdout=subprocess.PIPE).communicate()[0]
  out = out.split('\n')
  dic = {}
  for line in out:
    if re_nameoid.search(line):
      name_idx = re_nameoid.search(line).group(1)
      name = re_nameoid.search(line).group(2)
      dic[name_idx] = name
  return dic

if __name__ == "__main__":
  #Bet all needed tables
  if_descr = get_table(IF_DESCR_OID, "STRING")
  if DEBUG == 1: print if_descr 
  if_oper = get_table(IF_OPER_STATUS_OID, "INTEGER")
  if DEBUG == 1: print if_oper
  if_alias = get_table(IF_ALIAS_OID, "STRING")
  if DEBUG == 1: print if_alias
  if_hispeed = get_table(IF_SPEED_OID, "Gauge32")
  if DEBUG == 1: print if_hispeed

  json_out = {}
  json_out['data'] = []
  #go through table descr and select all UP interfaces that match descr and alias regexps
  for idx in if_descr:
    if DEBUG == 1: print idx
    if DESCR_REGEXP.search(if_descr[idx]) and ALIAS_REGEXP.search(if_alias[idx]) and (if_oper.get(idx) == '1'):
      if DEBUG == 1: print idx, if_descr[idx], if_oper[idx], if_alias[idx], if_hispeed[idx]
      #100G by default. If speed is unknown, let's better do not trigger false alarms.
      speed_max_trigger = 100000000000
      if int(if_hispeed[idx]) > 0:
        speed_max_trigger = int(1000000*int(if_hispeed[idx])*0.9)
      json_out['data'].append({'{#HNAME}' : HOSTNAME, '{#IDX}' : str(idx), '{#IF_DESCR}' : if_descr[idx], 
                            '{#IF_ALIAS}' : if_alias[idx], '{#TRIGGER_MAX_BPS}' : str(speed_max_trigger), '{#MAX_BPS}' : if_hispeed[idx]})

  print json.dumps(json_out, sort_keys=True, indent=4, separators=(',', ': '))
