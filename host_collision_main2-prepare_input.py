# -*- coding: utf-8 -*-
import hostscan_module, ipscan_module
import pymongo
from ipscan_module import ip_select_main
from loguru import logger
import argparse, sys
import os
from config_loader import get_mongodb_uri, get_main2_config

def argparser():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Here we can help prepare data which are used in HC module for some SLD',
                                     epilog='\tUsage:\npython ' + sys.argv[
                                         0] + " --sld google.com")
    parser.add_argument('--sld', '-sld', help='A target like example.com', required=True)
    parser.add_argument('--abroad', help='Retry mode, last failed API mode, default None', default=None)
    parser.add_argument('--lastkey', help='Retry mode, request page identifier when last failed, default None', default=None)
    parser.add_argument('--AHTTP', help='Whether to perform AHTTP, default False', default='False')
    parser.add_argument('--dmUpdate', help='Whether to update DM Collection, default False', default='False')
    parser.add_argument('--ipUpdate', help='Whether to update IP Collection, default False', default='False')
    args = parser.parse_args()
    return args

args = argparser()
sld = args.sld
assert not ((args.abroad is None) ^ (args.lastkey is None))  # Ensure both are assigned or both are not assigned
abroad = args.abroad
if abroad is None:
    pass
elif abroad.lower() == 'true':
    abroad = True
elif abroad.lower() == 'false':
    abroad = False
else:
    print(f"--abroad must be true or false")
    exit()
lastKey = args.lastkey
if lastKey is None:
    pass
AHTTP = args.AHTTP
if AHTTP.lower() == 'true':
    AHTTP = True
elif AHTTP.lower() == 'false':
    AHTTP = False
else:
    logger.error("--AHTTP must be true or false!")
    exit()
ipUpdate = args.ipUpdate  # Default update, when domain count is too large, reading database takes long time, can choose not to update
if ipUpdate.lower() == 'true':
    ipUpdate = True
elif ipUpdate.lower() == 'false':
    ipUpdate = False
else:
    logger.error("--ipUpdate must be true or false!")
    exit()

# Read time range and database configuration from config file
config = get_main2_config()
time_range = config["time_range"]
start_time = time_range["start_time"]
end_time = time_range["end_time"]

# Connect to database
myclient = pymongo.MongoClient(get_mongodb_uri('hostcollision'))
# hostscan_module.main(sld=sld, abroad=abroad, start_time=start_time, end_time=end_time, rtype=rtype, mode=mode, db=db, svpath="hostscan_module/res/", lastKey=lastKey)

# Read database names from config file
db_for_collision_name = config["databases"]["for_collision"]
db_host_name = config["databases"]["host"]
db_ip_name = config["databases"]["ip"]

# Check if domain file exists
db_for_collision = myclient[db_for_collision_name]  # Select database
db_host = myclient[db_host_name]
nondm_collection = config["collection_patterns"]["nondm"].format(sld=sld)

dmUpdate = args.dmUpdate
if dmUpdate.lower() == 'true':
    dmUpdate = True
elif dmUpdate.lower() == 'false':
    dmUpdate = False
else:
    logger.error("--dmUpdate must be true or false!")
    exit()
if nondm_collection not in db_for_collision.list_collection_names():
    hostscan_module.main(sld=sld, abroad=abroad, start_time=start_time, end_time=end_time, db_host=db_host, db_for_collision=db_for_collision, svpath=False, lastKey=lastKey, AHTTP=AHTTP, Checknondm=False)
    print(f"Domain collection completed")
    # hostscan_module.main(sld=sld, abroad=abroad, start_time=start_time, end_time=end_time, db_host=db_host, db_for_collision=db_for_collision, svpath="hostscan_module/res/", lastKey=lastKey, AHTTP=AHTTP)
elif dmUpdate:
    print(f"Domain database resource already exists, and dmUpdate=True, will update domain list")
    hostscan_module.main(sld=sld, abroad=abroad, start_time=start_time, end_time=end_time, db_host=db_host, db_for_collision=db_for_collision, svpath=False, lastKey=lastKey, AHTTP=AHTTP)
else:
    print(f"Domain database resource already exists, and dmUpdate=False, using existing domain list")


db = myclient[db_host_name]
clname = config["collection_patterns"]["dtree"].format(sld=sld, start_time=start_time, end_time=end_time)
collection_rd = db[clname]  # Collection name

db = myclient[db_ip_name]
# collection_sv_pdns = db[f'{sld}-pdns']
# collection_sv_pdns.delete_many({})
adns_name = config["collection_patterns"]["adns"].format(sld=sld)
adns_asn_name = config["collection_patterns"]["adns_asn"].format(sld=sld)
collection_sv_adns = db[adns_name]
collection_sv_adns_asn = db[adns_asn_name]
if ipUpdate:  # If update, delete both collections
    print(f"ipUpdate=True, will delete original IP list and then update")
    collection_sv_adns.delete_many({})
    collection_sv_adns_asn.delete_many({})
elif adns_name not in db.list_collection_names():  # If adns_name doesn't exist, it's the first run, update
     print(f"IP database resource does not exist, and ipUpdate=False, will update IP list")
     collection_sv_adns_asn.delete_many({})
     ipUpdate = True

# collection_sv_pdns_asn = db[f'{sld}-pdns-asn']
# collection_sv_pdns_asn.delete_many({})
if ipUpdate:
    ipscan_module.main(collection_rd, collection_sv_adns, collection_sv_adns_asn)


collection_adns_asn = db[adns_asn_name]
collection_adns = db[adns_name]
# iplist_svfile = f"ipscan_module/res/{sld}-ip.txt"
ip_collection_name = config["collection_patterns"]["ip"].format(sld=sld)
collection_for_collision_ip = db_for_collision[ip_collection_name]
ip_select_main.ip_select_by_asn(sld, collection_adns, collection_adns_asn, collection_for_collision_ip, iplist_svfile=False, mannual=False)