from .passiveDNS import passive_scan
from .activeDNS import activeDNS, resolve_hostnames, is_private_ipv4, is_private_ipv6
from .activeHTTP import ActiveHttp
import pymongo
from tqdm import tqdm
from loguru import logger
import validators
import sys
from pathlib import Path
# Add project root directory to path to import config_loader
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
from config_loader import get_mongodb_uri

def is_valid_domain(domain):
    if validators.domain(domain) is True:
        return True
    else:
        return False


def main(sld, start_time, end_time, db_host, db_for_collision, svpath, abroad=None, lastKey=None, pdnsdel=False, ahttpdel=False, AHTTP=True, Checknondm=True):
    """

    :param sld: Domain name
    :param start_time: Start time
    :param end_time: End time  
    :param db_host: Domain database
    :param db_for_collision: Collision database
    :param svpath: Save path, when set to False, only store domains in database, no need to store under svpath
    :param abroad: Only used when PDNS is interrupted and restarted, i.e., when DtreeProcess exists.
    :param lastKey: Only used when PDNS is interrupted and restarted, i.e., when DtreeProcess exists.
    :param pdnsdel: Whether to delete pdns database, default False; set to True when PDNS has executed partially and want to re-execute
    :param ahttpdel: Whether to delete ahttp database, default False
    :param AHTTP: Whether to perform AHTTP, default True
    :param Checknondm: Whether to perform nondm DNS check, i.e., re-query DNS for all nxdomain types, default True
    :return:
    """
    dns_collection_name = f"{sld}-DTree-{start_time}TO{end_time}"
    process_collection_name = f"{sld}-DTree-{start_time}TO{end_time}-Process"
    if lastKey is None:
        # For cases without lastKey input, check if collection exists
        if dns_collection_name in db_host.list_collection_names() and pdnsdel:
            # Delete collection
            db_host[dns_collection_name].drop()
        if process_collection_name in db_host.list_collection_names() and pdnsdel:
            db_host[process_collection_name].drop()
    dns_collection = db_host[dns_collection_name]
    process_collection = db_host[process_collection_name]

    logger.info("Now in PDNS Stage...")
    if dns_collection_name not in db_host.list_collection_names():  # PDNS has not been executed yet
        passive_scan(dns_collection, process_collection, DM=sld, abroad=True, start=start_time, end=end_time,
                     lastKey=lastKey)
        passive_scan(dns_collection, process_collection, DM=sld, abroad=False, start=start_time, end=end_time,
                     lastKey=lastKey)
    elif lastKey is not None:  # If lastkey is not empty, need to retry
        if abroad == True:
            passive_scan(dns_collection, process_collection, DM=sld, abroad=True, start=start_time, end=end_time,
                         lastKey=lastKey)
            passive_scan(dns_collection, process_collection, DM=sld, abroad=False, start=start_time, end=end_time)
        elif abroad == False:
            passive_scan(dns_collection, process_collection, DM=sld, abroad=False, start=start_time, end=end_time,
                         lastKey=lastKey)
        else:  # If abroad is not bool type, error
            logger.error("abroad parameter error!")
            exit()
    else:  # For lastKey being empty but database already has values, PDNS has finished
        pass
    logger.info("PDNS Stage is over. Now in ADNS Stage...")
    activeDNS(dns_collection, Checknondm)
    logger.info("ADNS Stage is over. Now in Save Stage...")


    query1 = {  # Find all private network domains (either ipv4 or ipv6 is private IP)
        "$or": [
            {"$and": [
                {"ipv4": {"$ne": False}},  # adata is not False
                {"ipv4IsInet": True}  # aIsInet is True
            ]},
            {"$and":[
                {"ipv6": {"$ne": False}},  # adata is not False
                {"ipv6IsInet": True}  # aIsInet is True 
            ]}
        ]
    }

    query2 = {  # Find all NXDomain domains (both ipv4 and ipv6 are False)
        "$and": [
            {"ipv4": False},
            {"ipv6": False}
        ]
    }


    # # Re-resolve non-existent IP addresses to ensure purification
    # results2 = dns_collection.find(query2)
    # domains = set()
    # for item in results2:
    #     domains.add(item['domain'].lower())
    
    # # Resolve domains in domain_list to purify NXDOMAIN domains (found many failed resolutions in previous parsing during practice)
    # print("Starting domain resolution...")
    # inetDM_new = set()
    # nonDM_new = set()
    
    # # Process domain list in batches, at most 200 per batch
    # domains = list(domains)
    # batch_size = 200
    # for i in range(0, len(domains), batch_size):
    #     batch = domains[i:i + batch_size]
    #     print(f"Processing batch {i//batch_size + 1}, total {len(batch)} domains...")
        
    #     # Resolve IPv4
    #     resolved_results_ipv4 = asyncio.run(resolve_hostnames(batch, rtype=1))
    #     # Resolve IPv6
    #     resolved_results_ipv6 = asyncio.run(resolve_hostnames(batch, rtype=28))
        
    #     # Process resolution results
    #     for domain in batch:
    #         # Use get method to get resolution result, return None if not exists
    #         ipv4_result = resolved_results_ipv4.get(domain)
    #         ipv6_result = resolved_results_ipv6.get(domain)
            
    #         # Check if any IP is private IP
    #         has_inet_ipv4 = ipv4_result is not None and is_inet_ip(ipv4_result)
    #         has_inet_ipv6 = ipv6_result is not None and is_inet_ip(ipv6_result)
            
    #         # If any IP is private IP, record to inetDM_new
    #         if has_inet_ipv4 or has_inet_ipv6:
    #             inetDM_new.add(domain)
    #         # If both IPs failed to resolve, record to nonDM_new
    #         elif ipv4_result is None and ipv6_result is None:
    #             nonDM_new.add(domain)
    
    # print("Domain resolution completed")


    # # Query: Private IP
    # results1 = dns_collection.find(query1)
    # tmp1 = set()
    # tmp1.update(inetDM_new)
    # for item in results1:
    #     tmp1.add(item['domain'].lower())
    # svfile1 = svpath + f"{sld}-inetdm.txt"
    # with open(svfile1, "w") as f:
    #     for hostname in tmp1:
    #         if is_valid_domain(hostname):
    #             f.write(hostname+'\n')
    
    # # Write domains resolved to empty
    # svfile2 = svpath + f"{sld}-nondm.txt"
    # tmp2 = set()
    # tmp2.update(nonDM_new)
    # with open(svfile2, "w") as f:
    #     for hostname in tmp2:
    #         if is_valid_domain(hostname):
    #             f.write(hostname+'\n')
    
    inetdm_collection = db_for_collision[f"{sld}-inetdm"]
    nondm_collection = db_for_collision[f"{sld}-nondm"]

    # Query: Private IP
    results1 = dns_collection.find(query1)
    inetdm_collection.delete_many({})
    # Use batch insert to process data to avoid large memory overhead
    batch_size = 1000
    batch = []
    # Write to database
    tmp = set()  # For deduplication
    for item in results1:
        domain = item['domain'].lower()
        if domain in tmp:
            continue
        else:
            tmp.add(domain)
        batch.append({
            'domain': domain,
            'ipv4': item['ipv4'],
            'ipv6': item['ipv6']
        })
        if len(batch) >= batch_size:
            inetdm_collection.insert_many(batch)
            batch = []
    # Insert remaining data
    if batch:
        inetdm_collection.insert_many(batch)
        logger.info(f"[+]Hostnames resolved to inetip ==> mongodb-ForCollision/{sld}-inetdm")
    if svpath:
        svfile1 = svpath + f"{sld}-inetdm.txt"
        # Re-query database to write to file, avoid storing large amounts of data in memory
        results1 = dns_collection.find(query1)
        with open(svfile1, "w") as f:
            for item in results1:
                domain = item['domain'].lower()
                f.write(domain + '\n')
    
    # Use batch insert to process data to avoid large memory overhead
    batch_size = 1000
    batch = []
    results2 = dns_collection.find(query2)
    # Clear all documents in collection
    nondm_collection.delete_many({})
    tmp = set()  # For deduplication
    for item in results2:
        domain = item['domain'].lower()
        if domain in tmp:
            continue
        else:
            tmp.add(domain)
        if is_valid_domain(domain):
            batch.append({
                'domain': domain
            })
        if len(batch) >= batch_size:
            nondm_collection.insert_many(batch)
            batch = []
    # Insert remaining data
    if batch:
        nondm_collection.insert_many(batch)
        logger.info(f"[+]Hostnames resolved to nonip ==> mongodb-ForCollision/{sld}-nondm")
    if svpath:
        svfile2 = svpath + f"{sld}-nondm.txt"
        with open(svfile2, "w") as f:
            # Re-query database to write to file, avoid storing large amounts of data in memory
            results2 = dns_collection.find(query2)
            for item in results2:
                domain = item['domain'].lower()
                if is_valid_domain(domain):
                    f.write(domain + '\n')

    """Below enters the stage of searching for domains resolved to public IP"""
    # Query condition: Public IP
    # 1. adata is not False
    # 2. aIsInet is True
    # Execute query to get all records matching conditions
    count = dns_collection.count_documents({
        "ipv4": {"$ne": False},  # adata is not False
        "ipv4IsInet": False
    })
    results = dns_collection.find({
        "ipv4": {"$ne": False},  # adata is not False
        "ipv4IsInet": False,
    }, no_cursor_timeout=True)

    keywords = [sld]
    keyword = ','.join(keywords)

    dm_collection_name = keyword + "-dtree-activehttp-DM"
    url_collection_name = keyword + "-dtree-activehttp-URL"

    # Clear all documents in collection
    if dm_collection_name in db_host.list_collection_names() and ahttpdel:
        db_host[dm_collection_name].drop()
    # Clear all documents in collection
    if url_collection_name in db_host.list_collection_names() and ahttpdel:
        db_host[url_collection_name].drop()
    DM_collection = db_host[dm_collection_name]
    URL_collection = db_host[url_collection_name]

    if dm_collection_name not in db_host.list_collection_names() and AHTTP:
        logger.info(f"{dm_collection_name} is not in collections, now in ActiveHttp...")
        target_domain = []
        with tqdm(total=count) as pbar:
            for result in results:
                dm = result["domain"]
                if dm not in target_domain:
                    target_domain.append(dm)
                pbar.update()
            pbar.close()
        results.close()

        ActiveHttp(DM_collection=DM_collection, URL_collection=URL_collection, targetlst=target_domain, dm_keywords=keywords, initial=False).start()

    query3 = {
        "Islogin": True
    }
    # Query: Public IP with login interface
    results3 = DM_collection.find(query3)
    publogindm_collection = db_for_collision[f"{sld}-publogindm"]
    tmp3 = {}
    for item in results3:
        tmp3[item['domain']] = {
            'domain': item['domain'],
            'url': item['url'],
            'Title': item['Title']
        }
    publogindm_collection.delete_many({})
    if len(tmp3) > 0:
        publogindm_collection.insert_many(tmp3.values())
        logger.info(f"[+]Hostnames resolved to login-pubip ==> mongodb-ForCollision/{sld}-publogindm")
    if svpath:
        svfile3 = svpath + f"{sld}-publogindm.txt"
        with open(svfile3, "w") as f:
            for hostname in tmp3:
                if is_valid_domain(hostname):
                    f.write(hostname+'\n')
        logger.info("[+]Hostnames resolved to inetip ==> {}".format(svfile1))
        logger.info("[+]Hostnames resolved to nullip ==> {}".format(svfile2))
        logger.info("[+]Hostnames resolved to login-pubip ==> {}".format(svfile3))

import argparse, sys
def argparser():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Hostscan Module Main',
                                     epilog='\tUsage:\npython ' + sys.argv[
                                         0] + " --sld google.com --abroad True --lastkey xxxxxx")
    parser.add_argument('--sld', help='A target like example.com', required=True)
    parser.add_argument('--abroad', help='Determine to use abroad or domestic database', required=True)
    parser.add_argument('--lastkey', help='If has run PassiveDNS Module, you can choose to begin at the existing state')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = argparser()
    sld = args.sld
    if args.abroad.lower() == 'true':
        abroad = True
    elif args.abroad.lower() == 'false':
        abroad = False
    else:
        logger.error("--abroad must be true or false!")
        exit()
    lastKey = args.lastkey


    start_time = "20201105000000"
    end_time = "20241105000000"


    dns_collection_name = f"{sld}-DTree-{start_time}TO{end_time}"
    process_collection_name = f"{sld}-DTree-{start_time}TO{end_time}-Process"
    # Connect to database
    myclient = pymongo.MongoClient(get_mongodb_uri('hostcollision'))
    db_host = myclient["host"]
    db_for_collision = myclient["ForCollision"] 
    main(sld, start_time, end_time, db_host, db_for_collision, svpath="hostscan_module/res/", lastKey=lastKey, abroad=abroad)