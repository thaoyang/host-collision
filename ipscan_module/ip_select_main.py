from pymongo import MongoClient
from loguru import logger
import json
import os


def get_company_by_sld(sld):
    """Find corresponding company name by SLD"""
    # Get sld.json file path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sld_json_path = os.path.join(current_dir, 'sld.json')
    
    try:
        with open(sld_json_path, 'r', encoding='utf-8') as f:
            sld_data = json.load(f)
        
        # Iterate through all companies to find the one containing this SLD
        for company, info in sld_data.items():
            if 'domains' in info and sld in info['domains']:
                logger.info(f"Found company corresponding to SLD {sld}: {company}")
                return company.lower()  # Return lowercase company name
        
        logger.warning(f"Company corresponding to SLD {sld} not found")
        return None
    except Exception as e:
        logger.error(f"Failed to read sld.json file: {e}")
        return None


def get_company_exclude_mapping():
    """Build mapping relationship from company to Exclude feature fragments (only includes four specified companies)"""
    return {
        'google': ['google'],
        'amazon': ['amazon'],
        'microsoft': ['microsoft'],
        'verizon communications': ['verizon'],
        'alibaba': ['aliyun'],
        'alphabet': ['google']
    }


def ip_select_by_asn(sld, collection_adns, collection_adns_asn, collection_for_collision_ip, iplist_svfile=False, mannual=False):
    
    all_documents = collection_adns_asn.find()
    to_check_records = dict()
    for document in all_documents:
        to_check_records[document['ASNOrg']] = {'ipnum':document['ipnum'], 'hostnum':document['hostnum']}

    ASNs = list(to_check_records.keys())
    ASNs_select = []
    NUM = len(ASNs)
    Chose = [-1 for _ in range(NUM)]
    index = -1
    while index < len(ASNs)-1:
        index += 1
        asn = ASNs[index]
        ipnum = to_check_records[asn]['ipnum']
        hostnum = to_check_records[asn]['hostnum']
        if mannual:
            print("-" * 20)
            print("\033[0;31;40m" + f"Now wh're checking the {index+1}/{NUM} ASN:" + "\033[0m")
            print(f"ASN: {asn};\nipnum: {ipnum};\nhostnum:{hostnum}")
            string = f"If the ASN maybe the {sld}', please enter 1; else enter 0; if rollback, enter -1:"
            Judge = input("\033[0;31;40m" + string + "\033[0m")
            while (Judge!="0" and Judge!="1" and Judge != "-1"):
                Judge = input("\033[0;31;40m"+string+"\033[0m")
            Judge = int(Judge)
            Chose[index] = Judge
            if Judge == 0:
                continue
            elif Judge == 1:
                ASNs_select.append(asn)
            else:
                index -= 1
                Judge = Chose[index]
                if Judge == 1:
                    ASNs_select.pop()
                if index == -1:
                    continue
                index -= 1
        else:
            # Base exclude list
            Exclude = ["cloudflare", "akamai", "fastly", "google", "amazon", "squarespace", "microsoft", "incapsula", "ibm", "edgecast", "aliyun",
                "weebly", "servicenow", "ovh", "rackspace", "sendgrid", "hubspot", "automattic", "verizon", "hosting", "godaddy", "digitalocean", "hostgtor", "zendesk", "wpengine", "eastlink", "wowrack",
                "github", "shopify", "vercel", "wordline", "salesforce", "oracle", "sybase", "twitter", "adobe", "smarttrade", "bunny", "cdnetworks", "cachefly"]
            
            # Find corresponding company by SLD and adjust Exclude list (only for four specified companies)
            company = get_company_by_sld(sld)
            if company:
                company_mapping = get_company_exclude_mapping()
                if company in company_mapping:
                    exclude_terms = company_mapping[company]
                    original_exclude_count = len(Exclude)
                    # Remove the company's feature fragments from Exclude list
                    Exclude = [term for term in Exclude if term not in exclude_terms]
                    removed_count = original_exclude_count - len(Exclude)
                    if removed_count > 0:
                        logger.info(f"For company {company}, removed {removed_count} feature fragments from Exclude list: {exclude_terms}")
                    else:
                        logger.info(f"Company {company}'s feature fragments {exclude_terms} not found in Exclude list")
                else:
                    logger.info(f"Company {company} is not in the specified four companies list, keeping original Exclude list")
            
            Break = False
            for ex in Exclude:
                if asn and ex in asn.lower():
                    Break = True
                    break
            if Break:
                continue
            ASNs_select.append(asn)
    
    # Iterate through all records in collection_adns_asn and update Select field
    for doc in collection_adns_asn.find({}, {"_id": 1, "ASNOrg": 1}):  # Only query _id and ASNOrg
        select_value = 1 if doc.get("ASNOrg") in ASNs_select else 0
        collection_adns_asn.update_one({"_id": doc["_id"]}, {"$set": {"Select": select_value}})

    ip_list = []
    all_documents = collection_adns.find()
    for document in all_documents:
        if document['ASNOrg'] in ASNs_select:
            ip_list.append((document['ip'], document['hostnum'], document['RIR'], document['ASNOrg']))

    collection_for_collision_ip.delete_many({})
    if not ip_list:  # If ip_list is empty, insert an empty record to determine how far the program has run
        collection_for_collision_ip.insert_one({'ip':'null', 'hostnum':0, 'RIR':'', 'ASNOrg':''})
    for item in ip_list:
        collection_for_collision_ip.insert_one({'ip':item[0], 'hostnum':item[1], 'RIR':item[2], 'ASNOrg':item[3]})
    logger.info(f"[+] IPlist has been saved in mongodb.")
    if iplist_svfile:
        with open(iplist_svfile, 'w') as f:
            for item in ip_list:
                f.write(item[0]+'\n')
        logger.info(f"[+] IPlist has been saved in {iplist_svfile}.")

if __name__ == "__main__":
    import sys
    from pathlib import Path
    root_dir = Path(__file__).parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    from config_loader import get_mongodb_uri
    client = MongoClient(get_mongodb_uri('hostcollision'))  # Read connection information from config file
    sld = "alibaba-inc.com"
    db = client['ip']
    collection_adns_asn = db[f'{sld}-adns-asn']
    collection_adns = db[f'{sld}-adns']
    iplist_svfile = f"res/{sld}-ip.txt"
    ip_select_by_asn(collection_adns, collection_adns_asn, iplist_svfile)