# -*- coding: utf-8 -*-
import requests
from loguru import logger
import re
import pymongo
import idna
import sys
from pathlib import Path

# Add project root directory to path
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
from config_loader import get_passive_dns_config


def potential_normal_hostname(domain: str, sld: str) -> bool:
    """
    Check if the given domain name conforms to normal format.
    
    Rules:
    - Can only contain letters (A-Z, a-z), numbers (0-9), and hyphens (-).
    - Hyphens cannot appear at the beginning or end.
    - Each label (separated by .) is at most 63 characters, entire domain is at most 253 characters.
    - Internationalized Domain Names (IDN) are allowed, automatically converted to Punycode for validation.

    :param domain: Domain name to check
    :param sld: Second-level domain (SLD), for compatibility, currently unused
    :return: Whether it conforms to normal domain format
    """
    if not domain or len(domain) > 253:
        return False

    try:
        # Handle Internationalized Domain Names (IDN)
        domain = idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        return False

    # Regular expression match: allow letters, numbers, hyphens, cannot start or end with `-`
    pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

    labels = domain.split(".")
    if len(labels) < 2:  # At least one `.` separator required
        return False

    if not all(pattern.match(label) for label in labels):
        return False

    return True



# Define API URL
def passive_scan(Data_collection, Process_collection, DM, abroad:bool, start=None, end=None, lastKey=None):
    """
    Get data from API and save to MongoDB.
    :param Data_collection: MongoDB collection object for saving data, required.
    :param Process_collection: MongoDB collection object for saving progress, required.
    :param DM: Domain DM value, required.
    :param abroad: Whether it's foreign data source, to select PDNS interface, required.
    :param start: Start time, required.
    :param end: End time, required.
    :param lastKey: Last request's lastKey value, optional.
    """
    logger.info(f"Now in PassiveDNS, abroad is {abroad}, lastkey is {lastKey}")
    
    # Read PDNS configuration from config file
    pdns_config = get_passive_dns_config()
    urls = pdns_config["urls"]
    api_credentials = pdns_config["api_credentials"]
    timeout_config = pdns_config["timeout"]
    MaxRecords = pdns_config["max_records"]
    
    # Select URL based on abroad parameter
    if not abroad:
        url_template = urls["domestic"]
    else:
        url_template = urls["abroad"]
    url = url_template.format(DM=DM)
    
    if (start is not None) and (end is not None):
        url = url + f"?start={start}&end={end}&timeformat=simple"
    else:
        logger.warning("Please Check the passive_scan's input: start & end!")
        raise

    # Read account credentials from config file
    headers = {
        "fdp-access": api_credentials["fdp-access"],
        "fdp-secret": api_credentials["fdp-secret"],
    }

    # Read timeout settings from config file
    MinTimeout = timeout_config["min_timeout"]
    Timeout = timeout_config["initial_timeout"]  # Delay setting
    delta = timeout_config["delta"]  # Delay increment after single request failure
    MaxTryTimes = timeout_config["max_try_times"]  # Maximum retry times

    Errortimes = 0
    while Errortimes < MaxTryTimes:
        try:
            if lastKey is not None:
                response = requests.get(url + f'&lastkey={lastKey}', headers=headers, timeout=Timeout)
            else:
                response = requests.get(url, headers=headers, timeout=Timeout)
            assert response.status_code == 200
            break
        except:
            Timeout += delta
            Errortimes += 1
    assert Errortimes < MaxTryTimes, "In Module PDNS-Wrong at the beginning! Attention: Errortimes == MaxTryTimes!"

    index = 0
    rec_ok_nums = 0
    hostname_queue = []  # Initialize queue
    while rec_ok_nums < MaxRecords:
        # Parse response JSON content as dictionary
        data = response.json()
        index += len(data['data'])
        lastKey = data['lastKey']

        # with open(tmpsvfile, "a+") as f:
        for item in data['data']:
            hostname = item['domain'].lower()
            
            # If hostname is already in queue, skip processing
            if hostname in hostname_queue:
                continue
                
            # Add hostname to queue, keep queue length no more than 10
            hostname_queue.append(hostname)
            if len(hostname_queue) > 10:
                hostname_queue.pop(0)
            if potential_normal_hostname(hostname, DM):
                Data_collection.insert_one(item)
                rec_ok_nums += 1

        Process_collection.insert_one({"index":index, "rec_ok_nums":rec_ok_nums, "abroad":abroad, "lastKey":lastKey})
        logger.info(f"Now Index is {index}, Domainnames that meet the criteria are {rec_ok_nums}, Abroad is {str(abroad)}, LastKey is {lastKey}.")
        if not lastKey:
            logger.info("LastKey is empty, query ended~")
            break

        Errortimes = 0
        while Errortimes < MaxTryTimes:
            try:
                response = requests.get(url + f"&lastkey={lastKey}", headers=headers, timeout=Timeout)
                assert response.status_code == 200
                break
            except:
                if Timeout <= 2 * MinTimeout:
                    Timeout += delta
                Errortimes += 1
        assert Errortimes < MaxTryTimes, "In Module PDNS! Attention: Errortimes == MaxTryTimes!"
    logger.info("PassiveDNS Module has finished the work!")

if __name__ == "__main__":
    # Connect to database
    import sys
    from pathlib import Path
    root_dir = Path(__file__).parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    from config_loader import get_mongodb_uri
    myclient = pymongo.MongoClient(get_mongodb_uri('hostcollision'))

    # Get database, fill in database name in brackets
    db = myclient["host"]
    sld = "baidu.com"
    abroad = False
    start_time = "20200601000000"
    end_time = "20240601000000"

    dns_collection_name = f"{sld}-DTree-{start_time}TO{end_time}"
    process_collection_name = f"{sld}-DTree-{start_time}TO{end_time}-Process"

    if dns_collection_name in db.list_collection_names():
        # Delete collection
        db[dns_collection_name].drop()
    if process_collection_name in db.list_collection_names():
        db[process_collection_name].drop()

    dns_collection = db[dns_collection_name]
    process_collection = db[process_collection_name]

    passive_scan(dns_collection, process_collection, DM=sld, abroad=abroad, start=start_time, end=end_time)