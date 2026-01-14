# -*- coding: utf-8 -*-
# Target: Gain domains with A record resolution non-existent / private IP
from tqdm import tqdm
import ipaddress
import asyncio
import aiodns
import time
import socket
import pymongo
from loguru import logger

def is_private_ipv4(ip_address: str) -> bool:
    # Check if it's a private IP
    try:
        ip = ipaddress.ip_address(ip_address)
        P1 = not ip.is_global
        P2 = ip in ipaddress.ip_network('100.64.0.0/10')
        return P1 or P2  # As long as it's not a public IP, it's a private IP
    except ValueError:
        logger.warning(f"Invalid IP address: {ip_address}")
        return False

def is_private_ipv6(ipv6_address):
    # Check if it's a private IP
    try:
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        return not ipv6.is_global  # As long as it's not a public IP, it's a private IP
    except ValueError:
        logger.warning(f"Invalid IP address: {ipv6_address}")
        return False

async def resolve_domain(domain: str, resolver, rtype) -> tuple:
    """
    Use aiodns to asynchronously resolve domain name and get its IP address.

    :param domain: Domain name to resolve
    :param resolver: aiodns DNS resolver object
    :return: Resolved IP address or error message
    """
    # Create aiodns resolver
    if rtype == 1:
        try:
            response = await resolver.gethostbyname(domain, family=socket.AF_INET)
            ip_addresses = response.addresses

            IsInnet = False
            for ipv4 in ip_addresses:
                if is_private_ipv4(ipv4):
                    IsInnet = True
                    break
            return (domain, ', '.join(ip_addresses), IsInnet)
        except Exception as e:
            return (domain, False, False)

    elif rtype == 28:
        try:
            response = await resolver.gethostbyname(domain, family=socket.AF_INET6)
            ip_addresses = response.addresses
            IsInnet = False
            for ipv6 in ip_addresses:
                if is_private_ipv6(ipv6):
                    IsInnet = True
                    break
            return (domain, ', '.join(ip_addresses), IsInnet)
        except Exception as e:
            return (domain, False, False)

async def resolve_hostnames(domains, rtype):
    """
    Main async function for parallel resolution of multiple domain names.

    :param domains: Domain name list
    """
    # Create aiodns resolver
    resolver = aiodns.DNSResolver()

    # Create coroutine task list
    tasks = [resolve_domain(domain, resolver, rtype) for domain in domains]

    # Run coroutine tasks in parallel
    results = await asyncio.gather(*tasks)

    return results

def activeDNS(collection, Checknondm):
    """     
    Perform active resolution on PDNS database to update dataset
    :param Dataname: Obtained PDNS database name
    :return:
    """

    batch_size = 500  # Number of records processed per batch
    # query = {'$or': [{'ipv6': {'$exists': False}}, {'ipv4': {'$exists': False}}]}  # Query condition
    if Checknondm:
        query = {
        '$or': [
            {'ipv6': {'$exists': False}}, 
            {'ipv4': {'$exists': False}}, 
            {'$and': [{'ipv4': False}, {'ipv6': False}]}
            ]
        }  # Query condition
    else:
        query = {
        '$or': [
            {'ipv6': {'$exists': False}}, 
            {'ipv4': {'$exists': False}}
            ]
        }  # Query condition

    # Check if ipv4 and ipv6 fields of the last record in collection both exist
    last_record = collection.find_one(sort=[("_id", -1)])
    if last_record and 'ipv4' in last_record and 'ipv6' in last_record:
        logger.info("The last record has both ipv4 and ipv6 fields, task already completed.")
        return
    else:
        logger.info("Continue ADNS From last breakpoint...")

    total_docs = collection.count_documents(query)  # Get total number of documents in collection
    processed_docs = 0  # Number of processed documents

    last_id = None  # Record _id of the last processed document

    # Process in batches
    while processed_docs < total_docs:
        # If not the first query, add _id range condition
        if last_id is not None:
            if Checknondm:
                query = {
                    '$and': [
                        {'_id': {'$gt': last_id}},  # Only query documents with _id greater than last_id
                        {
                            '$or': [
                                {'ipv6': {'$exists': False}}, 
                                {'ipv4': {'$exists': False}}, 
                                {'$and': [{'ipv4IsInet': False}, {'ipv6IsInet': False}]}
                            ]
                        }
                    ]
                }  # Update query condition
            else:
                query = {
                    '$and': [
                        {'_id': {'$gt': last_id}},  # Only query documents with _id greater than last_id
                        {
                            '$or': [
                                {'ipv6': {'$exists': False}}, 
                                {'ipv4': {'$exists': False}}
                            ]
                        }   
                    ]
                }  # Update query condition

        # Query current batch data
        rrname_list = collection.find(query, {'domain': 1, '_id': 1}).sort('_id', 1).limit(batch_size)

        # Use set to deduplicate rrname
        unique_rrnames = {}
        k = 0
        for record in rrname_list:
            k += 1
            _id = record['_id']
            last_id = _id
            domain = record.get('domain')
            domain = domain.lower()

            if domain not in unique_rrnames:
                unique_rrnames[domain] = [_id]
            else:
                unique_rrnames[domain].append(_id)
        hostlist = unique_rrnames.keys()
        processed_docs += k

        # Run async main function
        time0 = time.time()
        resolveRes_ipv4 = asyncio.run(resolve_hostnames(hostlist, rtype=1))
        resolveRes_ipv6 = asyncio.run(resolve_hostnames(hostlist, rtype=28))
        for domain, IPs, IsInet in resolveRes_ipv4:
            for _id in unique_rrnames[domain]:
                collection.update_one({'_id': _id}, {'$set': {'ipv4':IPs, 'ipv4IsInet':IsInet}})
        logger.info(f"Runtime: {time.time() - time0}s.")
        for domain, IPs, IsInet in resolveRes_ipv6:
            for _id in unique_rrnames[domain]:
                collection.update_one({'_id': _id}, {'$set': {'ipv6': IPs, 'ipv6IsInet': IsInet}})

        # Update number of processed documents
        logger.info(f"{min(processed_docs, total_docs)} / {total_docs} has handled.")

    logger.info("ActiveDNS has finished the task.")


if __name__ == "__main__":
    # Connect to database
    import sys
    from pathlib import Path
    root_dir = Path(__file__).parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    from config_loader import get_mongodb_uri
    myclient = pymongo.MongoClient(get_mongodb_uri('hostcollision'))
    db = myclient["host"]
    collection = db["baidu.com-DTree-20201105000000TO20241105000000"]
    activeDNS(collection)