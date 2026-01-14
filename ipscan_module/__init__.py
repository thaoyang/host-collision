from pymongo import MongoClient
import ipaddress
from .MultiIpwhois import MultiIPwhois
from tqdm import tqdm
from loguru import logger

def is_private_ipv4(ip_address: str) -> bool:
    # Check if it's a private IP
    try:
        ip = ipaddress.ip_address(ip_address)
        P1 = ip.is_private
        P2 = ip in ipaddress.ip_network('100.64.0.0/10')
        return P1 or P2
    except ValueError:
        # logger.warning(f"Invalid IP address: {ip_address}")
        return False

def is_private_ipv6(ipv6_address):
    # Check if it's a private IP
    try:
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        return (ipv6.is_private or ipv6.is_link_local)
    except ValueError:
        return False

def ip_stats(collection_rd, collection_sv_adns, batch=500):
    # Read specified column data from collection
    field_name = ['domain', 'ipv4', 'ipv6']  # Field names to be counted

    tmp = dict()
    for field in field_name:
        tmp[field] = 1
    field_name = tmp
    field_name['_id'] = 0
    count = collection_rd.count_documents({})
    data = collection_rd.find({}, field_name, no_cursor_timeout=True)

    # Extract field values and perform frequency statistics
    field_values_adns = dict()
    ip_dms_adns = dict()
    with tqdm(total=count) as pbar:
        for item in data:
            dm = item['domain']
            ipv4s_adns = item['ipv4']
            ipv6s_adns = item['ipv6']
            iplst = []
            if ipv4s_adns:
                if ipv4s_adns[-1] == ';':
                    ipv4s_adns = ipv4s_adns[:-1]
                iplst.extend(ipv4s_adns.replace(' ', '').split(','))
            if ipv6s_adns:
                if ipv6s_adns[-1] == ';':
                    ipv6s_adns = ipv6s_adns[:-1]
                iplst.extend(ipv6s_adns.replace(' ', '').split(','))
            for ip in iplst:
                ip = ip.strip()
                if is_private_ipv4(ip) or is_private_ipv6(ip):  # Only record public IPs
                    continue
                if ip not in ip_dms_adns:
                    ip_dms_adns[ip] = {dm}
                else:
                    ip_dms_adns[ip].add(dm)
            pbar.update()
        data.close()
    for ip in ip_dms_adns:
        field_values_adns[ip] = len(ip_dms_adns[ip])

    field_values_adns = dict(sorted(field_values_adns.items(), key=lambda item: item[1], reverse=True))

    ip_whois_dict = dict()
    ips_adns = list(field_values_adns.keys())

    # Read batch size from config file
    try:
        import sys
        from pathlib import Path
        root_dir = Path(__file__).parent.parent
        if str(root_dir) not in sys.path:
            sys.path.insert(0, str(root_dir))
        from config_loader import get_ipscan_config
        config = get_ipscan_config()
        batch = config.get("batch_size", batch)
    except:
        pass  # If config loading fails, use default batch value
    
    for i in tqdm(range(0, len(ips_adns), batch)):
        ips = ips_adns[i:min(i+batch, len(ips_adns))]
        ips_, rir_orgs = MultiIPwhois(ips, FULL_TXT=False).start()
        for ip, rir_org in zip(ips_, rir_orgs):
            ip_whois_dict[ip] = rir_org

        for ip in ips:
            """hostnum: the number of hostnames which are resolved to the ip."""
            if ip in ip_whois_dict:
                collection_sv_adns.insert_one({'ip': ip, 'hostnum': field_values_adns[ip], 'RIR': ip_whois_dict[ip][0],
                                               'ASNOrg': ip_whois_dict[ip][1]})
            else:
                collection_sv_adns.insert_one({'ip': ip, 'hostnum': field_values_adns[ip]})


def ip_analysis_to_asn(collection_ip, collection_asn_sv):
    data_analysis = collection_ip.find({}, {'ASNOrg':1, 'hostnum':1, '_id':0})
    ASN_ip_dict = dict()
    for item in data_analysis:
        asn, hostnum = item['ASNOrg'], item['hostnum']
        if asn not in ASN_ip_dict:
            ASN_ip_dict[asn] = [1, hostnum]
        else:
            ASN_ip_dict[asn][0] += 1
            ASN_ip_dict[asn][1] += hostnum
    """sort by the number of hostnames"""
    ASN_ip_dict = dict(sorted(ASN_ip_dict.items(), key=lambda item: item[1][1], reverse=True))
    for asn in ASN_ip_dict:
        collection_asn_sv.insert_one({'ASNOrg':asn, 'ipnum':ASN_ip_dict[asn][0], 'hostnum':ASN_ip_dict[asn][1]})


# Connect to MongoDB
def main(collection_rd, collection_sv_adns, collection_sv_adns_asn):
    logger.info("Now in IPscan Module...")
    ip_stats(collection_rd, collection_sv_adns)
    ip_analysis_to_asn(collection_sv_adns, collection_sv_adns_asn)
    # ip_analysis_to_asn(collection_sv_pdns, collection_sv_pdns_asn)



# if __name__ == '__main__':
#     client = MongoClient("mongodb://admin:tsinghua@202.112.47.79:27017")  # Change connection URL as needed
#     db = client['host']  # Database name
#     sld = "alibaba-inc.com"
#     clname = 'alibaba-inc.com-PDNS&rtype=1&start=20200101000000&end=20240920000000&mode=6'
#     assert sld in clname
#     collection_rd = db[clname]  # Collection name
#
#     db = client['ip']
#     collection_sv_pdns = db[f'{sld}-pdns']
#     collection_sv_pdns.delete_many({})
#
#     collection_sv_adns = db[f'{sld}-adns']
#     collection_sv_adns.delete_many({})
#
#     collection_sv_adns_asn = db[f'{sld}-adns-asn']
#     collection_sv_adns_asn.delete_many({})
#
#     collection_sv_pdns_asn = db[f'{sld}-pdns-asn']
#     collection_sv_pdns_asn.delete_many({})
#
#
#     main(collection_rd, collection_sv_adns, collection_sv_adns_asn)