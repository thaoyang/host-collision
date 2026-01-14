import asyncio
import ipaddress
import maxminddb
from pathlib import Path
import sys
from loguru import logger

# Add project root directory to path
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
from config_loader import get_ipscan_config

class MultiIPwhois():
    def __init__(self, ips:list, FULL_TXT = False):
        for ip in ips[:]:  # Use slice copy to avoid modifying list during iteration
            try:
                ip = ip.strip()
                assert self.is_valid_ipv4(ip) or self.is_valid_ipv6(ip)
            except:
                ips.remove(ip)
        self.ips = ips
        self.FULL_TXT = FULL_TXT
        
        # Read GeoLite2-ASN.mmdb path from config file
        try:
            config = get_ipscan_config()
            db_path = config.get("geolite2_asn_db_path", "GeoLite2-ASN.mmdb")
            # If relative path, resolve relative to project root directory
            if not Path(db_path).is_absolute():
                db_path = root_dir / db_path
            else:
                db_path = Path(db_path)
            
            if not db_path.exists():
                raise FileNotFoundError(f"GeoLite2-ASN.mmdb file does not exist: {db_path}")
            
            self.mmdb_reader = maxminddb.open_database(str(db_path))
            logger.info(f"Successfully loaded GeoLite2-ASN database: {db_path}")
        except Exception as e:
            logger.error(f"Failed to load GeoLite2-ASN database: {e}")
            raise

    def __del__(self):
        """Destructor, close mmdb database connection"""
        if hasattr(self, 'mmdb_reader') and self.mmdb_reader:
            try:
                self.mmdb_reader.close()
            except:
                pass

    def start(self):
        asn_results = asyncio.run(self.run_asn_queries_async(self.ips))
        return self.ips, asn_results

    # Query ASN information from GeoLite2-ASN.mmdb
    def asn_query(self, ip):
        """
        Query ASN information for an IP from GeoLite2-ASN.mmdb
        
        :param ip: IP address
        :return: (RIR, ASNOrg) tuple, where RIR is set to empty string, ASNOrg is in "AS{number} {organization}" format
        """
        try:
            # Query ASN information for the IP
            record = self.mmdb_reader.get(ip)
            
            if not record:
                return ('', '')
            
            # Extract ASN number and organization name
            asn_number = record.get('autonomous_system_number')
            asn_organization = record.get('autonomous_system_organization', '')
            
            if asn_number:
                # Format ASN information: AS{number} {organization}
                if asn_organization:
                    asn_org = f"AS{asn_number} {asn_organization}"
                else:
                    asn_org = f"AS{asn_number}"
                return ('', asn_org)  # Set RIR to empty string for compatibility
            else:
                return ('', '')
                
        except Exception as e:
            logger.warning(f"Failed to query ASN information for IP {ip}: {e}")
            return ('', 'ERROR')

    # Async wrapper for synchronous function
    async def asn_query_async(self, ip):
        loop = asyncio.get_event_loop()
        # Use run_in_executor to asynchronously execute the synchronous asn_query function
        return await loop.run_in_executor(None, self.asn_query, ip)

    # Asynchronously execute multiple ASN queries concurrently
    async def run_asn_queries_async(self, ips):
        tasks = [self.asn_query_async(ip) for ip in ips]  # Create coroutine tasks
        return await asyncio.gather(*tasks)  # Run all tasks concurrently

    def is_valid_ipv4(self, address):
        try:
            # Try to convert string to IPv4Address, if successful then it's a valid IPv4 address
            ip = ipaddress.IPv4Address(address)
            return True
        except ipaddress.AddressValueError:
            # Catch exception for invalid IPv4 address
            return False

    def is_valid_ipv6(self, address):
        try:
            # Try to convert string to IPv6Address, if successful then it's a valid IPv6 address
            ip = ipaddress.IPv6Address(address)
            return True
        except ipaddress.AddressValueError:
            # Catch exception for invalid IPv6 address
            return False

