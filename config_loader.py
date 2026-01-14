# -*- coding: utf-8 -*-
"""
Configuration file loading module
Used to centrally manage configuration information in the project, especially MongoDB connection information
"""
import json
import os
from pathlib import Path


def get_config_path():
    """Get configuration file path"""
    # Get project root directory
    current_file = Path(__file__).resolve()
    root_dir = current_file.parent
    config_path = root_dir / "config.json"
    return config_path


def load_config():
    """Load configuration file"""
    config_path = get_config_path()
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file does not exist: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config


def get_mongodb_uri(connection_name="hostcollision"):
    """
    Get MongoDB connection URI
    
    Note: All connections use the "hostcollision" account uniformly
    
    :param connection_name: Connection name, defaults to "hostcollision" (all connections use this account uniformly)
    :return: MongoDB connection URI string
    """
    config = load_config()
    connections = config.get("mongodb", {}).get("connections", {})
    
    if connection_name not in connections:
        raise ValueError(f"Connection configuration not found: {connection_name}")
    
    connection = connections[connection_name]
    return connection.get("uri")


def get_mongodb_config(connection_name="hostcollision"):
    """
    Get MongoDB connection configuration (returns dictionary containing host, port, username, password, etc.)
    
    Note: All connections use the "hostcollision" account uniformly
    
    :param connection_name: Connection name, defaults to "hostcollision" (all connections use this account uniformly)
    :return: MongoDB connection configuration dictionary
    """
    config = load_config()
    connections = config.get("mongodb", {}).get("connections", {})
    
    if connection_name not in connections:
        raise ValueError(f"Connection configuration not found: {connection_name}")
    
    return connections[connection_name]


def get_main1_config():
    """
    Get configuration for main1-prepare_slds
    
    :return: Dictionary containing targetlst, svpath, dm_keywords
    """
    config = load_config()
    main1_config = config.get("main1_prepare_slds", {})
    
    if not main1_config:
        raise ValueError("main1_prepare_slds configuration not found")
    
    # Validate required fields
    required_fields = ["targetlst", "svpath", "dm_keywords"]
    for field in required_fields:
        if field not in main1_config:
            raise ValueError(f"Missing required field in configuration: {field}")
    
    return main1_config


def get_passive_dns_config():
    """
    Get configuration for passiveDNS
    
    :return: Dictionary containing urls, api_credentials, timeout, max_records
    """
    config = load_config()
    pdns_config = config.get("passiveDNS", {})
    
    if not pdns_config:
        raise ValueError("passiveDNS configuration not found")
    
    # Validate required fields
    required_fields = ["urls", "api_credentials", "timeout", "max_records"]
    for field in required_fields:
        if field not in pdns_config:
            raise ValueError(f"Missing required field in configuration: {field}")
    
    # Validate urls sub-fields
    if "domestic" not in pdns_config["urls"] or "abroad" not in pdns_config["urls"]:
        raise ValueError("urls in configuration missing domestic or abroad field")
    
    # Validate api_credentials sub-fields
    if "fdp-access" not in pdns_config["api_credentials"] or "fdp-secret" not in pdns_config["api_credentials"]:
        raise ValueError("api_credentials in configuration missing fdp-access or fdp-secret field")
    
    return pdns_config


def get_main2_config():
    """
    Get configuration for main2-host_collision
    
    :return: Dictionary containing all main2-related configurations
    """
    config = load_config()
    main2_config = config.get("main2_host_collision", {})
    
    if not main2_config:
        raise ValueError("main2_host_collision configuration not found")
    
    # Validate required fields
    required_fields = ["check_cycle", "directories", "databases", "collection_patterns", "log_files", "time_range"]
    for field in required_fields:
        if field not in main2_config:
            raise ValueError(f"Missing required field in configuration: {field}")
    
    # Validate directories sub-fields
    required_dirs = ["checker_dir", "collision_dir", "main2_log_dir"]
    for dir_field in required_dirs:
        if dir_field not in main2_config["directories"]:
            raise ValueError(f"directories in configuration missing {dir_field} field")
    
    # Validate databases sub-fields
    required_dbs = ["for_collision", "host", "ip", "hosts_ok_supervisor", "hosts_ok"]
    for db_field in required_dbs:
        if db_field not in main2_config["databases"]:
            raise ValueError(f"databases in configuration missing {db_field} field")
    
    # Validate collection_patterns sub-fields
    required_collections = ["ip", "host", "hosts_ok", "spv", "nondm", "dtree", "dtree_process", "adns", "adns_asn"]
    for col_field in required_collections:
        if col_field not in main2_config["collection_patterns"]:
            raise ValueError(f"collection_patterns in configuration missing {col_field} field")
    
    # Validate log_files sub-fields
    if "checker" not in main2_config["log_files"] or "main2" not in main2_config["log_files"]:
        raise ValueError("log_files in configuration missing checker or main2 field")
    
    # Validate time_range sub-fields
    if "start_time" not in main2_config["time_range"] or "end_time" not in main2_config["time_range"]:
        raise ValueError("time_range in configuration missing start_time or end_time field")
    
    return main2_config


def get_ipscan_config():
    """
    Get configuration for ipscan_module
    
    :return: Dictionary containing geolite2_asn_db_path, batch_size
    """
    config = load_config()
    ipscan_config = config.get("ipscan_module", {})
    
    if not ipscan_config:
        raise ValueError("ipscan_module configuration not found")
    
    # Validate required fields
    if "geolite2_asn_db_path" not in ipscan_config:
        raise ValueError("Missing required field in configuration: geolite2_asn_db_path")
    
    # Set default value
    if "batch_size" not in ipscan_config:
        ipscan_config["batch_size"] = 500
    
    return ipscan_config


if __name__ == "__main__":
    # Test configuration loading
    try:
        config = load_config()
        print("Configuration file loaded successfully:")
        print(json.dumps(config, indent=2, ensure_ascii=False))
        
        print("\nTest MongoDB connection URI retrieval:")
        print(f"hostcollision: {get_mongodb_uri('hostcollision')}")
        
        print("\nTest main1-prepare_slds configuration retrieval:")
        main1_config = get_main1_config()
        print(f"targetlst: {main1_config.get('targetlst')}")
        print(f"svpath: {main1_config.get('svpath')}")
        print(f"dm_keywords: {main1_config.get('dm_keywords')}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()