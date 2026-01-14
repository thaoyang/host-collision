import time
import subprocess
from pymongo import MongoClient
import argparse, sys
from pathlib import Path
from config_loader import get_mongodb_uri, get_main2_config

def check_and_run(sld):
    # Read configuration from config file
    config = get_main2_config()
    check_cycle = config["check_cycle"]
    time_range = config["time_range"]
    start_time = time_range["start_time"]
    end_time = time_range["end_time"]
    
    # Build collection names
    dtree_collection_name = config["collection_patterns"]["dtree"].format(
        sld=sld, start_time=start_time, end_time=end_time
    )
    process_collection_name = config["collection_patterns"]["dtree_process"].format(
        sld=sld, start_time=start_time, end_time=end_time
    )

    client = MongoClient(get_mongodb_uri('hostcollision'))  # Read connection information from config file

    while True:
        # Check if the script is running
        process_check = subprocess.run(['pgrep', '-af', f'host_collision_main2-prepare_input.py -sld {sld}'],
                                       stdout=subprocess.PIPE)
        if not process_check.stdout:
            db_name = config["databases"]["for_collision"]
            db = client[db_name]
            ip_collection_name = config["collection_patterns"]["ip"].format(sld=sld)
            if ip_collection_name in db.list_collection_names():
                break

            else:
                db_name = config["databases"]["host"]
                db = client[db_name]
                process_collection = db[process_collection_name]
                try:
                    last_record_process = process_collection.find_one(sort=[("_id", -1)])
                except:
                    print("Mongodb connect error!!!")
                    time.sleep(check_cycle)
                    continue

                if last_record_process:
                    abroad = last_record_process.get('abroad', '')
                    lastkey = last_record_process.get('lastKey', '')

                    # Read log path from config file
                    root_dir = Path(__file__).parent
                    main2_log_dir = root_dir / config["directories"]["main2_log_dir"]
                    main2_log_dir.mkdir(parents=True, exist_ok=True)
                    main2_log_file = config["log_files"]["main2"].format(sld=sld)
                    main2_log_path = root_dir / main2_log_file
                    
                    if lastkey:  # If lastkey is not empty, it means PDNS was interrupted and restarted, execute command with --abroad and --lastkey
                        command = f"nohup python host_collision_main2-prepare_input.py -sld {sld} --abroad {abroad} --lastkey {lastkey} --AHTTP false > {main2_log_path} &"
                    else:  # Otherwise, PDNS has finished or hasn't started yet
                        command = f"nohup python host_collision_main2-prepare_input.py -sld {sld} --AHTTP false > {main2_log_path} &"

                    subprocess.run(command, shell=True)
                    print(f"Command executed: {command}")
                else:
                    # Read log path from config file
                    root_dir = Path(__file__).parent
                    main2_log_dir = root_dir / config["directories"]["main2_log_dir"]
                    main2_log_dir.mkdir(parents=True, exist_ok=True)
                    main2_log_file = config["log_files"]["main2"].format(sld=sld)
                    main2_log_path = root_dir / main2_log_file
                    command = f"nohup python host_collision_main2-prepare_input.py -sld {sld} --AHTTP false > {main2_log_path} &"
                    subprocess.run(command, shell=True)
                    print(f"Command executed: {command}")

        else:
            print(f"Script is already running for SLD: {sld}")

        time.sleep(check_cycle)



def argparser():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Here we can help prepare data which are used in HC module for some SLD',
                                     epilog='\tUsage:\npython ' + sys.argv[
                                         0] + " -sld google.com")
    parser.add_argument('--sld', '-sld', help='A target like example.com', required=True)
    args = parser.parse_args()
    return args

# Example usage
args = argparser()
sld = args.sld
check_and_run(sld)
