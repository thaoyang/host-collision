import time
import subprocess
from pymongo import MongoClient
from pathlib import Path
import argparse
import multiprocessing
import signal
import sys
from config_loader import get_mongodb_uri, get_main2_config

def stop_programs(sld):
    """Stop all related background programs"""
    subprocess.run(['pkill', '-f', f'-sld {sld}'], 
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Stopped all programs related to {sld}")


def signal_handler(signum, frame):
    """Handle Ctrl+C signal"""
    print("\nStopping program...")
    if 'sld' in globals():
        stop_programs(sld)
    sys.exit(0)


def collision_has_ended(sld, config):
    client = MongoClient(get_mongodb_uri('hostcollision'))
    db_name = config["databases"]["hosts_ok_supervisor"]
    db = client[db_name]
    host_collection = config["collection_patterns"]["host"].format(sld=sld)
    spv_collection = config["collection_patterns"]["spv"].format(sld=sld)

    if host_collection in db.list_collection_names() and spv_collection not in db.list_collection_names():
        return True
    return False

def is_command_running(command):
    try:
        result = subprocess.run(['pgrep', '-f', command], stdout=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False


def main(sld, maxGoroutine):
    # Read configuration from config file
    config = get_main2_config()
    check_cycle = config["check_cycle"]
    
    # Set signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Get project root directory and subdirectories
    root_dir = Path(__file__).parent
    checker_dir = root_dir / config["directories"]["checker_dir"]
    collision_dir = root_dir / config["directories"]["collision_dir"]
    
    # Ensure log directory exists
    main2_log_dir = root_dir / config["directories"]["main2_log_dir"]
    main2_log_dir.mkdir(parents=True, exist_ok=True)

    try:
        while True:
            Run_guard_main2 = False  # Record if in main2 stage
            Run_host_collision = False  # Record if in hostcollision stage
            Run_host_collision_checker = False  # Record if in hostcollision checker stage
            client = MongoClient(get_mongodb_uri('hostcollision'))
            if not is_command_running(f'python GuardProcedure-ForMain2.py -sld {sld}'):  # If main2 is not running: 1) GuardProcedure-ForMain2.py hasn't started; 2) GuardProcedure-ForMain2.py has finished
                db_name = config["databases"]["for_collision"]
                db = client[db_name]
                ip_collection_name = config["collection_patterns"]["ip"].format(sld=sld)
                if ip_collection_name not in db.list_collection_names():  # If ip collection doesn't exist, it's case 1), execute main2
                    Run_guard_main2 = True
                else:  # If ip collection exists, it's case 2), execute hostcollision.go
                    if not is_command_running(f"hostCollision.go -sld {sld}"):  # If hostcollision.go is not running, execute it
                        db_name = config["databases"]["hosts_ok_supervisor"]
                        db = client[db_name]
                        host_collection = config["collection_patterns"]["host"].format(sld=sld)
                        if host_collection in db.list_collection_names():
                            # Find total document count in host_collection
                            total_count = db[host_collection].count_documents({})
                            # Find number of documents with haschecked field value of 1
                            haschecked_count = db[host_collection].count_documents({"haschecked": 1})

                            # Check if they are equal
                            if total_count == haschecked_count:
                                Run_host_collision_checker = True
                            else:
                                Run_host_collision = True   
                        else:  # If host_collision doesn't exist, execute hostcollision.go
                            Run_host_collision = True
                    else:  # If hostcollision.go is running, just wait
                        time.sleep(check_cycle)
                        continue
            else:  # If main2 is running, just wait
                time.sleep(check_cycle)
                continue
        
            if Run_guard_main2:  # Run main2
                ip_collection_name = config["collection_patterns"]["ip"].format(sld=sld)
                print(f"Collection {ip_collection_name} does not exist, starting GuardProcedure-ForMain2.py")
                subprocess.run(['python', 'GuardProcedure-ForMain2.py', '-sld', sld],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif Run_host_collision:  # Run hostcollision.go
                db_name = config["databases"]["for_collision"]
                db = client[db_name]
                ip_collection_name = config["collection_patterns"]["ip"].format(sld=sld)
                collection = db[ip_collection_name]
                line_count = collection.count_documents({})
                # Check if the ip field of the first record is "null"
                first_record = collection.find_one({})
                if first_record and first_record.get('ip') == "null":
                    line_count -= 1
                print(f"line_count: {line_count}")
                print(f"maxGoroutine: {maxGoroutine}")
                M = min(line_count, maxGoroutine)
                subprocess.run([
                    f"nohup ./run_host_collision.sh {sld} {str(M)}"
                ], shell=True, cwd=str(collision_dir))
                print(f"Run --------> nohup ./run_host_collision.sh {sld} {str(M)}")
            elif Run_host_collision_checker:  # Run hostcollision checker
                db_name = config["databases"]["hosts_ok"]
                db = client[db_name]
                hosts_ok_collection = config["collection_patterns"]["hosts_ok"].format(sld=sld)
                status_zero_count = db[hosts_ok_collection].count_documents({"status_code": 0})
                if status_zero_count > 0:
                    checker_log = config["log_files"]["checker"].format(sld=sld)
                    subprocess.run([
                        f"nohup ./run_parallel_checker.sh {sld} > {checker_log}"
                    ], shell=True, cwd=str(checker_dir))
                    print(f"Run --------> nohup ./run_parallel_checker.sh {sld}")
                break
            time.sleep(check_cycle)

    except KeyboardInterrupt:
        print("\nStopping program...")
    finally:
        stop_programs(sld)
        # print("\nend successfully...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-sld", "--sld", help="SLD to check")
    # Read default maxGoroutine multiplier from config file
    try:
        config = get_main2_config()
        default_multiplier = config.get("default_max_goroutine_multiplier", 3)
    except:
        default_multiplier = 3
    parser.add_argument("-m", "--maxGoroutine", help="maxGoroutine", default=multiprocessing.cpu_count() * default_multiplier)
    args = parser.parse_args()
    sld = args.sld
    maxGoroutine = int(args.maxGoroutine)
    main(sld, maxGoroutine)
