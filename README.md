# Host Collision Detection System

A comprehensive system for detecting host header collision vulnerabilities by discovering domains associated with target organizations and testing for collision scenarios.

## Overview

This project implements a multi-stage pipeline for:
1. **Root Domain Discovery**: Extracting and discovering root domains (SLDs) from target URLs
2. **Subdomain Enumeration**: Using passive DNS, active DNS, and active HTTP scanning to discover subdomains
3. **IP Analysis**: Collecting and analyzing IP addresses with ASN information
4. **Host Collision Testing**: Testing discovered hosts for collision vulnerabilities using Go-based high-performance scanning

## Included Data

The project includes two important data files:

1. **`company_tested.json`**: A comprehensive list of target organizations. The file includes major organizations across various industries (technology, finance, energy, automotive, etc.).

2. **`ipscan_module/GeoLite2-ASN.mmdb`**: The MaxMind GeoLite2 ASN (Autonomous System Number) database. This database is used for:
   - Mapping IP addresses to their ASN numbers
   - Identifying the organization associated with each ASN
   - Filtering and analyzing IP addresses based on their network ownership

   **Note**: This is the GeoLite2 ASN database from MaxMind. For the most up-to-date version, you can download it from [MaxMind's website](https://dev.maxmind.com/geoip/geoip2/geolite2/).

## Project Structure

```
host-collision/
├── main1-prepare_slds.py          # Stage 1: Root domain discovery from target URLs
├── host_collision_main2-prepare_input.py  # Stage 2: Prepare input data (PDNS, ADNS, AHTTP)
├── main2-host_collision.py        # Main coordinator for host collision detection workflow
├── GuardProcedure-ForMain2.py    # Daemon process to monitor and restart prepare_input
├── config.json                    # Centralized configuration file
├── config_loader.py               # Configuration loader utilities
├── utils.py                       # Utility functions (hostwhois, etc.)
├── requirements.txt               # Python dependencies
├── company_slds_tested.json       # List of target organizations and their SLDs
│
├── hostscan_module/               # Host scanning modules
│   ├── __init__.py               # Main hostscan orchestration
│   ├── passiveDNS.py             # Passive DNS scanning via FDP API
│   ├── activeDNS.py              # Active DNS resolution
│   └── activeHTTP.py             # Active HTTP scanning
│
├── ipscan_module/                # IP scanning and analysis
│   ├── __init__.py               # IP statistics and ASN lookup
│   ├── MultiIpwhois.py           # ASN lookup using GeoLite2-ASN.mmdb
│   ├── ip_select_main.py         # IP selection and processing
│   └── GeoLite2-ASN.mmdb         # MaxMind GeoLite2 ASN database
│
└── host_collision_Go/            # Go-based host collision scanner
    ├── hostCollision.go          # Main collision detection logic
    ├── rerun_collision.py        # Python wrapper for rerunning collisions
    ├── run_host_collision.sh     # Shell script to run collision detection
    ├── go.mod                    # Go dependencies
    └── simHtml/                  # HTML similarity calculation
        ├── calSim.go
        ├── getSim.go
        └── utils.go
```

## Features

- **Multi-stage Pipeline**: Automated workflow from domain discovery to collision testing
- **Passive DNS Scanning**: Integration with FDP (Qianxin) passive DNS API
- **Active DNS/HTTP Scanning**: Concurrent DNS resolution and HTTP requests
- **IP Analysis**: ASN lookup using GeoLite2-ASN database
- **High-Performance Scanning**: Go-based collision detection with rate limiting
- **MongoDB Integration**: Centralized data storage and retrieval
- **Configuration Management**: Centralized configuration via `config.json`
- **Process Monitoring**: Automatic process monitoring and restart capabilities

## Prerequisites

### Python Requirements
- Python 3.7+
- MongoDB (local or remote instance)
- GeoLite2-ASN.mmdb database file

### Go Requirements (for host collision scanner)
- Go 1.23.3+

### External Services
- MongoDB database
- FDP (Qianxin) Passive DNS API access (optional, for passive DNS scanning)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd host-collision
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Go dependencies** (for host collision scanner):
   ```bash
   cd host_collision_Go
   go mod download
   go build -o hostCollision hostCollision.go
   cd ..
   ```

4. **Configure the project**:
   - Edit `config.json` with your MongoDB connection details
   - Configure API credentials for passive DNS (if using)
   - Set time ranges, directories, and other parameters

5. **Verify included data files**:
   - `company_slds_tested.json` should be in the project root directory
   - `ipscan_module/GeoLite2-ASN.mmdb` should be in the `ipscan_module/` directory
   - Both files are included with the project, but you can update `GeoLite2-ASN.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/) if needed

## Configuration

All configuration is managed through `config.json`. Key sections include:

### MongoDB Connection
```json
{
  "mongodb": {
    "connections": {
      "hostcollision": {
        "host": "your-mongodb-host",
        "port": 27017,
        "username": "your-username",
        "password": "your-password",
        "uri": "mongodb://user:pass@host:27017/"
      }
    }
  }
}
```

### Main1 Prepare SLDs
```json
{
  "main1_prepare_slds": {
    "targetlst": ["https://www.example.com"],
    "svpath": "sld_output/",
    "dm_keywords": ["example", "keyword1"]
  }
}
```

### Passive DNS Configuration
```json
{
  "passiveDNS": {
    "urls": {
      "domestic": "https://fdp.qianxin**/********/dtree/{DM}",
      "abroad": "https://fdp.qianxin**/********/dtree/{DM}"
    },
    "api_credentials": {
      "fdp-access": "your-access-key",
      "fdp-secret": "your-secret-key"
    },
    "timeout": {
      "min_timeout": 600,
      "initial_timeout": 600,
      "delta": 120,
      "max_try_times": 10
    },
    "max_records": 100000000
  }
}
```

### Main2 Host Collision Configuration
```json
{
  "main2_host_collision": {
    "check_cycle": 60,
    "directories": {
      "checker_dir": "host_collision_checker_Go",
      "collision_dir": "host_collision_Go",
      "main2_log_dir": "main2Log"
    },
    "databases": {
      "for_collision": "ForCollision",
      "host": "host",
      "ip": "ip",
      "hosts_ok_supervisor": "hosts-ok-supervisor-1",
      "hosts_ok": "hosts-ok-1"
    },
    "time_range": {
      "start_time": "20210601000000",
      "end_time": "20250601000000"
    },
    "default_max_goroutine_multiplier": 3
  }
}
```

## Usage

### Stage 1: Root Domain Discovery (Optional)

Discover root domains from target URLs. This is an optional preliminary step to identify target SLDs:

```bash
python main1-prepare_slds.py
```

This script:
- Reads target URLs from `config.json` (`main1_prepare_slds.targetlst`)
- Crawls web pages to extract links and domains
- Uses whois information to identify root domains
- Saves discovered SLDs to the output directory

**Note**: This stage is optional. You can skip it if you already know the target SLD(s).

### Main Workflow: Automated Host Collision Detection

Run the main coordinator to automatically handle both Data Collection and Collision Detection phases:

```bash
python main2-host_collision.py --sld example.com --maxGoroutine 100
```

**Parameters**:
- `--sld` or `-sld`: Target second-level domain (required, e.g., `example.com`)
- `--maxGoroutine` or `-m`: Maximum number of goroutines for collision detection (default: CPU count × 3)

**What this script does automatically**:

1. **Checks if input data exists**:
   - If IP collection doesn't exist → Automatically starts **Data Collection Phase**
   - If IP collection exists → Proceeds to **Collision Detection Phase**

2. **Data Collection Phase** (automatically triggered if needed):
   - Runs `GuardProcedure-ForMain2.py` which monitors and manages `host_collision_main2-prepare_input.py`
   - Performs:
     - **Passive DNS Scanning**: Queries FDP API for historical DNS records
     - **Active DNS Scanning**: Resolves discovered domains
     - **Active HTTP Scanning**: Sends HTTP requests to discovered hosts (optional, configurable)
     - **IP Analysis**: Extracts IPs and performs ASN lookups
   - Waits until IP collection is created

3. **Collision Detection Phase** (automatically triggered when data is ready):
   - Executes `hostCollision.go` when IP collection is ready
   - Performs host header collision testing
   - Stores results in MongoDB
   - Monitors progress and handles the entire lifecycle

4. **Process Management**:
   - Monitors workflow state every 60 seconds (configurable via `check_cycle`)
   - Automatically restarts failed processes
   - Handles graceful shutdown on Ctrl+C

**Example**:
```bash
# Start the automated workflow for a target domain
python main2-host_collision.py --sld google.com

# With custom goroutine limit
python main2-host_collision.py --sld google.com --maxGoroutine 200
```

### Manual Data Preparation (Advanced)

If you need to manually prepare input data or resume from a failure:

```bash
python host_collision_main2-prepare_input.py --sld example.com
```

**Options**:
- `--sld`: Target second-level domain (required)
- `--abroad`: Retry mode for failed API calls (`true`/`false`)
- `--lastkey`: Request page identifier when last failed (for resuming interrupted PDNS)
- `--AHTTP`: Whether to perform active HTTP scanning (`true`/`false`, default: `False`)
- `--dmUpdate`: Whether to update domain collection (`true`/`false`)
- `--ipUpdate`: Whether to update IP collection (`true`/`false`)

**Note**: Normally, you don't need to run this manually as `main2-host_collision.py` handles it automatically.

### Direct Host Collision Scanning (Advanced)

Run the Go-based collision scanner directly (usually not needed):

```bash
cd host_collision_Go
./hostCollision -sld example.com -t 100 -D -DNSt 500
```

**Options**:
- `-sld`: Target second-level domain (required)
- `-t`: Number of goroutines for HTTP requests (0 = auto)
- `-D`: Use DNS to filter non-domains
- `-DNSt`: Number of goroutines for DNS requests
- `-RecheckInetdm`: Recheck internet domains

**Note**: Normally, you don't need to run this directly as `main2-host_collision.py` handles it automatically.

## Workflow

The system follows this automated workflow when you run `main2-host_collision.py`:

### Automated Workflow (Recommended)

When you run `main2-host_collision.py --sld example.com`, the system automatically:

1. **Checks Current State**:
   - Checks if IP collection exists in MongoDB
   - Determines which phase to run next

2. **Data Collection Phase** (if IP collection doesn't exist):
   - Automatically starts `GuardProcedure-ForMain2.py`
   - `GuardProcedure-ForMain2.py` monitors and runs `host_collision_main2-prepare_input.py`
   - Performs:
     - **Passive DNS**: Query historical DNS records from FDP API
     - **Active DNS**: Resolve discovered domains concurrently
     - **Active HTTP**: Send HTTP requests to hosts (optional)
     - **IP Analysis**: Extract IPs and perform ASN lookups using GeoLite2-ASN
   - Creates IP collection in MongoDB when complete

3. **Collision Detection Phase** (when IP collection exists):
   - Automatically starts `hostCollision.go`
   - Reads IPs and hosts from MongoDB
   - Sends HTTP requests with Host headers
   - Detects collision vulnerabilities
   - Stores results in MongoDB

4. **Continuous Monitoring**:
   - Monitors workflow state every 60 seconds (configurable)
   - Automatically restarts failed processes
   - Handles transitions between phases
   - Manages process lifecycle

### Optional: Manual Root Domain Discovery

Before running the main workflow, you can optionally discover root domains:

1. **Discovery Phase** (`main1-prepare_slds.py`):
   - Extract root domains from target URLs
   - Identify organization domains via whois
   - Save discovered SLDs for use in main workflow

**Note**: This is optional. You can skip it if you already know the target SLD(s).

## Rate Limiting

The Go-based collision scanner implements per-IP rate limiting:
- **1 request per second** per IP address
- **1-hour pause** after 10,000 consecutive requests to the same IP
- Rate limiting does not affect requests to other IPs

## Data Storage

All data is stored in MongoDB with the following structure:

### Databases
- `ForCollision`: IPs and hosts prepared for collision testing
- `host`: Domain and DNS records
- `ip`: IP statistics and ASN information
- `hosts-ok-supervisor-1`: Host collision results (supervisor)
- `hosts-ok-1`: Host collision results

### Collection Naming Patterns
- IPs: `{sld}-ip`
- Hosts: `{sld}-host`
- DNS Records: `{sld}-DTree-{start_time}TO{end_time}`
- Active DNS: `{sld}-adns`
- Active DNS with ASN: `{sld}-adns-asn`
- Results: `{sld}-hosts_ok`

## Modules

### hostscan_module

**passiveDNS.py**: Passive DNS scanning via FDP API
- Queries historical DNS records
- Handles pagination and rate limiting
- Stores results in MongoDB

**activeDNS.py**: Active DNS resolution
- Concurrent DNS queries using aiodns
- Filters private IPs
- Resolves both IPv4 and IPv6

**activeHTTP.py**: Active HTTP scanning
- Concurrent HTTP requests using aiohttp
- Extracts links and domains from responses
- Performs whois checks for domain validation

### ipscan_module

**MultiIpwhois.py**: ASN lookup using GeoLite2-ASN
- Reads from MaxMind GeoLite2-ASN.mmdb
- Extracts ASN number and organization
- Returns formatted ASN information

**__init__.py**: IP statistics and processing
- Analyzes IP frequency from DNS records
- Performs batch ASN lookups
- Stores IP statistics in MongoDB

## Logging

Logs are stored in:
- `main2Log/`: Main workflow logs
- `host_collision_Go/log1/`: Go scanner logs

All Python modules use `loguru` for logging.

## Troubleshooting

### MongoDB Connection Issues
- Verify MongoDB connection details in `config.json`
- Ensure MongoDB is running and accessible
- Check network connectivity

### API Rate Limiting
- Adjust timeout settings in `config.json` for passive DNS
- Reduce concurrent requests if hitting rate limits

### Process Monitoring
- Check if processes are running: `pgrep -af "script_name"`
- Review logs in `main2Log/` directory
- Use `GuardProcedure-ForMain2.py` to auto-restart failed processes

### GeoLite2-ASN Database
- Ensure `GeoLite2-ASN.mmdb` exists in `ipscan_module/`
- Download from MaxMind if missing
- Verify file permissions

## Dependencies

### Python Dependencies
See `requirements.txt` for complete list:
- `aiohttp>=3.8.0`: Async HTTP client
- `aiodns>=3.0.0`: Async DNS resolver
- `pymongo>=4.0.0`: MongoDB driver
- `loguru>=0.6.0`: Logging
- `tqdm>=4.64.0`: Progress bars
- `tldextract>=5.0.0`: Domain extraction
- `maxminddb>=2.2.0`: GeoLite2 database reader
- And more...

### Go Dependencies
See `host_collision_Go/go.mod`:
- `github.com/go-resty/resty/v2`: HTTP client
- `github.com/miekg/dns`: DNS library
- `go.mongodb.org/mongo-driver`: MongoDB driver
- `github.com/sirupsen/logrus`: Logging
- And more...

## License

[Specify your license here]

## Contributing

[Add contribution guidelines if applicable]

## Contact

[Add contact information if applicable]
