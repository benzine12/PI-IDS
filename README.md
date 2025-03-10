# PI-IDS - WIFI attacking Detection System on Raspberry Pi 

![PI-IDS Banner](https://img.shields.io/badge/WIDS-Wireless%20Intrusion%20Detection-blue?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PI-IDS is a detection system designed to monitor and protect wireless networks with Raspberry Pi. It detects various types of wireless attacks in real-time, tracks access points, and provides a web-based dashboard for monitoring and management.


> **⚠️ DISCLAIMER**: This tool is developed for educational purposes only. The developer takes no responsibility for any misuse or for the accuracy of attack detection. Use at your own risk and only on networks you own or have permission to test.

## ✨ Features

- 🔍 Real-time monitoring of wireless networks
- 🛡️ Detection of multiple attack vectors:
  - Deauthentication attacks
  - Probe scanning attacks
  - Beacon spam attacks
  - Rogue AP detection
  - KARMA/MANA attacks
- 📊 Advanced packet analysis and threat classification
- 🔐 Protected AP management system
- 🌓 Dark/light theme support
- 📊 System resource monitoring
- 🔔 Real-time alert notifications

## 📂 Project Structure

```
python_wifi_attack_detection/
├── backend/
│   ├── data.py                   # Database and state management
│   ├── instance/                 # SQLite database instance
│   │   └── wids.db               # Database file
│   ├── json_to_sqlite.py         # Utility for importing MAC vendor data
│   ├── logs.log                  # Application logs
│   ├── main.py                   # Main application entry point
│   ├── models.py                 # Database models
│   ├── modules.py                # Core detection modules
│   ├── requirements.txt          # Python dependencies
│   ├── routes.py                 # Flask API routes
│   ├── run_server.py             # Server setup utility
│   └── tests/                    # Test utilities
│       ├── beacon_spam_test.py   # Beacon spam attack simulator
│       └── probe_scanner_test.py # Probe scanner attack simulator
└── frontend/
    ├── static/                   # Static resources
    │   ├── ap_scan.js            # AP scanning page script
    │   ├── css/                  # CSS stylesheets
    │   ├── login.js              # Login page script
    │   ├── notification-system.js # Notification management
    │   ├── scripts.js            # Main dashboard scripts
    │   └── webfonts/             # Font resources
    └── templates/                # HTML templates
        ├── ap_scan.html          # AP scanning page
        ├── base.html             # Base template
        ├── dashboard.html        # Main dashboard
        └── login.html            # Login page
```

## 🔧 Prerequisites

- Python 3.6+
- Linux-based system (Ubuntu, Kali Linux, Raspbian)
- Wireless adapter capable of monitor mode ([supported adapters list](https://www.aircrack-ng.org/doku.php?id=compatible_cards))
- Root/sudo privileges
- aircrack-ng suite

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/benzine12/python_wifi_attack_detection.git
   cd python_wifi_attack_detection
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv env
   source env/bin/activate 
   ```

3. **Install requirements**:
   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Create a user account** (or use the default credentials mentioned below):
   ```bash
   sudo python main.py -c your_username
   ```

5. **Run the application**:
   ```bash
   sudo python main.py -i wlan0
   ```
   Replace `wlan0` with your wireless interface name capable of monitor mode.

6. **Access the dashboard**:
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## 🏃‍♂️ Quick Start

For quick testing, you can use the default credentials:
- **Username**: `admin`
- **Password**: `admin`

However, for production environments, it's strongly recommended to create a new user with a secure password and delete default.


## 📋 Command Line Arguments

The system supports the following command line arguments:

| Argument | Long Form | Description | Example |
|----------|-----------|-------------|---------|
| `-c` | `--Create` | Create a new user account | `python main.py -c your_username` |
| `-u` | `--Update` | Update an existing user's password | `python main.py -u your_username` |
| `-d` | `--Delete` | Delete a user account | `python main.py -d your_username` |
| `-i` | `--Interface` | Specify the wireless interface to use | `python main.py -i wlan0` |
| `-h` | `--Help` | Display help information | `python main.py -h` |

## 🛡️ Attack Detection Techniques

WIDS employs sophisticated detection techniques for various wireless threats:

### 1. Deauthentication Attacks

**What it is**: Attackers send spoofed deauthentication frames to disconnect legitimate clients from their APs, potentially forcing them to reconnect to rogue APs.

**Detection Method**: WIDS analyzes temporal patterns in deauthentication frames, looking for:
- Multiple frames sent in rapid succession
- Consistent time intervals between frames (suggesting automated tools)
- Frames sent to broadcast addresses or specific clients

**Implementation**: `DeauthDetector` class in `modules.py`

### 2. Probe Request Scanning

**What it is**: Attackers use tools to send numerous probe requests for different SSIDs to discover hidden networks and gather information about nearby APs.

**Detection Method**: WIDS monitors:
- Volume of probe requests from a single source
- Number of unique SSIDs being requested
- Time pattern of probe requests
- Flags devices that exceed configurable thresholds

**Implementation**: `ProbeScannerDetector` class in `modules.py`

### 3. Beacon Spam Attacks

**What it is**: Attackers flood the airwaves with fake beacon frames advertising non-existent APs to confuse wireless clients and tools.

**Detection Method**: WIDS analyzes:
- Beacon frame frequency from a specific source
- Number of unique SSIDs being advertised
- Temporal patterns of beacon transmission
- Flags sources exceeding normal beacon rates

**Implementation**: `BeaconSpamDetector` class in `modules.py`

### 4. Rogue AP Detection

**What it is**: Unauthorized access points set up to mimic legitimate networks, often used for man-in-the-middle attacks.

**Detection Method**: WIDS compares detected APs against a database of known legitimate APs, checking:
- BSSID (MAC address) discrepancies
- ESSID (network name) matches with different security settings
- Unusual configurations or unexpected security changes

**Implementation**: `is_rogue_ap()` function in `main.py`

### 5. Karma Attacks

**What it is**: Advanced rogue AP attacks where the attacker's AP responds to any probe request, mimicking whatever network a client is looking for.

**Detection Method**: WIDS looks for:
- APs that respond to multiple different probe requests
- High volumes of probe responses from a single source
- Matching SSIDs with different security configurations

**Implementation**: Integrated with rogue AP detection in `main.py`

## 🌐 API Routes Reference

### Authentication Endpoints

| Endpoint | Method | Description | Protected | Returns |
|----------|--------|-------------|-----------|---------|
| `/` | GET | Renders the login page | No | Login page HTML |
| `/login` | POST | Authenticates users | No | JWT token |
| `/dashboard` | GET | Renders the dashboard | Yes | Dashboard HTML |
| `/ap-scan` | GET | Renders the AP scan page | Yes | AP scan page HTML |

### Data Endpoints

| Endpoint | Method | Description | Protected | Returns |
|----------|--------|-------------|-----------|---------|
| `/get-aps` | GET | Retrieves active APs | Yes | JSON with AP data |
| `/packets` | GET | Retrieves attack data | Yes | JSON with attack data |
| `/resolve_attack/<id>` | PUT | Marks an attack as resolved | Yes | Success/failure message |
| `/system-stats` | GET | Retrieves system statistics | Yes | JSON with system data |

### AP Management Endpoints

| Endpoint | Method | Description | Protected | Returns |
|----------|--------|-------------|-----------|---------|
| `/set_to_protected` | POST | Adds an AP to protected list | Yes | Success/failure message |
| `/remove_from_protected` | POST | Removes AP from protected list | Yes | Success/failure message |

## 🧪 Testing the Detection System

The repository includes attack simulation tools to test and validate detection capabilities:

### Beacon Spam Testing

Tests the system's ability to detect beacon flooding attacks:

```bash
cd backend/tests
sudo python beacon_spam_test.py wlan0mon
```

### Probe Scanner Testing

Tests the system's ability to detect aggressive network scanning:

```bash
cd backend/tests
sudo python probe_scanner_test.py wlan0mon
```

> **IMPORTANT**: Always use a different wireless interface for testing than the one WIDS is monitoring. For example, if WIDS is monitoring `wlan0`, use `wlan1` for testing.

## 🎮 User Interface Guide

### Dashboard

The main dashboard provides:
- Real-time packet activity graph
- Threat detection graph
- System resource utilization
- Comprehensive table of detected attacks
- Options to resolve/acknowledge threats

### AP Scanner

The AP scanning view shows:
- List of all detected access points
- Signal strength and channel information
- Security information (encryption type)
- Option to add APs to protected list
- Band distribution statistics (2.4GHz vs 5GHz)

### Themes

You can switch between light and dark themes using the toggle in the top navigation bar.

## 🔍 Advanced Configuration

You can modify detection thresholds and behaviors by editing the corresponding classes in `modules.py`:

- `DeauthDetector`: Configure deauthentication attack detection sensitivity
- `ProbeScannerDetector`: Adjust probe request scanning thresholds
- `BeaconSpamDetector`: Modify beacon spam detection parameters

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📌 Acknowledgments

- Scapy project for packet manipulation capabilities
- Flask framework for the web interface
- Aircrack-ng suite for wireless tools
- All open-source contributors
