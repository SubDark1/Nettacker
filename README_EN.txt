# Nettacker - Advanced Network Security Scanner

## About the Tool

Nettacker is an advanced network scanning tool inspired by OWASP Nettacker. It was developed to assist penetration testers and security auditors in network security assessment and web application testing. The tool features an easy-to-use interface and multiple scanning and testing capabilities.

## Key Features

- Scan for open ports on target systems
- Detect potential security vulnerabilities
- Analyze services running on ports
- Web application scanning using Wapiti
- Discovery of hidden paths and files
- Advanced path scanning using dirsearch (powerful for discovering hidden paths)
- Comprehensive path scanning using Gobuster (extremely powerful for discovering hidden paths and files)
- Ability to save results to text files
- Easy-to-use command-line interface
- Interactive distinctive logo

## System Requirements

- Operating System: Windows, Linux, or macOS
- Python 3.6 or newer
- Internet connection (for installation and some scanning operations)
- Storage space: At least 50 MB

## Required Libraries

- argparse>=1.4.0
- textwrap3>=0.9.2
- requests>=2.28.0
- colorama>=0.4.6
- scapy>=2.5.0
- bs4>=0.0.1
- beautifulsoup4>=4.11.0
- tqdm>=4.65.0

## Installation Steps

### 1. Install Python

Make sure Python 3.6 or newer is installed on your system. You can download Python from the official website:
https://www.python.org/downloads/

To check the installed Python version, run the following command in the command prompt or terminal:

```
python --version
```
or
```
python3 --version
```

### 2. Download Nettacker

You can download Nettacker using one of the following methods:

#### Using Git:

```
git clone https://github.com/SayerLinux/Nettacker.git
cd Nettacker
```

#### Direct Download:

- Visit the project page on GitHub: https://github.com/SayerLinux/Nettacker
- Click on the "Code" button and select "Download ZIP"
- Extract the downloaded file
- Navigate to the Nettacker folder using the command prompt or terminal

### 3. Install Required Libraries

After navigating to the Nettacker folder, run the following command to install all required libraries:

```
pip install -r requirements.txt
```
or
```
pip3 install -r requirements.txt
```

### 4. Verify Installation

To ensure successful installation, run the following command to display the help menu:

```
python nettacker.py -h
```
or
```
python3 nettacker.py -h
```

## Usage

### General Command Format

```
python nettacker.py -H <target> -p <ports> -m <scan_method> [additional_options]
```

### Available Options

#### General Options
- `-H, --host`: Target host to scan (domain name or IP address)
- `-p, --ports`: Ports to scan (comma-separated or range like 80,443 or 1-100)
- `-m, --method`: Scan method (vuln, port, service, dir, wapiti, dirsearch, gobuster, all)
- `-o, --output`: Save results to a file
- `-v, --verbose`: Enable verbose mode
- `-t, --timeout`: Connection timeout in seconds (default: 3)
- `--threads`: Number of concurrent scanning threads (default: 10)

#### Logo Options
- `--no-logo`: Disable logo display at program start
- `--show-logo-only`: Display only the logo and then exit (useful for viewing the interactive logo)

#### Wapiti Scan Options
- `--wapiti-timeout`: Wapiti scan timeout in seconds (default: 300)

#### Dirsearch Scan Options
- `--dirsearch-wordlist`: Path to wordlist file for dirsearch scan
- `--dirsearch-extensions`: File extensions to search for in dirsearch scan (example: php,asp,html)
- `--dirsearch-threads`: Number of concurrent threads for dirsearch (default: 10)
- `--dirsearch-timeout`: Dirsearch scan timeout in seconds (default: 30)

#### Gobuster Scan Options
- `--gobuster-wordlist`: Path to wordlist file for Gobuster scan
- `--gobuster-extensions`: File extensions to search for in Gobuster scan (example: php,asp,html,txt,bak,config)
- `--gobuster-threads`: Number of concurrent threads for Gobuster (default: 20)
- `--gobuster-timeout`: Gobuster scan timeout in seconds (default: 30)

## Usage Examples

### Port Scanning

```
# Scan a specific port
python nettacker.py -H target.com -p 80 -m port -v

# Scan a range of ports
python nettacker.py -H target.com -p 1-100 -m port -v
```

### Hidden Path and File Scanning

```
# Basic hidden path scanning
python nettacker.py -H target.com -p 80,443 -m dir -v

# Advanced path scanning using dirsearch
python nettacker.py -H target.com -p 80,443 -m dirsearch --dirsearch-extensions php,asp,html -v

# Comprehensive path scanning using Gobuster
python nettacker.py -H target.com -p 80,443 -m gobuster --gobuster-extensions php,html,txt,bak,config -v

# Gobuster scan with custom thread count, timeout, and wordlist
python nettacker.py -H target.com -p 80,443 -m gobuster --gobuster-threads 30 --gobuster-timeout 60 --gobuster-wordlist /path/to/wordlist.txt -v
```

### Vulnerability Scanning

```
# Basic vulnerability scanning
python nettacker.py -H target.com -p 80,443 -m vuln -v
```

### Comprehensive Scanning

```
# Comprehensive scan (includes port scanning, services, paths, vulnerabilities, Wapiti, dirsearch, and Gobuster)
python nettacker.py -H target.com -p 80,443 -m all -o results.txt -v --dirsearch-extensions php,asp,html --gobuster-extensions php,txt,bak,config --wapiti-timeout 600
```

### Logo Options

```
# Display only the interactive logo (useful for viewing the new logo in the browser)
python nettacker.py --show-logo-only

# Run a scan without displaying the logo
python nettacker.py -H target.com -p 80,443 -m all --no-logo -v
```

## Tips and Guidelines

1. **Use the tool responsibly**: Make sure you have permission to scan the target systems. Using the tool on systems without authorization may be illegal.

2. **Start with port scanning**: Before performing advanced scans, it's useful to know which ports are open first using `-m port`.

3. **Use verbose mode**: Use the `-v` option to get more detailed information during the scanning process.

4. **Save results**: Use the `-o` option to save scan results to a file for later reference.

5. **Adjust thread count**: You can increase scanning speed using the `--threads` option, keeping in mind that increasing the number may affect connection stability.

6. **Customize wordlists**: For better results in path scanning, use custom wordlists with the `--dirsearch-wordlist` or `--gobuster-wordlist` options.

## Troubleshooting

1. **Installation issues**: Make sure Python is installed correctly and you have the appropriate version (3.6+).

2. **Library errors**: If you encounter problems with libraries, try installing them separately:
   ```
   pip install argparse textwrap3 requests colorama scapy bs4 beautifulsoup4 tqdm
   ```

3. **Slow scanning**: Reduce the port range or increase the number of concurrent scanning threads using `--threads`.

4. **Connection problems**: Increasing the connection timeout using `-t` may help with slow networks.

5. **No results appearing**: Make sure the target is available and the specified ports are correct.

## Developer Information

- **Name**: SayerLinux
- **Email**: SaudiSayer@gmail.com

## License

This project is licensed under the MIT License.

---

Thank you for using Nettacker! If you have any questions or suggestions, please contact the developer.