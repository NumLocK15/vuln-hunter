<h1 align="center">
    Vuln-Hunter
    <br>
</h1>

<h4 align="center">Streamlined Vulnerability Hunting</h4>

<p align="center">
  <a href="#about">📖 About</a> •
  <a href="#installation">🏗️ Installation</a> •
  <a href="#usage">⛏️ Usage</a> •
  <a href="#examples">🚀 Examples</a> •
  <a href="#contribution">🤝 Contributing</a>
</p>

![Banner](vuln-hunter-Banner.png)

# About

Vuln-Hunter is an automated workflow that utilizes existing community tools for web assessment. It's designed to streamline the process of scanning domains and hosts for vulnerabilities and misconfigurations, making it particularly useful for bug bounty and pentesting engagements.

## Tool Choices
While there are many tools available in the community, it is crucial to choose those that can be adjusted to each assessor's preference. This is why [Nuclei](https://github.com/projectdiscovery/nuclei) by ProjectDiscovery is a top choice. Each pentester can create custom templates that fit their style using a simple YAML-based DSL.

## Important Notes:
- The effectiveness of scans depends on the templates used. Some community templates can be found at [Nuclei-Fuzzing Templates](https://github.com/projectdiscovery/fuzzing-templates). However, it is often better to create your own to fit your style.
- Subfinder is highly effective, especially when augmented with additional sources (API keys), such as SecurityTrails.
- The workflow enables multi-threading for higher efficiency. Please choose the number of threads wisely.

# Installation

Before using Vuln-Hunter, ensure the following tools are installed on your system:

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Katana](https://github.com/projectdiscovery/katana)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [httpx](https://github.com/projectdiscovery/httpx)

Install these dependencies with the following commands:

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
git clone https://github.com/projectdiscovery/fuzzing-templates.git
mv fuzzing-templates $HOME/.local/nuclei-templates/
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip install .

#NOTE: Ensure your Go bin directory is included in your system's PATH. If it's not already set, temporarily add it with:
export PATH=$PATH:$HOME/go/bin
```
# Usage

To use Vuln-Hunter, run the script with the desired options. Below is the table of options for easy reference:

| Option                | Description                                                         |
| --------------------- | ------------------------------------------------------------------- |
| `-d, --domain`        | Specify a single domain for scanning.                               |
| `-l, --domain_list`   | Specify a file containing a list of domains (one per line).         |
| `--fuzzing`           | Perform Nuclei fuzzing scan.                                        |
| `--complete`          | Perform both basic and fuzzing scans.                               |
| `--paramspider`       | Use ParamSpider for parameterized URL discovery (default is Katana).|
| `--nobasic`           | Disable Nuclei basic scan.                                          |
| `-cs, --concurrentscans` | Specify the number of concurrent scans (default is 2).              |
| `-t, --timeout`       | Set a timeout for each scan in minutes (default is 30 minutes).     |
| `--silent`            | Run scans in silent mode.                                           |
| `--techdetect`        | Run a technology detection scan on the target.                      |
| `--allparams`         | Use both Katana and ParamSpider for URL extraction and merging.     |

Example usage:

```bash
python vuln-hunter.py [options]
```
# Examples

Here are some example commands to illustrate how you can use Vuln-Hunter:

1. Scan a single domain with a basic scan:
   ```bash
   python adhm_hunt.py -d example.com
   ```
2. Scan multiple domains from a file with both basic and fuzzing scans:
  ```bash
  python adhm_hunt.py -l domains.txt --complete
  ```
3. Run scans in silent mode for a single domain with a timeout of 15 minutes:
  ```bash
  python adhm_hunt.py -d example.com --silent -t 15
  ```
4. Run a complete scan with technology detection:
  ```bash
  python adhm_hunt.py -d example.com --complete --techdetect
  ```
5. Using both Katana and ParamSpider for URL extraction:
  ```bash
  python adhm_hunt.py -d example.com --fuzzing --allparams
  ```

# Contributing

Vuln-Hunter is a synthesis of several powerful tools developed by the cybersecurity community. The efficacy and utility of Vuln-Hunter are a testament to the ingenuity and hard work of the developers behind these individual tools. It's highly encouraged to visit their repositories to understand the depth of their contributions:

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Katana](https://github.com/projectdiscovery/katana)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [httpx](https://github.com/projectdiscovery/httpx)

This workflow is developed solely by myself as a contribution to the cybersecurity community. If you wish to contribute, enhance, or fork the project for your purposes, you are more than welcome to do so. Any contributions that improve the tool or extend its capabilities are greatly appreciated. 

Feel free to raise issues, submit pull requests, or suggest new features. Let's work together to make the cybersecurity space more robust and accessible to everyone. 

Let's hunt vulnerabilities smarter, not harder! 🚀

