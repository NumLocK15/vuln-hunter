# ADHM-Hunt

ADHM-Hunt is an Automated Domain and Host Monitoring Tool designed to streamline the process of scanning domains and hosts for vulnerabilities and misconfigurations. This tool is particularly useful for quick checks and is not a replacement for comprehensive security assessments.

## Installation

Before using ADHM-Hunt, ensure that the following tools are installed on your system:

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Katana](https://github.com/projectdiscovery/katana)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [httpx](https://github.com/projectdiscovery/httpx)

You can install these dependencies with the following commands:

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
git clone https://github.com/projectdiscovery/fuzzing-templates.git
mv fuzzing-templates $HOME/.local/nuclei-templates/
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip install .

NOTE: Ensure that your Go bin directory is included in your system's PATH. If it's not already set, you can temporarily add it to your PATH with the following command:
export PATH=$PATH:$HOME/go/bin
