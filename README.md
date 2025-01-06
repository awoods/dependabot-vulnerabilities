# Dependabot Vulnerabilities
This script reads the `critical` and `high` dependabot vulnerabilities from all repositories in the provided Github organization and prints a CSV formatted result to the console.

## Usage

### Setup
```bash
python3.11 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

Credentials, populate with Github PAT (`Read access to Dependabot alerts, administration, and metadata`) and Github organization name.
```bash
cp env-example .env
vi .env
```

### Execution
```bash
python dependabot_vulnerabilities.py > vulnerabilities-2025-01-06.csv
```
