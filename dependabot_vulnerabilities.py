import requests
from dotenv import load_dotenv
import os
import urllib.parse
import json

# Load .env file
load_dotenv()

# Constants
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
ORGANIZATION = os.getenv('ORGANIZATION')
URL_REPOS = os.getenv('URL_REPOS')
URL_ALERTS = os.getenv('URL_ALERTS')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'}

def get_repositories(org):
    """Fetch all repositories in the given organization."""
    repos = []
    url = URL_REPOS.format(org)
    while url:
        response = requests.get(url, headers=HEADERS)
        data = response.json()
        repos.extend([repo['name'] for repo in data])
        url = response.links.get('next', {}).get('url')  # Pagination
    return repos


def get_vulnerabilities(repo):
    """Fetch critical and high vulnerabilities for a given repository with pagination."""
    url = URL_ALERTS.format(ORGANIZATION, repo)
    vulnerabilities = []

    while url:
        response = requests.get(url, headers=HEADERS)
        # Check if the response is successful (2xx status code)
        if response.status_code >= 200 and response.status_code < 300:
            # Add the current page's results to the vulnerabilities list
            vulnerabilities.extend(response.json())

            # Parse the "Link" header to find the next page URL, if it exists
            links = response.headers.get('Link', '')
            next_url = None
            if links:
                for link in links.split(','):
                    if 'rel="next"' in link:
                        next_url = link[link.find('<') + 1:link.find('>')]
                        break

            # Set the URL to the next page or None if there's no next page
            url = next_url
        else:
            return []

    # Filter vulnerabilities
    return [
        v for v in vulnerabilities
        if 'security_advisory' in v
        and v['security_advisory'].get('severity') in ['critical', 'high']
        and v['state'] == 'open'
    ]


def get_base_url(url):
    # Parse the URL into components
    parsed_url = urllib.parse.urlparse(url)

    # Split the path on '/' and remove the last element
    path_parts = parsed_url.path.split('/')
    if len(path_parts) > 1:  # Ensure there is something to remove
        new_path = '/'.join(path_parts[:-1])
    else:
        new_path = ''

    # Construct the new URL without the last path element
    new_url = parsed_url._replace(path=new_path).geturl()
    return new_url



def main():
    repos = get_repositories(ORGANIZATION)
    print("Repository,Critical,High,URL")
    for repo in repos:
        vulnerabilities = get_vulnerabilities(repo)
        if vulnerabilities:
            url = ""
            critical = 0
            high = 0
            for v in vulnerabilities:
                if url == "":
                    url = get_base_url(v['html_url'])

                if v['security_advisory'].get('severity') == 'critical':
                    critical = critical + 1
                if v['security_advisory'].get('severity') == 'high':
                    high = high + 1

            print(f"{repo},{critical},{high},{url}")

if __name__ == "__main__":
    main()

