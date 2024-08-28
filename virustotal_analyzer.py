import argparse
import requests
import json
import os
import logging
from datetime import datetime, timezone
from typing import List
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Set default output directory from environment variable or use "results" if not provided
OUTPUT_DIR = os.getenv('OUTPUT_DIR', 'results')

class VirusTotalV3:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_headers(self):
        return {
            "x-apikey": self.api_key
        }

    def query_ip(self, ip: str) -> dict:
        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()  # Raises HTTPError for bad responses
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying IP {ip}: {e}")
            raise RuntimeError(f"Error querying IP {ip}: {e}")
        return response.json()

    def query_url(self, url_value: str) -> dict:
        url_id = self._encode_url(url_value)
        url = f"{self.base_url}/urls/{url_id}"
        try:
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying URL {url_value}: {e}")
            raise RuntimeError(f"Error querying URL {url_value}: {e}")
        return response.json()

    def _encode_url(self, url_value: str) -> str:
        """Encodes the URL as required by the VirusTotal API."""
        import base64
        url_bytes = url_value.encode('utf-8')
        return base64.urlsafe_b64encode(url_bytes).decode('utf-8').strip("=")

    def analyze_iocs(self, iocs: List[str]) -> List[dict]:
        results = []
        for ioc in iocs:
            if self._is_ip(ioc):
                result = self.query_ip(ioc)
                ioc_type = "IP_ADDRESS"
            else:
                result = self.query_url(ioc)
                ioc_type = "URL"

            last_analysis = result.get('data', {}).get('attributes', {}).get('last_analysis_date', "N/A")
            is_malicious = self._is_malicious(result)
            results.append({
                "Identifier": ioc,
                "Type": ioc_type,
                "LastAnalysisTime": datetime.fromtimestamp(last_analysis, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if last_analysis != "N/A" else "N/A",
                "IsMalicious": is_malicious
            })
        return results

    def _is_ip(self, ioc: str) -> bool:
        """Checks if the IOC is an IP address."""
        import re
        ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return re.match(ip_regex, ioc) is not None

    def _is_malicious(self, result: dict) -> bool:
        """Determines if the IOC is malicious based on VirusTotal analysis."""
        stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return stats.get('malicious', 0) > 0

def load_iocs_from_file(file_path: str) -> List[str]:
    if file_path is None:
        logger.error("File path cannot be None")
        raise ValueError("File path cannot be None")

    try:
        with open(file_path, 'r') as file:
            iocs = file.read().splitlines()
    except FileNotFoundError:
        logger.error(f"The file {file_path} does not exist.")
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    except IOError as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise IOError(f"Error reading file {file_path}: {e}")
    return iocs

def save_results_to_json(results: List[dict], output_dir: str = OUTPUT_DIR):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"action_results_{timestamp}.json")

    try:
        with open(output_file, 'w') as file:
            json.dump({"results": results}, file, indent=4)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Error saving results to {output_file}: {e}")
        raise IOError(f"Error saving results to {output_file}: {e}")

def main(api_key, input_file):
    try:
        # Initialize VirusTotal API client
        vt_client = VirusTotalV3(api_key)

        # Load IOCs from input file
        iocs = load_iocs_from_file(input_file)
        if not iocs:
            logger.warning("No IOCs to process. Exiting.")
            return

        # Analyze the IOCs
        results = vt_client.analyze_iocs(iocs)

        # Save the results to a JSON file
        save_results_to_json(results)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        raise

if __name__ == "__main__":
    # Use argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description='VirusTotal Analyzer')
    parser.add_argument('--api_key', required=False, help='Your VirusTotal API key')
    parser.add_argument('--input_file', required=False, help='Path to the input file containing IOCs')

    args = parser.parse_args()

    # Use environment variables if no command-line arguments are provided
    api_key = args.api_key if args.api_key else os.getenv('API_KEY')
    input_file = args.input_file if args.input_file else os.getenv('INPUT_IOCS_FILE_PATH')

    # Check if both values are provided
    if not api_key or not input_file:
        logger.error("Error: API key and input file path must be provided either through command-line arguments or .env file.")
        raise ValueError("API key and input file path must be provided either through command-line arguments or .env file.")
    else:
        main(api_key, input_file)
