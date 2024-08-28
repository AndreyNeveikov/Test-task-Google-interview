# VirusTotalV3 IOC Analyzer

The VirusTotalV3 IOC Analyzer is a Python script designed to use the VirusTotal API to analyze indicators of compromise (IOCs) such as IP addresses and URLs to determine if they are malicious. This script is ideal for security analysts and IT professionals who need to quickly assess potential threats.

## Prerequisites

- **Python Version**: 3.12
- **VirusTotal API Key**: You need an API key from VirusTotal. You can get one by signing up at the [VirusTotal website](https://www.virustotal.com/).

## Installation

You can install the VirusTotalV3 IOC Analyzer either by downloading the ZIP archive or by cloning the GitHub repository.

### Option 1: Download the ZIP Archive

1. **Extract the ZIP archive**:

   Download the ZIP archive of the project and extract it to your desired location on your computer.

2. **Set up a virtual environment (optional but recommended)**:

   Navigate to the extracted project directory and create a virtual environment to manage dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # On Windows use: .venv\Scripts\activate
   ```
   
3. **Install dependencies**:

   With the virtual environment activated, install the required dependencies from the requirements.txt file:

   ```bash
   pip install -r requirements.txt
   ```
   
### Option 2: Clone the GitHub Repository
Clone the repository:

Open your terminal and run the following command to clone the repository:

```bash
git clone https://github.com/AndreyNeveikov/Test-task-Google-interview.git
```

Navigate to the project directory:

```bash
cd Test-task-Google-interview
```

Set up a virtual environment (optional but recommended):

Create a virtual environment to manage dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows use: .venv\Scripts\activate
```

Install dependencies:

With the virtual environment activated, install the required dependencies from the requirements.txt file:

```bash
pip install -r requirements.txt
```

## Configuration

1. **API Key and Input File**:

   To use the script, you need to configure your API key and specify the path to your input file containing the IOCs.

2. **.env File**:

   Create a `.env` file in the root directory of the project and add the following lines with your specific details:

   ```plaintext
   API_KEY=your_virustotal_api_key
   INPUT_IOCS_FILE_PATH=path_to_your_input_file.txt
   OUTPUT_DIR=results
   ```

- Replace your_virustotal_api_key with your actual VirusTotal API key.
- Replace path_to_your_input_file.txt with the path to your input file containing the IOCs.
- Optionally, set OUTPUT_DIR to a different path if you do not want to use the default "results" directory for saving the output JSON files.

3. **Prepare the Input File**:

- Create an input file (e.g., input_iocs.txt) with a list of IOCs (IP addresses or URLs), one per line:

    ```plaintext
    8.8.8.8
    maliciouswebsite.com
    1.1.1.1
    suspicious-link.net
    ```

## Usage
Run the script using the command line:

```bash
python virustotal_analyzer.py
```
- By default, the script uses the API key and input file path specified in the .env file. 
- You can also override these values by providing them as command-line arguments:

```bash
python virustotal_analyzer.py --api_key "your_virustotal_api_key" --input_file "path_to_your_input_file.txt" --output_dir "custom_output_directory"
```

## Output
- The script generates a JSON file containing the analysis results of the IOCs.
- The output file is saved in the directory specified by the OUTPUT_DIR environment variable or the --output_dir command-line argument. If neither is set, it defaults to the "results" directory.
- The output file is named in the format action_results_YYYYMMDD_HHMMSS.json.

- Example content of the output JSON file:

```json
{
    "results": [
        {
            "Identifier": "8.8.8.8",
            "Type": "IP_ADDRESS",
            "LastAnalysisTime": "2024-08-28 05:47:08",
            "IsMalicious": false
        },
        {
            "Identifier": "maliciouswebsite.com",
            "Type": "URL",
            "LastAnalysisTime": "2024-07-15 15:14:08",
            "IsMalicious": false
        }
    ]
}
```

## Testing
All test files are located in the tests directory. To run the tests, use pytest:

```bash
pytest tests/
```
This command will discover and run all tests in the tests directory. 
Make sure to activate your virtual environment before running the tests.

## Troubleshooting
- Invalid API Key: Ensure your VirusTotal API key is correctly set in the .env file or passed via command-line arguments.
- Rate Limits: VirusTotal may impose rate limits on API requests. Check their API documentation for details on rate limits and upgrade options.

## Contributing
We welcome contributions to enhance the functionality of the VirusTotalV3 IOC Analyzer. To contribute:

- Make changes to the project.
- Ensure all tests pass.
- Share your changes with the project maintainer for review.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

### Key Points of the README:

- **Introduction**: Explains what the script does and who it's for.
- **Prerequisites**: Lists required tools and versions.
- **Installation**: Provides step-by-step instructions to set up the project.
- **Configuration**: Details how to set up the necessary environment variables and input files.
- **Usage**: Shows how to run the script with and without additional arguments.
- **Output**: Describes the output format and provides an example.
- **Testing**: Explains how to run the test suite.
- **Troubleshooting**: Provides tips for common issues.
- **Contributing**: Encourages community contributions and outlines the process.
- **License**: Specifies the licensing terms.

This `README.md` should give users a comprehensive guide on how to install, configure, and use your VirusTotalV3 IOC Analyzer.
