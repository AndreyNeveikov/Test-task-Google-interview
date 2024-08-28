import os
from unittest.mock import patch, mock_open
import pytest
from dotenv import load_dotenv
from virustotal_analyzer import VirusTotalV3, load_iocs_from_file, save_results_to_json


load_dotenv()

@pytest.fixture
def api_key():
    return os.getenv('API_KEY')

def test_get_headers(api_key):
    vt = VirusTotalV3(api_key=api_key)
    headers = vt.get_headers()
    assert headers == {"x-apikey": api_key}

def test_query_ip(api_key):
    vt = VirusTotalV3(api_key=api_key)
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {'data': 'mocked response'}
        mock_get.return_value.status_code = 200
        response = vt.query_ip("8.8.8.8")
        assert response == {'data': 'mocked response'}
        mock_get.assert_called_once_with(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": api_key}
        )

def test_query_url(api_key):
    vt = VirusTotalV3(api_key=api_key)
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {'data': 'mocked response'}
        mock_get.return_value.status_code = 200
        response = vt.query_url("http://www.example.com")
        assert response == {'data': 'mocked response'}
        encoded_url = vt._encode_url("http://www.example.com")
        mock_get.assert_called_once_with(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers={"x-apikey": api_key}
        )

def test_encode_url():
    vt = VirusTotalV3(api_key="dummy")
    encoded = vt._encode_url("http://www.example.com")
    assert encoded == "aHR0cDovL3d3dy5leGFtcGxlLmNvbQ"

def test_is_ip():
    vt = VirusTotalV3(api_key="dummy")
    assert vt._is_ip("192.168.1.1") is True
    assert vt._is_ip("www.example.com") is False

def test_is_malicious():
    vt = VirusTotalV3(api_key="dummy")
    mock_result = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1}
            }
        }
    }
    assert vt._is_malicious(mock_result) is True

    mock_result['data']['attributes']['last_analysis_stats']['malicious'] = 0
    assert vt._is_malicious(mock_result) is False

def test_analyze_iocs():
    vt = VirusTotalV3(api_key="dummy")
    with patch.object(vt, 'query_ip') as mock_query_ip:
        mock_query_ip.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_date": 1622505600,
                    "last_analysis_stats": {"malicious": 1}
                }
            }
        }
        results = vt.analyze_iocs(["192.168.1.1"])
        assert len(results) == 1
        assert results[0]["IsMalicious"] is True
        assert results[0]["Type"] == "IP_ADDRESS"

def test_load_iocs_from_file():
    mock_file_data = "8.8.8.8\nmaliciouswebsite.com\n"
    with patch("builtins.open", mock_open(read_data=mock_file_data)):
        iocs = load_iocs_from_file("mock_input_file.txt")
        assert iocs == ["8.8.8.8", "maliciouswebsite.com"]

def test_load_iocs_from_file_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_iocs_from_file("non_existent_file.txt")


def test_save_results_to_json():
    results = [{"Identifier": "8.8.8.8", "Type": "IP_ADDRESS", "LastAnalysisTime": "2024-08-28 05:47:08",
                "IsMalicious": False}]
    with patch("builtins.open", mock_open()) as mock_file:
        with patch("os.makedirs") as mock_makedirs:  # Mock os.makedirs to avoid creating directories
            save_results_to_json(results, output_dir="../mock_results_dir")

            # Check if os.makedirs was called with the correct directory
            mock_makedirs.assert_called_once_with("../mock_results_dir", exist_ok=True)

            # Check if open was called with a file path ending in .json and write mode
            mock_file.assert_called_once()
            assert mock_file.call_args[0][0].startswith("../mock_results_dir")
            assert mock_file.call_args[0][0].endswith(".json")
            assert 'w' in mock_file.call_args[0][1]

            handle = mock_file()
            handle.write.assert_any_call('{')  # Ensure that the write method is called with the beginning of JSON data
            handle.write.assert_any_call('}')  # Ensure that the write method is called with the end of JSON data


def test_save_results_to_json_io_error():
    results = [{"Identifier": "8.8.8.8", "Type": "IP_ADDRESS", "LastAnalysisTime": "2024-08-28 05:47:08",
                "IsMalicious": False}]
    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = IOError("Unable to write to file")
        with pytest.raises(IOError):
            save_results_to_json(results, output_dir="../mock_results_dir")