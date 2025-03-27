import pandas as pd
import json

# Load JSON data with UTF-8 encoding
with open('nvdcve-1.1-2023.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

vulnerabilities = []
for item in data['CVE_Items']:
    cve_id = item['cve']['CVE_data_meta']['ID']
    description = item['cve']['description']['description_data'][0]['value']
    severity = item['impact']['baseMetricV2']['severity'] if 'baseMetricV2' in item['impact'] else 'UNKNOWN'
    cvss_score = item['impact']['baseMetricV2']['cvssV2']['baseScore'] if 'baseMetricV2' in item['impact'] else 0.0
    vulnerabilities.append({
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'cvss_score': cvss_score
    })

df = pd.DataFrame(vulnerabilities)
df.to_csv('nvd_data.csv', index=False, encoding='utf-8')