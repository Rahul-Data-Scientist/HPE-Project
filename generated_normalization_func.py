import pandas as pd
import numpy as np
import ast

def normalize_data(df):
    normalized_df = pd.DataFrame()

    def safe_literal_eval(s):
        try:
            if pd.isna(s) or not isinstance(s, str):
                return None
            return ast.literal_eval(s)
        except (ValueError, SyntaxError, Exception): # Catch any parsing errors
            return None

    # --- Pre-parse complex string columns once to avoid redundant operations ---
    df['parsed_relatedVulnerabilities'] = df.get('relatedVulnerabilities', pd.Series(dtype=object)).apply(safe_literal_eval)
    df['parsed_vulnerability_cvss'] = df.get('vulnerability.cvss', pd.Series(dtype=object)).apply(safe_literal_eval)
    df['parsed_vulnerability_urls'] = df.get('vulnerability.urls', pd.Series(dtype=object)).apply(safe_literal_eval)
    df['parsed_vulnerability_advisories'] = df.get('vulnerability.advisories', pd.Series(dtype=object)).apply(safe_literal_eval)


    # --- 1. vuln_id ---
    normalized_df['vuln_id'] = None # Default to None

    if 'vulnerability.id' in df.columns:
        def get_final_vuln_id(row):
            current_id = row['vulnerability.id']
            # Prioritize CVE from vulnerability.id if it exists and starts with 'CVE-'
            if pd.notna(current_id) and isinstance(current_id, str) and current_id.startswith('CVE-'):
                return current_id

            # Otherwise, look for a CVE in relatedVulnerabilities
            related_vulns = row['parsed_relatedVulnerabilities']
            if isinstance(related_vulns, list):
                for vuln in related_vulns:
                    if isinstance(vuln, dict) and 'id' in vuln and pd.notna(vuln['id']) and isinstance(vuln['id'], str) and vuln['id'].startswith('CVE-'):
                        return vuln['id']

            # If no CVE found, fallback to the original vulnerability.id (scanner-specific)
            return str(current_id) if pd.notna(current_id) else None
        
        normalized_df['vuln_id'] = df.apply(get_final_vuln_id, axis=1)
    
    # Ensure empty strings or NaN values are explicitly None
    normalized_df['vuln_id'] = normalized_df['vuln_id'].replace({np.nan: None, 'None': None, '': None})


    # --- 2. severity_raw ---
    if 'vulnerability.severity' in df.columns:
        normalized_df['severity_raw'] = df['vulnerability.severity'].astype(str).str.upper().replace({np.nan: 'UNKNOWN', 'NAN': 'UNKNOWN', '': 'UNKNOWN'})
    else:
        normalized_df['severity_raw'] = 'UNKNOWN'


    # --- 3. ip, hostname, port, instance_id (not present in input, initialize with None) ---
    normalized_df['ip'] = None
    normalized_df['hostname'] = None
    normalized_df['port'] = None
    normalized_df['instance_id'] = None


    # --- 4. component ---
    normalized_df['component'] = df.get('artifact.name', None)
    normalized_df['component'] = normalized_df['component'].replace({np.nan: None, '': None})


    # --- 5. affected_version ---
    normalized_df['affected_version'] = df.get('artifact.version', None)
    normalized_df['affected_version'] = normalized_df['affected_version'].replace({np.nan: None, '': None})


    # --- 6. cvss_score ---
    normalized_df['cvss_score'] = df['parsed_vulnerability_cvss'].apply(
        lambda x: float(x[0]['metrics']['baseScore']) if isinstance(x, list) and len(x) > 0 and isinstance(x[0], dict) and 'metrics' in x[0] and 'baseScore' in x[0]['metrics'] else np.nan
    )
    normalized_df['cvss_score'] = pd.to_numeric(normalized_df['cvss_score'], errors='coerce')


    # --- 7. cvss_vector ---
    normalized_df['cvss_vector'] = df['parsed_vulnerability_cvss'].apply(
        lambda x: str(x[0]['vector']) if isinstance(x, list) and len(x) > 0 and isinstance(x[0], dict) and 'vector' in x[0] else None
    )
    normalized_df['cvss_vector'] = normalized_df['cvss_vector'].replace({np.nan: None, '': None})


    # --- 8. description ---
    normalized_df['description'] = df.get('vulnerability.description', None)
    normalized_df['description'] = normalized_df['description'].replace({np.nan: None, '': None})


    # --- 9. references (MUST BE A LIST of strings) ---
    all_references_per_row = [[] for _ in range(len(df))]

    # Add vulnerability.urls
    for i, urls in enumerate(df['parsed_vulnerability_urls']):
        if isinstance(urls, list):
            all_references_per_row[i].extend([str(url).strip() for url in urls if pd.notna(url) and str(url).strip()])

    # Add vulnerability.dataSource
    if 'vulnerability.dataSource' in df.columns:
        for i, ds in enumerate(df['vulnerability.dataSource']):
            if pd.notna(ds) and isinstance(ds, str) and ds.strip():
                all_references_per_row[i].append(ds.strip())
    
    # Add vulnerability.advisories
    for i, advisories in enumerate(df['parsed_vulnerability_advisories']):
        if isinstance(advisories, list):
            all_references_per_row[i].extend([str(adv).strip() for adv in advisories if pd.notna(adv) and str(adv).strip()])

    # Add URLs from relatedVulnerabilities (nested dicts)
    for i, related_vulns in enumerate(df['parsed_relatedVulnerabilities']):
        if isinstance(related_vulns, list):
            for vuln in related_vulns:
                if isinstance(vuln, dict) and 'urls' in vuln and isinstance(vuln['urls'], list):
                    all_references_per_row[i].extend([str(url).strip() for url in vuln['urls'] if pd.notna(url) and str(url).strip()])

    # Deduplicate references for each row while preserving order (using dict.fromkeys)
    normalized_df['references'] = [list(dict.fromkeys(refs)) for refs in all_references_per_row]

    # --- Final cleanup of temporary columns from df ---
    df.drop(columns=[col for col in df.columns if col.startswith('parsed_')], errors='ignore', inplace=True)

    return normalized_df