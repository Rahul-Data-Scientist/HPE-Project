import pandas as pd
import numpy as np
import ast

def normalize_data(df):
    # Create a copy to avoid modifying original dataframe
    df = df.copy()
    
    def safe_get(col, default=None):
        return df[col] if col in df.columns else pd.Series([default]*len(df), index=df.index)

    # vuln_id: Use CVE ID if present else scanner-specific ID else None
    cve_series = safe_get('identifiers.CVE', None)
    id_series = safe_get('id', None)
    # Extract first CVE if multiple
    def extract_first_cve(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return None
        try:
            parsed = ast.literal_eval(val) if isinstance(val,str) and val.startswith('[') else val
            if isinstance(parsed, list) and parsed:
                return parsed[0]
            elif isinstance(parsed,str):
                return parsed
            else:
                return None
        except Exception:
            return val
    vuln_id = cve_series.apply(extract_first_cve)
    vuln_id = vuln_id.where(vuln_id.notnull(), id_series)
    vuln_id = vuln_id.where(vuln_id.notnull(), None)

    # severity_raw: uppercase if present
    severity_raw = safe_get('severity', '').astype(str).str.upper().replace('NONE', None)

    # affected_asset: IP or hostname - not in sample, check 'from' column or 'host' variants
    affected_asset = None
    # Try 'from' column, extract host/ip if possible
    if 'from' in df.columns:
        # 'from' often contains package paths, so no valid host, set None
        affected_asset = pd.Series([None]*len(df), index=df.index)
    else:
        affected_asset = pd.Series([None]*len(df), index=df.index)

    # component: package or software name, try 'packageName', fallback 'name', fallback 'moduleName'
    component = safe_get('packageName', None)
    component = component.where(component.notnull(), safe_get('name', None))
    component = component.where(component.notnull(), safe_get('moduleName', None))
    component = component.where(component.notnull(), None)

    # affected_version: use 'version'
    affected_version = safe_get('version', None)

    # cvss_score: use 'cvssScore' or try extract from 'CVSSv3' string
    cvss_score = safe_get('cvssScore', None).astype(float)
    # If cvss_score missing, try parsing CVSSv3 string for base score
    def parse_cvss_score(cvss_str):
        if not isinstance(cvss_str, str):
            return None
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
        # Score is not embedded in this string, so we can't extract
        return None
    cvss_score = cvss_score.fillna( cvss_score )

    # epss_score: 'epssDetails.probability' or 'epssDetails' or None
    epss_score = None
    if 'epssDetails.probability' in df.columns:
        epss_score = safe_get('epssDetails.probability', np.nan).astype(float)
    elif 'epssDetails' in df.columns:
        epss_score = safe_get('epssDetails', np.nan).astype(float)
    else:
        epss_score = pd.Series([np.nan]*len(df), index=df.index)

    # exposure_score: default None
    exposure_score = pd.Series([None]*len(df), index=df.index)

    # fix_available: True if 'fixedIn' or 'fix_version' column has value or 'isUpgradable'
    fixed_in = safe_get('fixedIn', None)
    is_upgradable = safe_get('isUpgradable', False)
    # Consider fixedIn a list string - check if empty
    def is_fix_avail(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return False
        try:
            lst = ast.literal_eval(val) if isinstance(val,str) and val.startswith('[') else val
            if isinstance(lst, list):
                return len(lst) > 0
            elif val:
                return True
            else:
                return False
        except Exception:
            # fallback
            return bool(val)
    fix_available = fixed_in.apply(is_fix_avail) if fixed_in is not None else pd.Series([False]*len(df), index=df.index)
    fix_available = fix_available | is_upgradable.astype(bool)

    # cvss_vector: from 'CVSSv3' or 'cvssDetails' first element
    cvss_vector = pd.Series([None]*len(df), index=df.index)
    if 'CVSSv3' in df.columns:
        cvss_vector = safe_get('CVSSv3', None).astype(str).replace('nan', None)
    elif 'cvssDetails' in df.columns:
        def extract_vector(cvssdetails):
            if not isinstance(cvssdetails, str):
                return None
            try:
                lst = ast.literal_eval(cvssdetails) if cvssdetails.startswith('[') else [cvssdetails]
                if lst and isinstance(lst, list) and 'cvssV3Vector' in lst[0]:
                    return lst[0]['cvssV3Vector']
                elif lst and isinstance(lst, list) and isinstance(lst[0], str):
                    return lst[0]
                return None
            except Exception:
                return None
        cvss_vector = safe_get('cvssDetails', None).apply(extract_vector)
    
    # cwe_id: from 'identifiers.CWE' or None
    cwe_id_raw = safe_get('identifiers.CWE', None)
    def extract_first_cwe(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return None
        try:
            parsed = ast.literal_eval(val) if isinstance(val,str) and val.startswith('[') else val
            if isinstance(parsed, list) and parsed:
                return parsed[0]
            elif isinstance(parsed,str):
                return parsed
            else:
                return None
        except Exception:
            return val
    cwe_id = cwe_id_raw.apply(extract_first_cwe)

    # exploit_exists: True if 'exploit' column has True value or non-empty string, else False
    exploit_col = safe_get('exploit', '')
    def bool_exploit(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return False
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            val_stripped = val.strip().lower()
            if val_stripped in ['true', 'yes', 'y', 'proof of concept', 'poc']:
                return True
            elif val_stripped in ['', 'false', 'no', 'n', 'none']:
                return False
            else:
                return True
        return bool(val)
    exploit_exists = exploit_col.apply(bool_exploit).astype(bool)

    # exploit_count: from 'exploitDetails.sources' (list length), else 0
    exploit_sources = safe_get('exploitDetails.sources', None)
    def count_exploits(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return 0
        try:
            # val may be list string
            if isinstance(val,str):
                val = ast.literal_eval(val) if val.startswith('[') else val
            if isinstance(val, list):
                return len(val)
            return 1
        except Exception:
            return 1
    exploit_count = exploit_sources.apply(count_exploits).astype(int)

    # fix_version: first entry of 'fixedIn' or safe_get('fix_version') else None
    fix_ver_raw = safe_get('fixedIn', None)
    def extract_first_fix(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return None
        try:
            parsed = ast.literal_eval(val) if isinstance(val,str) and val.startswith('[') else val
            if isinstance(parsed, list) and parsed:
                return parsed[0]
            elif isinstance(parsed,str):
                return parsed
            else:
                return None
        except Exception:
            return val
    fix_version = fix_ver_raw.apply(extract_first_fix)

    # description: use available description or None
    description = safe_get('description', None).astype(object).replace({np.nan: None})

    # references: from 'references', normalize to list of strings
    refs_raw = safe_get('references', None)
    
    def normalize_refs(val):
        if val is None or (isinstance(val,float) and np.isnan(val)):
            return []
        try:
            if isinstance(val,str):
                # Try parse as list of dicts
                if val.strip().startswith('['):
                    parsed = ast.literal_eval(val)
                    if isinstance(parsed, list):
                        urls = []
                        for item in parsed:
                            if isinstance(item, dict) and 'url' in item:
                                urls.append(str(item['url']))
                            elif isinstance(item, str):
                                urls.append(item)
                        return urls
                # If string with commas or newlines
                if ',' in val or '\n' in val:
                    # split
                    parts = [x.strip() for x in val.replace('\n', ',').split(',') if x.strip()]
                    return parts
                # else single string
                return [val.strip()]
            elif isinstance(val, list):
                # list of strings or dicts
                urls = []
                for item in val:
                    if isinstance(item, dict) and 'url' in item:
                        urls.append(str(item['url']))
                    elif isinstance(item, str):
                        urls.append(item)
                return urls
            else:
                return []
        except Exception:
            # fallback treat as string
            try:
                return [str(val)]
            except:
                return []
    references = refs_raw.apply(normalize_refs)

    # Construct final dataframe
    out_df = pd.DataFrame({
        'vuln_id': vuln_id,
        'severity_raw': severity_raw,
        'affected_asset': affected_asset if isinstance(affected_asset, pd.Series) else pd.Series([None]*len(df), index=df.index),
        'component': component,
        'affected_version': affected_version,
        'cvss_score': cvss_score.astype(float).where(cvss_score.notnull(), None),
        'epss_score': epss_score.astype(float).where(epss_score.notnull(), None),
        'exposure_score': exposure_score,
        'fix_available': fix_available.astype(bool),
        'cvss_vector': cvss_vector.where(cvss_vector.notnull(), None),
        'cwe_id': cwe_id.where(cwe_id.notnull(), None),
        'exploit_exists': exploit_exists.astype(bool),
        'exploit_count': exploit_count.astype(int),
        'fix_version': fix_version.where(fix_version.notnull(), None),
        'description': description.where(description.notnull(), None),
        'references': references
    }, index=df.index)

    # Ensure correct types and replace NaNs
    bool_cols = ['fix_available', 'exploit_exists']
    for col in bool_cols:
        out_df[col] = out_df[col].fillna(False).astype(bool)

    out_df['exploit_count'] = out_df['exploit_count'].fillna(0).astype(int)

    # Replace NaNs with None for others
    for col in ['vuln_id', 'severity_raw', 'affected_asset', 'component', 'affected_version', 'cvss_vector', 'cwe_id', 'fix_version', 'description']:
        out_df[col] = out_df[col].where(out_df[col].notnull(), None)

    for col in ['cvss_score', 'epss_score', 'exposure_score']:
        out_df[col] = out_df[col].astype(float)

    # references must be list:
    out_df['references'] = out_df['references'].apply(lambda x: x if isinstance(x, list) else ([] if x is None else [x]))

    return out_df