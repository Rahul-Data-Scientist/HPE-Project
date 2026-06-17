import pandas as pd

def flatten_vulnerabilities_to_df(scan_output):
    """
    Flatten vulnerability data in the scan_output dict into a pandas DataFrame.
    Uses metadata about detected_entry_points and schema_map to extract vulnerabilities.

    Returns an empty DataFrame if no vulnerability data found.
    """
    # According to metadata, vulnerability data is located in scan_output['Results'] which is a list.
    # Each result has 'Vulnerabilities' key containing list of vulnerability dicts.
    results = scan_output.get('Results')
    if not results or not isinstance(results, list):
        return pd.DataFrame()

    dfs = []
    for group in results:
        vulns = group.get('Vulnerabilities')
        if vulns and isinstance(vulns, list) and len(vulns) > 0:
            df = pd.json_normalize(vulns, sep='.')
            dfs.append(df)
    if dfs:
        return pd.concat(dfs, ignore_index=True)

    # If no vulnerabilities found in any groups, return empty df
    return pd.DataFrame()
