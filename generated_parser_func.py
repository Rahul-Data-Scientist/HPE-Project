import pandas as pd

def flatten_vulnerabilities_to_df(scan_output):
    # According to metadata, vulnerabilities are nested at scan_output['Results'][*]['Vulnerabilities']
    if not isinstance(scan_output, dict):
        return pd.DataFrame()
    results = scan_output.get('Results', None)
    if not results or not isinstance(results, list):
        return pd.DataFrame()
    df_list = []
    for result in results:
        vulnerabilities = result.get('Vulnerabilities', None)
        if vulnerabilities and isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
            df = pd.json_normalize(vulnerabilities, sep='.')
            df_list.append(df)
    if df_list:
        return pd.concat(df_list, ignore_index=True)
    else:
        return pd.DataFrame()