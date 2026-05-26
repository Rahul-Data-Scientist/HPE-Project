import pandas as pd

def flatten_vulnerabilities_to_df(scan_output):
    # Known entry point for vulnerabilities from metadata
    entry_points = ['Results']

    vulnerabilities_df_list = []

    # Defensive check: scan_output must be a dict
    if not isinstance(scan_output, dict):
        return pd.DataFrame()

    # process each detected entry point
    for entry in entry_points:
        if entry not in scan_output:
            continue
        groups = scan_output.get(entry, [])
        # Defensive: groups should be a list
        if not isinstance(groups, list) or len(groups) == 0:
            continue

        # Loop through each group (e.g., each element of Results)
        for group in groups:
            if not isinstance(group, dict):
                continue
            # Extract vulnerabilities list if present
            vulnerabilities = group.get('Vulnerabilities')
            if vulnerabilities is None:
                continue
            if not isinstance(vulnerabilities, list) or len(vulnerabilities) == 0:
                continue

            # Flatten vulnerabilities with pandas json_normalize
            df_vuln = pd.json_normalize(vulnerabilities, sep='.')
            if not df_vuln.empty:
                vulnerabilities_df_list.append(df_vuln)

    if vulnerabilities_df_list:
        return pd.concat(vulnerabilities_df_list, ignore_index=True)
    else:
        return pd.DataFrame()
