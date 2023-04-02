import pandas as pd
import json
import math

def main():
    df = pd.read_csv("cve-details.csv")
    repos = df["Repo"]
    packages = df["Package Name"]
    ecosystems = df["Ecosystem"]
    cves = df["CVE"]
    severities = df["Severity"]
    versions = df["Versions"]
    fixed_versions = df["Fixed Versions"]

    final_data = {}

    def extract_data(json_data_list, repo, package_name, ecosystem, severity, version, fixed_version):
        is_new_addition = True
        for json_data in json_data_list:
            
            ex_package_name = json_data["package_name"]
            ex_ecosystem = json_data["ecosystem"]
            ex_severity = json_data["severity"]
            ex_version = json_data["version"]
        
            if package_name == ex_package_name and \
                ecosystem == ex_ecosystem and \
                    severity == ex_severity and \
                        version == ex_version:
                            print("Found duplicate - No action"+ repo + "," + package_name + "," + version)
                            is_new_addition = False
                            break
        if is_new_addition:
            final_data[cve].append({
                    "repo" : repo,
                    "package_name" : package_name,
                    "ecosystem" : ecosystem,
                    "cve" : cve,
                    "severity" : severity,
                    "version" : version,
                    "fixed_version" : fixed_version
                })
        
        # return package_name, ecosystem, severity, version, fixed_version
        
    for index in range(0,len(repos)):
        cve = cves[index]
        if type(cve) is not float:
            repo = repos[index]
            package_name =  packages[index]
            ecosystem = ecosystems[index]
            severity = severities[index]
            version = versions[index]
            fixed_version = fixed_versions[index]
            
            if cve not in final_data:
                final_data[cve] =[{
                    "repo" : repo,
                    "package_name" : package_name,
                    "ecosystem" : ecosystem,
                    "cve" : cve,
                    "severity" : severity,
                    "version" : version,
                    "fixed_version" : fixed_version
                }]
            else:
                existing_data = final_data[cve]
                extract_data(existing_data, repo, package_name,ecosystem, severity, version, fixed_version)
                
            
    with open("input_to_chatgpt.json", "w") as fd:
        json.dump(final_data, fd)
        

    
    

