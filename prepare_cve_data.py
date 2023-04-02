import requests
import json
import pandas as pd
import preprocess_cves
import get_function_by_chatgpt
url = "https://api.github.com/repos/{org}/{repo}/dependabot/alerts?state=open&page="

payload={}
headers = {
  'Authorization': 'Bearer <TOKEN>',
  'X-GitHub-Api-Version': '2022-11-28',
  'Accept': 'application/vnd.github+json'
}

def process_dependency_alerts(repo, response):
    collected_dependency = []
    try:
        for item in response:
            if "dependency" in item:
                dependency = item["dependency"]
                if "package" in dependency:
                    package = dependency["package"]
                    if "name" in package:
                        package_name = package["name"]
                        ecosystem = package["ecosystem"] if "ecosystem" in package else "NA"
                        cve = "NA"
                        severity = "NA"
                        version = "NA"
                        fixed_version = "NA"
                        if "security_advisory" in item:
                            if "cve_id" in item["security_advisory"]:
                                cve = item["security_advisory"]["cve_id"]
                        if "security_vulnerability" in item:
                            if "severity" in item["security_vulnerability"]:
                                severity = item["security_vulnerability"]["severity"]
                                
                            if "vulnerable_version_range" in item["security_vulnerability"]:
                                version = item["security_vulnerability"]["vulnerable_version_range"]
                            
                            if "first_patched_version" in item["security_vulnerability"]:
                                first_patched_version = item["security_vulnerability"]["first_patched_version"]
                                if type(first_patched_version) is dict:
                                    fixed_version_details = {str(first_patched_version[index]) for index in first_patched_version}
                                    fixed_version = ",".join(list(fixed_version_details))
                        data = {}
                        data["repo"] = repo
                        data["package_name"] = package_name
                        data["ecosystem"] = ecosystem
                        data["cve"] = cve
                        data["severity"] = severity
                        data["version"] = version
                        data["fixed_version"] = fixed_version
                        collected_dependency.append(data)
    except Exception as e:
        print("Exception while collecting data "+ str(e))
        
    print("Length of the collected dependencies "+ str(len(collected_dependency)))
    return collected_dependency
                            
def prepare_csv_file(final_dependencies_list):
    try:
        repos = []
        package_names = []
        ecosystems = []
        cves = []
        severities = []
        versions = []
        fixed_versions = []
        
        for item in final_dependencies_list:
            repo = item["repo"]
            package_name = item["package_name"]
            ecosystem = item["ecosystem"]
            cve = item["cve"]
            severity = item["severity"]
            version = item["version"]
            fixed_version = item["fixed_version"]
            
            repos.append(repo)
            package_names.append(package_name)
            ecosystems.append(ecosystem)
            cves.append(cve)
            severities.append(severity)
            versions.append(version)
            fixed_versions.append(fixed_version)
        
        dependabot_cve_data = {
                    "Repo": repos,
                    "Package Name": package_names,
                    "Ecosystem": ecosystems,
                    "CVE": cves,
                    "Severity" : severities,
                    "Versions" : versions,
                    "Fixed Versions" : fixed_versions
                }
        dep_data = pd.DataFrame(dependabot_cve_data)
        dep_data.to_csv("cve-details.csv", index=False)
        print("CSV file creation is done")
    except Exception as e:
        print("Exception while genereting CSV File" + str(e))
    
final_dependencies_list = []                              
with open("active_repos.json", "r") as f:
    active_repos = json.load(f)
    repos_list = list(set(active_repos["active"]))
    
    repo_list = []
    for repo in repo_list:
        print("Start Processing repo .."+ repo)
        page = 1
        format_url = url.format(repo=repo) + str(page)
        
        response = requests.request("GET",format_url , headers=headers, data=payload)
        response = response.json()
        if type(response) is dict:
            print("Depedendabot is not enabled on this repo: "+ repo)
        
        print("Length of the dependencies list before processing for this repo: " + str(len(final_dependencies_list)))
        while(type(response) is list and len(response) > 0):
            
            depedencies_list = process_dependency_alerts(repo, response)
            final_dependencies_list.extend(depedencies_list)
            
            page += 1
            response = requests.request("GET", url+str(page), headers=headers, data=payload)
            response = response.json()
        
        print("Length of the dependencies list after processing for this repo: " + str(len(final_dependencies_list)))
        # break
                
            
print("######################### Total Number of Dependabot Alerts from the repo's  ##############################")
print("                                 " + str(len(final_dependencies_list)) + "                                ")
print("###########################################################################################################")

prepare_csv_file(final_dependencies_list)
preprocess_cves.main()

get_function_by_chatgpt.main()