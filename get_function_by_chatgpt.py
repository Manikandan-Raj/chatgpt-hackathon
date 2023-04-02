import openai
import json
import pandas as pd
import requests
import json
import yaml
import subprocess

openai.api_key = "<OPENAI_KEY>"


def get_details_about_exploitable(package, version, cve):
    messages = [
        {"role": "user", "content": """
         This {package} is affected on this {version} and the cve id is {cve}. Tell whether this is explotable by web request. Say yes or no. Please don't provide explanation
         """.format(package=package, version=version, cve=cve)}
    ]
    response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages = messages,
            temperature = 0
    )
    return response

def get_affected_function_details_from_completion(cve, package_name, package_version, question):
    prompt ="""
    I am a helpful assistant to assist developer to write code. If I know the answer, I will give the extact information.
    But if I don't know or unsure about the answer, I will reply back with text "Sorry I don't know".
    
    Q: what is package name affected by this CVE:  {cve}
    A: The Affected package name is {package_name}
    
    Q: what is version number of the package: {package_name}
    A: The affected version is {package_version}
    
    Q: {question}
    A: 
    """.format(cve=cve, package_name=package_name, package_version=package_version, question=question)
    response = openai.Completion.create(
            model="text-davinci-003",
            prompt = prompt,
            max_tokens = 1000,
            temperature = 0
    )
    return response

def update_dashboard(repo, package_name, version, cve, severity, function_details, present="No", response_on_exploitable="N/A"):
    

    url = "<URL>"

    payload = json.dumps({
    "repo": repo,
    "package_name": package_name,
    "version": version,
    "cve": cve,
    "severity": severity,
    "function": function_details,
    "present": present,
    "exploitable": response_on_exploitable
    })
    headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)


def parse_response_to_get_function(response_on_function_details):
    if "I don't know." in response_on_function_details and response_on_function_details != "":
        return None
    else:
        response_on_function_details = response_on_function_details.strip()
        return response_on_function_details

def run_semgrep(filename, repo_name):
    try:
        semgrep_op = subprocess.run(["semgrep","--config",filename,repo_name +"/", "--quiet"],capture_output=True)
        if semgrep_op.stdout and semgrep_op.returncode == 0: 
            data = semgrep_op.stdout
            str_data = str(data, 'UTF-8')

            if str_data != "":
                return "Yes"
            else:
                return "No"
        return "No"
    except Exception as e:
        return "No"


def write_semgrep_rule_pattern(package_name, package_version, cve, methods):
    data = {}
    prepare_data = {}
    prepare_data["id"] = cve
    prepare_data["message"] = "Found the affected method by this CVE"
    prepare_data["severity"] = "WARNING"
    prepare_data["languages"] = ["python"]
    prepare_data["metadata"]= {}
    prepare_data["metadata"]["references"] = ["Package name is "+ package_name , "Affected package version is "+ package_version]
    
    patterns = []
    for item in methods.split(","):
        patterns.append({"pattern" : package_name+"."+item})
    
    prepare_data["pattern-either"] = patterns

    data["rules"]= [prepare_data]
    
    file=open(cve+".yaml","w")
    yaml.dump(data,file)
    file.close()

def write_semgrep_rule_pattern_java(package_name, package_version, cve, methods, classname):
    data = {}
    prepare_data = {}
    prepare_data["id"] = cve
    prepare_data["message"] = "Found the affected method by this CVE"
    prepare_data["severity"] = "WARNING"
    prepare_data["languages"] = ["java"]
    prepare_data["metadata"]= {}
    prepare_data["metadata"]["references"] = ["Package name is "+ package_name , "Affected package version is "+ package_version]
    
    patterns = []
    for item in methods.split(","):
        patterns.append({"pattern" : "("+classname + " $L)."+item})
    
    prepare_data["pattern-either"] = patterns

    data["rules"]= [prepare_data]
    
    file=open(cve+".yaml","w")
    yaml.dump(data,file)
    file.close()
          
      
def main():
    
    with open("input_to_chatgpt.json", "r") as f:
        cve_details = json.load(f)
    repos = []
    ecosystems = []
    severities = []
    fixed_versions = []
    cves= []
    package_names = []
    package_versions = []
    affected_methods = []
    
    count = 0
    for item in cve_details:
        affected_pack_details = cve_details[item]
        
        try:
            for pkg in affected_pack_details:
                cve = pkg["cve"]
                package_name = pkg["package_name"]
                package_version = pkg["version"]
                
                repo = pkg["repo"]
                ecosystem = pkg["ecosystem"]
                severity = pkg["severity"]
                fixed_version = pkg["fixed_version"]
                methods = "N/A"
                is_present = "No"
                classname = None
                exploitable = "N/A"
                
                print("Calling the Chat GPT to get the affected method details on this CVE: "+ cve + ", package: "+ package_name + " , version: "+ package_version)
                question = 'Give me list of affected methods in that package in json format with key "methods"'
                if ecosystem == "maven":
                    question = 'Give me list of affected methods along with the class name in that package in json format with key "methods" and "class"'
                function_details = get_affected_function_details_from_completion(cve, package_name, package_version, question)
                response_on_function_details = ""
                for item in function_details["choices"]:
                    function_message = item["text"]
                    response_on_function_details += function_message
                
                result = parse_response_to_get_function(response_on_function_details)
                if result is not None:
                    result_json = json.loads(result)
                    
                    methods = "(...),".join(result_json["methods"] if "methods" in result_json else [])
                    methods = methods + "(...)"
                    if ecosystem == "maven":
                        classname = result_json["class"] if "class" in result_json else package_name
                    
                    print("Affected methods on this cve - "+ cve + " and method details are " + methods)

                    if ecosystem == "pip":
                        write_semgrep_rule_pattern(package_name, package_version, cve, methods)
                        is_present  = run_semgrep(cve+".yaml",repo)
                    
                    if ecosystem == "maven":
                        write_semgrep_rule_pattern_java(package_name, package_version, cve, methods, classname)
                        is_present  = run_semgrep(cve+".yaml",repo)
                    
                    
                    
                    exploitable_details = get_details_about_exploitable(package_name, package_version, cve)
                    exploitable = ""
                    for item in exploitable_details["choices"]:
                        function_message = item["message"]["content"]
                        exploitable += function_message
                        
                update_dashboard(repo, package_name, package_version, cve, severity, methods.replace(",", "\n"), is_present, exploitable)
                repos.append(repo)
                package_names.append(package_name)
                package_versions.append(package_version)
                cves.append(cve)
                ecosystems.append(ecosystem)
                severities.append(severity)
                fixed_versions.append(fixed_version)
                affected_methods.append(methods)
                
                count += 1
                    
        except Exception as e:
            print("Exception while getting affected methods details in chat GPT: " + str(e))
            break
    
    
    
    dependabot_cve_data = {
                    "Repo": repos,
                    "Package Name": package_names,
                    "Ecosystem": ecosystems,
                    "CVE": cves,
                    "Severity" : severities,
                    "Versions" : package_versions,
                    "Fixed Versions" : fixed_versions,
                    "Methods" : affected_methods
                    }
    dep_data = pd.DataFrame(dependabot_cve_data)
    dep_data.to_csv("cve-with-method-details.csv", index=False)
    print("CSV file creation is done")

                
                    