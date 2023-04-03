# chatgpt-hackathon

# Install
1. Install dependencies - Run pip install -r requiremnts.txt
2. Run prepare_cve_data.py 

# Configuration Setup:

1. Add Open API Key in get_function_by_chatgpt.py
2. Update url and Token in prepare_cve_data.py (this is to interact with github to get dependabot alerts)
3. active_repos.json -- mention all the repo under your org

# Assumption:

1. Install semgrep tool
2. Clone the repo where you are expecting to find vulnerable function usage


# What this will do?

1. Collect all dependabot details (open issues) for the specified repo
2. Extract cve, package, version and eco system details
3. Make a call to chat gpt to get what function and class is really vulnerable
4. Write a semgrep rule (right now, it supports python and java based rules). Lot more can be add here.
5. Scan the code base with created semgrep rule
6. If scan finds some findings, this are really vulnerable function and can be delayed this to udpate. Push to developer and get it updated to lastest version
7. To help step 6, it will ask chatgpt to check whether this is vulneable to web. If answer is Yes, then no doubt to upgrade this.
8. In the get_function_by_chatgpt.py, we have used only web app to show this data in table. But it can be anything.
