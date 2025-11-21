import os
import glob
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
# ASSUMPTION: Your file is named 'logpoint.py' and is in the python path
# You might need to adjust this import based on your folder structure
from logpoint import Logpoint 

def test_real_rules():
    # Path to where GitHub Actions will clone the rules
    rules_path = "sigma_rules/rules/windows/process_creation"
    
    print(f"--- 1. Loading Rules from {rules_path} ---")
    
    # We use a glob to find yaml files. 
    # Process Creation is best because it often contains CommandLine (Regex) logic
    rule_files = glob.glob(f"{rules_path}/*.yml")
    
    if not rule_files:
        raise FileNotFoundError("No rules found! Did the git checkout work?")

    print(f"Found {len(rule_files)} rules.")

    # Instantiate your modified backend
    # We use processing_pipeline=None to test raw syntax conversion first.
    # If you have a specific pipeline definition in your repo, import and pass it here.
    backend = Logpoint(processing_pipeline=None) 

    success = 0
    errors = 0
    
    # Counters for your new features
    json_logic_triggered = 0
    regex_logic_triggered = 0

    print("--- 2. Starting Conversion ---")
    
    for rule_file in rule_files:
        try:
            collection = SigmaCollection.from_yaml(open(rule_file, 'r', encoding='utf-8').read())
            
            # The conversion returns a list of queries
            queries = backend.convert(collection)
            
            for q in queries:
                # Check if your specific new logic was used in the output
                if 'modifiedproperties' in q.lower() and '*' in q:
                    json_logic_triggered += 1
                if 'process regex(' in q:
                    regex_logic_triggered += 1
            
            success += 1
            
        except Exception as e:
            # We print the error but don't stop the test, to see how many pass total
            # print(f"Failed: {rule_file} -> {e}")
            errors += 1

    print("\n--- 3. Results ---")
    print(f"Total Rules Attempted: {len(rule_files)}")
    print(f"Successful Conversions: {success}")
    print(f"Failed Conversions:     {errors}")
    print("-" * 30)
    print(f"Rules utilizing your JSON logic:  {json_logic_triggered}")
    print(f"Rules utilizing your Regex logic: {regex_logic_triggered}")

    # Fail the CI if too many errors occur (e.g., more than 10%)
    if errors > (len(rule_files) * 0.1):
        exit(1)

if __name__ == "__main__":
    test_real_rules()
