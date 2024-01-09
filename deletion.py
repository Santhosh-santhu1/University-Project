import yara
import os

# Load YARA rule
rule_source = """
rule ExampleRule {
    strings:
        $magic_string = "Hello, World!"
    condition:
        $magic_string
}

"""
rules = yara.compile(source=rule_source)

# Specify the directory to scan
directory_to_scan = r'C:\Users\SANTHU\My PC (LAPTOP-7L8CSOJQ)\Downloads\project example'

# Iterate through files in the specified directory
for root, dirs, files in os.walk(directory_to_scan):
    for file_name in files:
        file_path = os.path.join(root, file_name)

        # Scan the file using YARA rules
        matches = rules.match(file_path)

        # If the file matches the YARA rule, attempt to delete it
        if matches:
            try:
                os.remove(file_path)
                print(f"File {file_path} deleted due to malware detection.")
            except Exception as e:
                print(f"Error deleting file {file_path}: {e}")
