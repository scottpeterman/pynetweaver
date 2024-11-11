import os
import json
from ttp import ttp

class SimplifiedTTPEngine:
    def __init__(self, folder_path):
        """
        Initialize the engine and load all .ttp templates from the folder structure.
        :param folder_path: Path to the folder containing .ttp template files, organized in subfolders by group.
        """
        self.templates = {}
        self.folderpath = folder_path
        self.load_templates()

    def load_templates(self):
        folder_path = self.folderpath
        for root, dirs, files in os.walk(folder_path):
            group = os.path.basename(root)
            if group not in self.templates:
                self.templates[group] = {}

            # Load each .ttp file in the folder
            for file_name in files:
                if file_name.endswith(".ttp"):
                    template_path = os.path.join(root, file_name)
                    with open(template_path, 'r') as file:
                        template_content = file.read()
                    self.templates[group][file_name] = template_content
                    print(f"Loaded template: {group}/{file_name}")  # Debug print

    def find_best_template(self, mac_output):
        best_template = None
        best_parsed_output = None
        best_score = 0

        # Iterate over the loaded templates for the mac_table group
        for group_name, templates in self.templates.items():
            if True:
                for template_name, template_content in templates.items():
                    fidelity, num_records, parsed_result = self.test_template_against_output(template_content,
                                                                                                   mac_output)

                    # Calculate score (fidelity + num_records) and only choose the best
                    score = fidelity + num_records
                    if score > best_score and parsed_result:  # Ensure parsed result is not empty
                        best_score = score
                        best_template = template_name
                        best_parsed_output = parsed_result

        return best_template, best_parsed_output, best_score
    def flatten_list(self, nested_list):
        """
        Recursively flattens a nested list.
        :param nested_list: A possibly nested list of dictionaries or lists.
        :return: A flattened list.
        """
        if isinstance(nested_list, list):
            flat_list = []
            for item in nested_list:
                flat_list.extend(self.flatten_list(item))
            return flat_list
        else:
            return [nested_list]  # Base case: item is not a list

    def test_template_against_output(self, template_content, input_text):
        """
        Test the input_text against a given template, returning fidelity, number of records, and parsed result.
        :param template_content: The content of the TTP template.
        :param input_text: The raw input data (e.g., SSH output) to be parsed.
        :return: fidelity (key count in the first record), number of records parsed, and the parsed result.
        """
        try:
            parser = ttp(data=input_text, template=template_content)
            parser.parse()
            results = parser.result(format='json')[0]
            results = json.loads(results)

            # Flatten the results in case of nested lists
            flat_results = self.flatten_list(results)

            # Calculate fidelity and number of records
            if isinstance(flat_results, list) and len(flat_results) > 0:
                first_record = flat_results[0] if isinstance(flat_results[0], dict) else {}
                fidelity = len(first_record.keys()) if isinstance(first_record, dict) else 0
                num_records = len(flat_results)
                return fidelity, num_records, flat_results
            return 0, 0, []
        except Exception as e:
            print(f"Error parsing with template: {e}")
            return 0, 0, []


# Example usage of SimplifiedTTPEngine
if __name__ == "__main__":
    # Path to the folder containing template groups
    folder_path = "./templates"

    # Example input text (replace with your actual SSH or log output)
    input_text = """
    hostname: Router1
    ip: 192.168.1.1
    model: Cisco2900
    """

    # Initialize the TTP engine and load templates
    ttp_engine = SimplifiedTTPEngine(folder_path)

    # Optionally restrict search to a group, e.g., "mac_tables"
    best_template, parsed_content = ttp_engine.find_best_template(input_text, group="mac_tables")

    # Display the results
    if best_template:
        print(f"\nBest Template: {best_template}")
        print("Parsed Content:", json.dumps(parsed_content, indent=2))
    else:
        print("No matching template found.")
