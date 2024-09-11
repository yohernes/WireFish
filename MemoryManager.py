import json


def save_dictionary_to_json(dictionary, filename='cache.json'):
    """Save a dictionary to a JSON file."""
    with open(filename, 'w') as file:
        json.dump(dictionary, file, indent=4)  # indent for pretty printing


def load_dictionary_from_json(filename='cache.json'):
    """Load a dictionary from a JSON file."""
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}  # Return an empty dictionary if file does not exist
