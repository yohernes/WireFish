import json
import os


def create_memory_dir() -> None:
    """create dir called app_memory to store the caches and maybe more in the future"""
    if not os.path.exists("app_memory"):
        os.mkdir("app_memory")


def save_dictionary_to_json(dictionary, filename: str) -> None:
    """Save a dictionary to a JSON file."""
    with open(filename, 'w') as file:
        json.dump(dictionary, file, indent=4)  # indent for pretty printing


def load_dictionary_from_json(filename: str) -> {}:
    """Load a dictionary from a JSON file."""
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}  # Return an empty dictionary if file does not exist
