import json
import os
import PacketSniffer
from typing import Dict


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


def create_memory_dir() -> None:
    """create dir called app_memory to store the caches and maybe more in the future"""
    if not os.path.exists("app_memory"):
        os.mkdir("app_memory")


class Memory:
    def __init__(self):
        self.global_dns_cache: Dict[str, str] = load_dictionary_from_json("app_memory/global_DNS_cache.json")
        self.local_dns_cache: Dict[str, str] = load_dictionary_from_json("app_memory/local_DNS_cache.json")
        self.check_ssid_delete_cache()
        create_memory_dir()

    def delete_local_cache(self) -> None:
        with open("app_memory/local_DNS_cache.json", 'w') as file:
            json.dump({}, file)
        self.local_dns_cache.clear()

    def delete_global_cache(self) -> None:
        with open("app_memory/global_DNS_cache.json", 'w') as file:
            json.dump({}, file)
        self.global_dns_cache.clear()

    def save_dns_memory(self):
        save_dictionary_to_json(self.global_dns_cache, "app_memory/global_DNS_cache.json")
        save_dictionary_to_json(self.local_dns_cache, "app_memory/local_DNS_cache.json")

    def check_ssid_delete_cache(self) -> None:
        current_network = PacketSniffer.get_current_ssid()
        if "SSID" not in self.local_dns_cache:
            self.local_dns_cache["SSID"] = current_network
        if not self.local_dns_cache["SSID"] == current_network:
            self.delete_local_cache()
            self.local_dns_cache["SSID"] = current_network
