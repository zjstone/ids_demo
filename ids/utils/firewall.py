import logging
import iptc
from typing import Dict
import yaml
from pathlib import Path

class IPTablesHandler:
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.chain_name = self.config.get('chain_name', 'IDS_CHAIN')