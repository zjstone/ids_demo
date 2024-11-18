import pytest
from pathlib import Path
import yaml

from ids.detectors.rule_engine import RuleEngine, Rule
from ids.models.packet_features import PacketFeatures 