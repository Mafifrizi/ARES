"""
ARES Cloud Base Module
Base class for cloud attack and recon modules.
"""
from __future__ import annotations

from typing import Any
from ares.modules.base import BaseModule


class BaseCloudModule(BaseModule):
    """Base class for all cloud reconnaissance and attack modules."""

    MODULE_CATEGORY = "cloud"
