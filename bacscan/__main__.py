# -*- coding: utf-8 -*-
"""Permet `python -m bacscan ...` (equivalent de la commande `bacscan`)."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
