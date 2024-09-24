#!/bin/bash
set -e

# Run s3download.py
python s3download.py

# Run illumio_to_lr.py
python illumio_to_lr.py