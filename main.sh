#!/bin/bash
python3 support_classes/scheduled/main.py &
flask db upgrade && gunicorn wsgi:app