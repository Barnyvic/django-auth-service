#!/bin/bash

set -e

echo "Installing dependencies..."
pip install --no-cache-dir -r requirements.txt

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Build completed successfully!"
