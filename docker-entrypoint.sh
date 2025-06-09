#!/bin/bash
set -e

echo "Fetching parameters from AWS SSM Parameter Store..."

rm -f .env

aws ssm get-parameters --names GEMINI_API_KEY VIRUSTOTAL_API_KEY --with-decryption \
  --query "Parameters[*].[Name,Value]" --output text | while read -r name value; do
    key=$(basename "$name")
    echo "$key=$value" >> .env
done

echo ".env file created:"
cat .env

exec uvicorn main:app --host 0.0.0.0 --port 8000