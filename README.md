# GenAI Virus and Malware Scanner Backend

This repository contains the backend code for the GenAI Virus and Malware Scanner project as part of cloudsineAI take home assessment.

It is written in Python using FastAPI and provides routes to scan files, handle the uploads and also GenAI analysis capabilities.

## Getting Started

### Prerequisites

- Tested with Python 3.12

### Installation

Clone the repository:

```bash
  git clone
````

Create a virtual environment and activate it:

```bash
  python -m venv venv
  source venv/bin/activate  # or `venv\Scripts\activate` on Windows
```

Install dependencies:

```bash
    pip install uv
    uv pip install .
```
### Environment Variables

These are the required API keys that you will need to set up in a `.env` file yourself:

```dotenv
VIRUSTOTAL_API_KEY=
GEMINI_API_KEY=
```

### Running the Application

For development, run:

```bash
    uvicorn run app.main:app --reload
```

For production, run:
```bash
    uvicorn run app.main:app
```

### Architecture & Folder Structure

```
/Backend
  /.github                    – GitHub Actions workflows (contains the deployment.yml file)
  /nginx                      – Nginx configuration file for reverse proxy
  /routes                     – API endpoints
      /scan                   – File scanning endpoints (contains the controller and service)
        /DTO                  – Data Transfer Objects for request/response validation
      /genai                  – GenAI analysis endpoints (contains the controller and service)
  .Dockerfile                 – For containerization deployment on EC2
  .docker-entrypoint.sh       - For getting env variables from AWS SSM Parameter Store
  .main.py                    – Starting point for the application
```

### Deployment

1. Set up an EC2 instance with Docker and Nginx installed.

2. Set up AWS SSM Parameter Store with the required environment variables.

3. Set up GitHub Actions secrets for `EC2_SSH_KEY`, `EC2_USER` and `EC2_HOST`. The EC2_USER should your distro (e.g., `ubuntu` for Ubuntu). The EC2_HOST should be the public IP.

4. Push your changes to master branch, it will then trigger the GitHub Actions workflow to deploy the application.

P.S For first deployment, it may fail due to missing SSL certificates. Remove the HTTPs Server block in the Nginx configuration file and redeploy.
You can then set up the SSL certificate. You can do this by:

1. Setting up a domain name and pointing it to the EC2 instance public IP.
2. I used Certbot and Let's Encrypt for the SSL certificate.
3. Once that is done, it should automatically update the Nginx conf. file, if not, you can manually upadte it back.

Thank you!
