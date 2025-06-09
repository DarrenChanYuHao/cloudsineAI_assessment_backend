FROM python:3.12.4-slim
LABEL authors="darrenchanyuhao"

RUN apt-get update && apt-get install -y \
    curl unzip groff less && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" && \
    unzip /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/aws /tmp/awscliv2.zip

WORKDIR /app

# Install libraries using uv
RUN pip install uv
COPY pyproject.toml uv.lock ./
RUN uv pip install . --no-cache --system

# Copy all your code
COPY . .

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

EXPOSE 8000

ENV AWS_REGION=ap-southeast-1
ENTRYPOINT ["./docker-entrypoint.sh"]