# BigQuery Operations Agent

A GenAI-powered BigQuery Operations Agent built with the **Google Agent Development Kit (ADK)**. Leverages **Gemini**, **OAuth 2.0** for user authentication, and **BigQuery MCP** to help optimize costs, enhance security, and improve performance through a natural language interface.

This project includes a backend agent server and a Gradio-based frontend.

## Features

- **Cost Analysis**: Forecast costs, find expensive queries, identify time travel waste.
- **Security Scanning**: Check for public datasets, IAM recommendations.
- **Performance Tuning**: Analyze slot consumption, query errors, partition recommendations.
- **Visual Dashboard**: Generates comprehensive environment dashboards.

## Prerequisites & GCP Setup (One-Time)

Before running the agent, ensure your Google Cloud environment is ready.

### 1. Enable Required APIs
Run the following command in your Cloud Shell or ensure these APIs are enabled in the Console:
```bash
gcloud services enable bigquery.googleapis.com \
                       aiplatform.googleapis.com \
                       recommender.googleapis.com \
                       cloudresourcemanager.googleapis.com
```

### 2. IAM Roles
Ensure the user running the agent (or the Service Account (not recommended)) has the following roles:
- **BigQuery Job User**: To run queries.
- **BigQuery Data Viewer**: To read metadata.
- **Vertex AI User**: For the generative model (GenAI).
- **Recommender Viewer**: To access Google's official recommendations.

### 3. Verification
- Ensure you have a valid **Quota Project** set up (usually your main working project) to avoid authentication warnings.

## Authentication

**OAuth 2.0 Integration**: This agent uses OAuth 2.0 to authenticate the actual user.
The **Frontend UI** requires the following environment variables to handle the OAuth flow:

```bash
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export OAUTH_SCOPES="openid email profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/bigquery"
export OPENID_PROVIDER_URL="https://accounts.google.com"
```

## Installation

### 1. Environment Setup
Create a virtual environment and install dependencies.

```bash
# Create and activate venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory (or set env vars) with the following details:

```ini
# Backend Configuration
TARGET_PROJECT_ID=your-project-id
TARGET_REGION=us-central1
QUOTA_PROJECT_ID=your-project-id  # Required to fix "UserWarning: quota_project_id"

# Frontend OAuth Configuration
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
```

## Running the Application

### 1. Start the Backend Agent Server

```bash
source venv/bin/activate
adk api_server . --reload
```
*Wait for the server to start (usually on port 8000).*

### 2. Start the Frontend UI

```bash
source venv/bin/activate
# Ensure OAuth vars are exported if not in .env
export OAUTH_CLIENT_ID=""
export OAUTH_CLIENT_SECRET=""
export OAUTH_SCOPES="openid email profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/bigquery"
export OPENID_PROVIDER_URL="https://accounts.google.com"
python gradio_bqops.py
```

- Open `http://localhost:7860`
- Click **"Sign in with Google"** to authenticate.

## Troubleshooting

-   **"UserWarning: Your application has authenticated using end user credentials..."**
    -   **Fix**: Ensure `QUOTA_PROJECT_ID` is set in your `.env` file or environment. This tells Google libraries which project to bill for API calls.


