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


**Automated:** The `setup_gcp.sh` script will handle this for you.

**Manual:** Run the following command:
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

### 4. Logging Dataset (Optional but Recommended)
The agent logs analytics to a BigQuery dataset (default: `adk_logs`). If the dataset does not exist, the agent will attempt to create the table, but the dataset itself must usually exist.

To manually create the dataset:
```bash
# Replace 'adk_logs' if you customized LOGGING_DATASET_ID in .env
bq mk --dataset --location=US adk_logs
```


## Authentication

**OAuth 2.0 Integration**: This agent uses OAuth 2.0 to authenticate the actual user.

The **Frontend UI** requires environment variables to handle the OAuth flow. You can set these via the setup script or manually (see *Configuration* below).

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


#### Option A: Manual Configuration
If you prefer to configure everything manually, you can set the environment variables directly in your shell or create a `.env` file.

**1. Enable APIs Manually:**
```bash
gcloud services enable bigquery.googleapis.com \
                       aiplatform.googleapis.com \
                       recommender.googleapis.com \
                       cloudresourcemanager.googleapis.com
```

**2. Set Credentials:**
You can either export these variables in your shell OR save them in a `.env` file (the app supports both).

```bash
# Backend Configuration
export TARGET_PROJECT_ID="your-project-id"
export TARGET_REGION="us-central1"
export QUOTA_PROJECT_ID="your-project-id"

# Frontend OAuth Configuration (Required for UI)
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export OAUTH_SCOPES="openid email profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/bigquery"
export OPENID_PROVIDER_URL="https://accounts.google.com"
```

#### Option B: Automated Setup
You can use the included helper script to automatically enable APIs, configure your project, and interactively set up your `.env` file:

```bash
./setup_gcp.sh
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
# Ensure you have set your OAuth credentials in the .env file or directly in environment variables
python gradio_bqops.py
```

- Open `http://localhost:7860`
- Click **"Sign in with Google"** to authenticate.

## Troubleshooting

-   **"UserWarning: Your application has authenticated using end user credentials..."**
    -   **Fix**: Ensure `QUOTA_PROJECT_ID` is set in your `.env` file or environment. This tells Google libraries which project to bill for API calls.


