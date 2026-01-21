# BigQuery Operations Agent

A GenAI-powered BigQuery Operations Agent built with the **Google Agent Development Kit (ADK)**. Leverages **Gemini**, **OAuth 2.0** for user authentication, and **BigQuery MCP** to help optimize costs, enhance security, and improve performance through a natural language interface.

This project includes a backend agent server and a Gradio-based frontend.

## Features

### Cost Optimization
- **Storage Analysis**: Compare **Logical vs. Physical** billing models to find immediate savings (Compression Analysis).
- **Waste Detection**: Identify **Unused Tables** (inactive for >180 days) and excessive **Time Travel** storage usage.
- **Forecasting**: Project monthly costs based on recent slot usage and storage trends.
- **Expensive Queries**: Pinpoint top queries by slot consumption.

### Performance Tuning
- **Anti-Pattern Detection**: Scans recent queries for performance killers (e.g., `SELECT *`, `UNION` vs `UNION ALL`, `ORDER BY` without `LIMIT`, cross joins).
- **Partitioning & Clustering**: Suggests partitioning keys for large tables and surfaces Google Cloud recommendations.
- **Capacity Planning**: Monitors slot capacity saturation, concurrency, and job wait times (detects queuing vs. saturation).
- **Materialized Views**: Identifies opportunities to accelerate queries with materialized views.

### Security & Governance
- **Exposure Scanning**: Detects **Publicly Exposed Datasets** (allUsers/allAuthenticatedUsers).
- **IAM Forensics**: Audit who is querying specific tables and check active IAM policy recommendations.
- **Permission Check**: Quickly verify who has `SELECT` access to sensitive tables.

### Interactive UI & Reporting
- **Visual Dashboards**: Generates high-level infographic dashboards summarizing your environment.
- **Interactive Charts**: Dynamic Vega-Lite charts for cost and performance metrics (Maximize/Restore view).
- **Data Export**: Download underlying chart data as **CSV**.
- **PDF Reporting**: Generate comprehensive **PDF Session Reports** containing executive summaries, embedded charts, and actionable data tables.

## Available Tools & Example Prompts

Here are some of the powerful tools available in the agent, along with complex example prompts to help you get started:

### 🔍 Full Environment Analysis
- **Tool**: `perform_full_environment_scan`
- **What it does**: Runs comprehensive checks across Cost, Security, and Performance layers.
- **Example Prompt**: *"🚀 Perform a full environment scan for Cost, Security, and Performance."*

### 💰 Cost Optimization
- **Tools**: `forecast_monthly_costs`, `get_expensive_queries`, `identify_large_unpartitioned_tables`, `analyze_storage_compression_model`
- **Example Prompt**: *"Forecast our monthly costs based on recent usage trends and identify tables with high Time Travel costs vs. total size."*
- **Example Prompt**: *"Which tables should switch to physical storage billing for cost savings? Analyze our storage compression model."*

### ⚡ Performance & Slots
- **Tools**: `check_slot_capacity_saturation`, `get_hourly_slot_consumption`, `get_slow_queries`, `analyze_data_skew` (Slot Detective)
- **Example Prompt**: *"Check for slot capacity saturation and list the top slow queries from the last 7 days."*
- **Example Prompt**: *"Show me a visualization of our hourly slot consumption and analyze recent slow queries for data skew."*

### 🛡️ Security & Governance
- **Tools**: `find_publicly_exposed_datasets`, `check_table_permissions`, `get_iam_policy_recommendations`
- **Example Prompt**: *"Scan for publicly exposed datasets and identify any risky IAM policy recommendations."*

### 🏗️ Infrastructure
- **Tools**: `suggest_partitioning_keys`, `get_partition_cluster_recommendations`
- **Example Prompt**: *"Find unpartitioned large tables and suggest partitioning keys based on recent query patterns."*

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
To enable logging, set `ENABLE_ADK_LOGGING="1"` in your `agent/.env` file. By default ADK logging is disabled.

### 5. OAuth 2.0 Setup (Required)
The agent uses OAuth 2.0 to authenticate users. You must create valid credentials in the Google Cloud Console.

1.  **Configure Consent Screen**:
    -   Go to **APIs & Services > OAuth consent screen**.
    -   Select **External** (or Internal if you have a Workspace).
    -   Fill in required fields (App name, User support email, Developer contact information).
    -   Add the following **Scopes**:
        -   `openid`
        -   `https://www.googleapis.com/auth/userinfo.email`
        -   `https://www.googleapis.com/auth/userinfo.profile`
        -   `https://www.googleapis.com/auth/bigquery`
    -   Add your email as a **Test User** (if External).

2.  **Create Credentials**:
    -   Go to **APIs & Services > Credentials**.
    -   Click **Create Credentials > OAuth client ID**.
    -   **Application type**: Web application.
    -   **Name**: `BigQuery Ops Agent` (or similar).
    -   **Authorized redirect URIs**: `http://localhost:7860/login/callback`
    -   Click **Create** & copy **Client ID** and **Client Secret**
    -   These will be used in the `Configuration` step.


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
You can either export these variables in your shell OR save them in the appropriate `.env` files.

**Backend Configuration (`agent/.env`):**
Contains GCP Project settings, Model config, and Logging settings.

**Frontend Configuration (`ui/.env`):**
Contains OAuth credentials and Server URL.

```bash
# Backend Configuration
export TARGET_PROJECT_ID="your-project-id"
export TARGET_REGION="US" # BigQuery Data/information schema Region (e.g. US, EU, or us-central1)
export GOOGLE_CLOUD_LOCATION="us-central1" # Vertex AI Compute Region (must be specific, e.g. us-central1)
export QUOTA_PROJECT_ID="your-project-id"

# Frontend OAuth Configuration (Required for UI)
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export OAUTH_SCOPES="openid email profile https://www.googleapis.com/auth/bigquery"
export OPENID_PROVIDER_URL="https://accounts.google.com"
```

#### Option B: Automated Setup
You can use the included helper script to automatically enable APIs, configure your project, and interactively set up your `.env` files (both `agent/.env` and `ui/.env`):

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
# Ensure you have set your OAuth credentials in the ui/.env file or directly in environment variables
python ui/gradio_bqops.py
```

- Open `http://localhost:7860`
- Click **"Sign in with Google"** to authenticate.

## Troubleshooting

-   **"UserWarning: Your application has authenticated using end user credentials..."**
    -   **Fix**: Ensure `QUOTA_PROJECT_ID` is set in your `agent/.env` file or environment. This tells Google libraries which project to bill for API calls.


## Disclaimer

**IMPORTANT: Community-Managed Project**

This is a community-managed agent for BigQuery Operations and is not an officially supported Google product. It uses Generative AI, which can produce incorrect results or "hallucinate".

-   **Verify Results**: Always manually verify critical findings (e.g., cost forecasts, security warnings) before taking action.
-   **No Liability**: The developers and contributors bear no responsibility for any consequences resulting from the use of this tool.
