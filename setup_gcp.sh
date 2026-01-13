#!/bin/bash

# setup_gcp.sh
# Automates GCP configuration and guides OAuth setup for BigQuery Ops Agent

ENV_FILE_FRONTEND="ui/.env"
ENV_FILE_BACKEND="agent/.env"
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

echo "${BOLD}BigQuery Ops Agent - GCP Setup Assistant${RESET}"
echo "============================================"

# 1. Project Detection
echo "[1/4] Detecting Google Cloud Project..."
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)

if [ -z "$CURRENT_PROJECT" ]; then
    echo "${YELLOW}No active gcloud project found.${RESET}"
    read -p "Enter your Google Cloud Project ID: " PROJECT_ID
else
    read -p "Use current project '${GREEN}$CURRENT_PROJECT${RESET}'? [Y/n]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
        read -p "Enter your Google Cloud Project ID: " PROJECT_ID
    else
        PROJECT_ID=$CURRENT_PROJECT
    fi
fi

echo "Setting active project to: $PROJECT_ID"
gcloud config set project "$PROJECT_ID"

# 2. Enable APIs
echo ""
echo "[2/4] Enabling Required APIs (this may take a minute)..."
gcloud services enable \
    bigquery.googleapis.com \
    aiplatform.googleapis.com \
    recommender.googleapis.com \
    cloudresourcemanager.googleapis.com

echo "${GREEN}APIs enabled successfully.${RESET}"

# 3. Region Configuration
echo ""
echo "[3/7] BigQuery Data Location"
echo "BigQuery Project Data Location (for Information Schema target config)."
echo "Examples: Enter 'US' or 'EU' for multi-region, or specific region like 'us-central1'."
read -p "Target Region (default: US): " REGION
REGION=${REGION:-US}
# Usually same as target project for simple setups
QUOTA_PROJECT_ID=$PROJECT_ID

# 4. Vertex AI Configuration
echo ""
echo "[4/7] Vertex AI Compute Region (for GenAI models)"
echo "Generative Models often require specific regions (like us-central1). Do not use multi-regions here."
read -p "Vertex AI Region (default: us-central1): " GOOGLE_CLOUD_LOCATION
GOOGLE_CLOUD_LOCATION=${GOOGLE_CLOUD_LOCATION:-us-central1}

# 4. OAuth Setup (Manual Step)
echo ""
echo "[5/7] OAuth 2.0 Configuration"
echo "${YELLOW}NOTE: Google requires you to manually create the OAuth Client credentials in the Console.${RESET}"
echo ""
echo "Please follow these steps:"
echo "1. Open this URL: ${BOLD}https://console.cloud.google.com/apis/credentials/oauthclient?project=$PROJECT_ID${RESET}"
echo "2. Application Type: ${BOLD}Web Application${RESET}"
echo "3. Name: ${BOLD}BigQuery Ops Agent${RESET}"
echo "4. Authorized Redirect URIs: ${BOLD}http://localhost:7860/login/callback${RESET}"
echo "5. Click 'Create' and copy the Client ID and Client Secret."
echo ""

read -p "Paste OAuth Client ID (leave empty if you want to export them seperately at run time): " OAUTH_CLIENT_ID
read -p "Paste OAuth Client Secret (leave empty if you want to export them seperately at run time): " OAUTH_CLIENT_SECRET

# 5. Billing Configuration
echo ""
echo "[6/7] Billing Configuration (Optional)"
echo "To enable cost analysis features, provide your Standard Cloud Billing Export table details."
echo "Press Enter to skip if not configured."
echo ""
read -p "Billing Project ID (default: $PROJECT_ID): " BILLING_PROJECT_ID
BILLING_PROJECT_ID=${BILLING_PROJECT_ID:-$PROJECT_ID}
read -p "Billing Dataset ID: " BILLING_DATASET_ID
read -p "Billing Table ID: " BILLING_TABLE_ID

# 6. Logging Configuration
echo ""
echo "[7/7] Logging Configuration (Optional)"
echo "The agent can log events and analytics to BigQuery."
read -p "Enable ADK Logging? [y/N]: " ENABLE_LOGGING_CONFIRM
if [[ "$ENABLE_LOGGING_CONFIRM" =~ ^[Yy]$ ]]; then
    ENABLE_ADK_LOGGING=1
    read -p "Logging Project ID (default: $PROJECT_ID): " LOGGING_PROJECT_ID
    LOGGING_PROJECT_ID=${LOGGING_PROJECT_ID:-$PROJECT_ID}
    read -p "Logging Dataset ID (default: adk_logs): " LOGGING_DATASET_ID
    LOGGING_DATASET_ID=${LOGGING_DATASET_ID:-adk_logs}
    read -p "Logging Table ID (default: agent_events): " LOGGING_TABLE_ID
    LOGGING_TABLE_ID=${LOGGING_TABLE_ID:-agent_events}
else
    ENABLE_ADK_LOGGING=0
    LOGGING_PROJECT_ID=""
    LOGGING_DATASET_ID="adk_logs"
    LOGGING_TABLE_ID="agent_events"
fi

# Write to .env (Frontend)
echo ""
echo "Writing configuration to $ENV_FILE_FRONTEND and $ENV_FILE_BACKEND..."

OAUTH_SCOPES="openid email profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/bigquery"
OPENID_PROVIDER_URL="https://accounts.google.com"

# Write Frontend Config
cat > $ENV_FILE_FRONTEND <<EOL
# --- OAuth Configuration (Frontend) ---
OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID
OAUTH_CLIENT_SECRET=$OAUTH_CLIENT_SECRET
OAUTH_SCOPES="$OAUTH_SCOPES"
OPENID_PROVIDER_URL="$OPENID_PROVIDER_URL"

# --- Server Config ---
ADK_SERVER_URL=http://127.0.0.1:8000
EOL

# Write Backend Config
# We append to existing agent/.env or create new, but better to preserve defaults if exists? 
# For simplicity, we will overwrite or append safe values. 
# Re-writing complete file is safer to ensure keys are there.

cat > $ENV_FILE_BACKEND <<EOL
GOOGLE_GENAI_USE_VERTEXAI=TRUE
# Region for Vertex AI Compute/GenAI (e.g. us-central1)
GOOGLE_CLOUD_LOCATION=$GOOGLE_CLOUD_LOCATION

# --- Logging Configuration ---
ENABLE_ADK_LOGGING=$ENABLE_ADK_LOGGING
LOGGING_PROJECT_ID=$LOGGING_PROJECT_ID
LOGGING_DATASET_ID=$LOGGING_DATASET_ID
LOGGING_TABLE_ID=$LOGGING_TABLE_ID

# --- Target Environment ---
TARGET_PROJECT_ID=$PROJECT_ID
QUOTA_PROJECT_ID=$QUOTA_PROJECT_ID
# BigQuery Data Region (e.g. US, EU, or us-central1)
TARGET_REGION=$REGION

# --- Billing Data Configuration ---
BILLING_PROJECT_ID=$BILLING_PROJECT_ID
BILLING_DATASET_ID=$BILLING_DATASET_ID
BILLING_TABLE_ID=$BILLING_TABLE_ID

# --- Agent Settings ---
AGENT_NAME=BigQuery_Operations_Agent
AGENT_MODEL=gemini-2.5-flash

# --- Image Generation Settings ---
IMAGE_GENERATION_MODEL=gemini-2.5-flash-image
EOL

echo ""
echo "${GREEN}Setup Complete!${RESET}" 
echo "Frontend config saved to $ENV_FILE_FRONTEND"
echo "Backend config saved to $ENV_FILE_BACKEND"
echo "You can now run the application:"
echo ""
echo "1. Start the Agent Server (Backend):"
echo "  ${BOLD}source venv/bin/activate${RESET}"
echo "  ${BOLD}adk api_server . --reload${RESET}"
echo ""
echo "2. Start the UI (Frontend) in a separate terminal:"
echo "  ${BOLD}source venv/bin/activate${RESET}"
echo "  ${BOLD}python ui/gradio_bqops.py${RESET}"
