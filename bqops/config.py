# Loads environment variables and defines configuration constants for the agent.
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Logging Configuration ---
# Where the agent logs its own activities and analytics
# Where the agent logs its own activities and analytics
# Set to '1' or 'true' to enable logging
ENABLE_ADK_LOGGING = os.getenv("ENABLE_ADK_LOGGING", "0").lower() in ("1", "true") #1 - ADK logging on, 0 - ADK logging off (default), see https://codelabs.developers.google.com/adk-bigquery-agent-analytics-plugin#6

LOGGING_PROJECT_ID = os.getenv("LOGGING_PROJECT_ID", "")
LOGGING_DATASET_ID = os.getenv("LOGGING_DATASET_ID", "adk_logs") #change or leave default
LOGGING_TABLE_ID = os.getenv("LOGGING_TABLE_ID", "agent_events") #change or leave default

if ENABLE_ADK_LOGGING and not LOGGING_PROJECT_ID:
    LOGGING_PROJECT_ID = TARGET_PROJECT_ID

# --- Target Environment ---
# The project and region the agent queries against for answers
TARGET_PROJECT_ID = os.getenv("TARGET_PROJECT_ID", "")
# The project used for billing/quota (Vertex AI, API limits). Defaults to TARGET_PROJECT_ID.
QUOTA_PROJECT_ID = os.getenv("QUOTA_PROJECT_ID", TARGET_PROJECT_ID)
os.environ["GOOGLE_CLOUD_QUOTA_PROJECT"] = QUOTA_PROJECT_ID

TARGET_REGION = os.getenv("TARGET_REGION", "region-us") #eg region-us

# --- Billing Data Configuration ---
# Project and Dataset containing the Standard Cloud Billing Export
BILLING_PROJECT_ID = os.getenv("BILLING_PROJECT_ID", "")
BILLING_DATASET_ID = os.getenv("BILLING_DATASET_ID", "")
BILLING_TABLE_ID = os.getenv("BILLING_TABLE_ID", "")

# --- Agent Settings ---
AGENT_NAME = os.getenv("AGENT_NAME", "BigQuery_Operations_Agent")
# Updated to a stable available model version
AGENT_MODEL = os.getenv("AGENT_MODEL", "gemini-2.5-flash")

# --- Image Generation Settings ---
# Model used for generating the dashboard images
IMAGE_GENERATION_MODEL = os.getenv("IMAGE_GENERATION_MODEL", "gemini-2.5-flash-image")
