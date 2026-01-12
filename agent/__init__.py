# Loads environment variables and defines configuration constants for the agent.
import os
from dotenv import load_dotenv

# Load environment variables from .env file inside the agent directory
# We look for .env in the same directory as this __init__.py file
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)

# --- Logging Configuration ---
# Where the agent logs its own activities and analytics
# Set to '1' or 'true' to enable logging
ENABLE_ADK_LOGGING = os.getenv("ENABLE_ADK_LOGGING", "0").lower() in ("1", "true") #1 - ADK logging on, 0 - ADK logging off (default)

LOGGING_PROJECT_ID = os.getenv("LOGGING_PROJECT_ID", "")
LOGGING_DATASET_ID = os.getenv("LOGGING_DATASET_ID", "adk_logs")
LOGGING_TABLE_ID = os.getenv("LOGGING_TABLE_ID", "agent_events")

# --- Target Environment ---
# The project and region the agent queries against for answers
TARGET_PROJECT_ID = os.getenv("TARGET_PROJECT_ID", "")

# The project used for billing/quota (Vertex AI, API limits). Defaults to TARGET_PROJECT_ID.
QUOTA_PROJECT_ID = os.getenv("QUOTA_PROJECT_ID", TARGET_PROJECT_ID)

if ENABLE_ADK_LOGGING and not LOGGING_PROJECT_ID:
    LOGGING_PROJECT_ID = TARGET_PROJECT_ID

# Set Google Cloud Quota Project explicitly for libraries that check this env var
os.environ["GOOGLE_CLOUD_QUOTA_PROJECT"] = QUOTA_PROJECT_ID
# CRITICAL: Force GOOGLE_CLOUD_PROJECT to ensure Vertex AI calls use the correct project
# instead of defaulting to the environment's project (e.g., cloudtop-vn).
if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
    os.environ["GOOGLE_CLOUD_PROJECT"] = QUOTA_PROJECT_ID

TARGET_REGION = os.getenv("TARGET_REGION", "")

# --- Billing Data Configuration ---
# Project and Dataset containing the Standard Cloud Billing Export
BILLING_PROJECT_ID = os.getenv("BILLING_PROJECT_ID", "")
BILLING_DATASET_ID = os.getenv("BILLING_DATASET_ID", "")
BILLING_TABLE_ID = os.getenv("BILLING_TABLE_ID", "")

# --- Agent Settings ---
AGENT_NAME = os.getenv("AGENT_NAME", "")
# Updated to a stable available model version
AGENT_MODEL = os.getenv("AGENT_MODEL", "")

# --- Image Generation Settings ---
IMAGE_GENERATION_MODEL = os.getenv("IMAGE_GENERATION_MODEL", "")
