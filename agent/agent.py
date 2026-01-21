# Defines the BigQuery Operations Agent, its instructions, tools, and app integration.
import os
import google.auth
from google.adk.agents import Agent
from google.adk.apps import App
from google.auth.transport.requests import Request

from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin

from . import operational_tools
from . import auth_plugin
from . import context
import agent
from .mcp_fallback_tool import execute_sql_via_mcp

# 1. Get Credentials & Ensure Token is Valid
# We must use quota_project_id for BigQuery API calls to work correctly with user credentials
# and ensure we have the correct scopes for the MCP server.
SCOPES = [
    "https://www.googleapis.com/auth/bigquery"
]
credentials, _ = google.auth.default(scopes=SCOPES, quota_project_id=agent.QUOTA_PROJECT_ID)
if not credentials.token:
    credentials.refresh(Request())

# --- Agent Definition ---
bq_ops_agent = Agent(
    name=agent.AGENT_NAME, 
    model=agent.AGENT_MODEL,
    description="An agent that answers operational questions about BigQuery.",
    instruction=(
        "You are an expert BigQuery Operations assistant. Your goal is to help users "
        "optimize BigQuery costs, performance, and security."
        "\n\n"
        "**STYLE GUIDELINES (CRITICAL):**\n"
        "1.  **BE CONCISE:** Users are busy engineers. Give direct answers. Avoid fluff, lengthy intros, or generic advice.\n"
        "2.  **SUMMARIZE:** Do not dump full tables of data. Highlight the top 3-5 findings and provide a summary stat (e.g., 'Total potential savings: $500').\n"
        "3.  **ACTION-ORIENTED:** Focus on what the user needs to *do* (e.g., 'Partition table X', 'Revoke access for user Y').\n"
        "4.  **SHOW IDs:** When analyzing specific queries (e.g., heavy queries, anti-patterns), **ALWAYS** include the `job_id` so the user can debug it.\n"
        "\n"
        "**CORE INSTRUCTIONS:**\n"
        "1.  **Use Tools:** ALWAYS check if a tool exists for the user's question before trying to write your own SQL. "
        "    * **FULL ANALYSIS / OVERALL SUGGESTIONS:** If the user asks for an 'analysis of the environment', 'overall suggestions', or a 'scan', "
        "      **YOU MUST USE `perform_full_environment_scan`**. This tool runs multiple checks and generates a dashboard image.\n"
        "    * Cost/Usage? Use `get_expensive_queries`, `identify_large_unpartitioned_tables`, `forecast_monthly_costs`. \n"
        "    * Optimization? Use `get_partition_cluster_recommendations` or `get_materialized_view_recommendations` to see Google's official advice. \n"
        "    * Hidden Costs? Use `get_top_time_travel_consumers` to find storage waste. \n"
        "    * Security? Use `get_iam_policy_recommendations` to see official security warnings, `check_table_permissions`, or `find_publicly_exposed_datasets`. \n"
        "    * Performance? Use `get_common_query_errors`, `check_slot_capacity_saturation`. \n"
        "    * **GCP Billing & Invoices?** Use `execute_sql_via_mcp` to query the Standard Billing Export table: "
        f"       `{agent.BILLING_PROJECT_ID}.{agent.BILLING_DATASET_ID}.{agent.BILLING_TABLE_ID}`. "
        "       Focus on `cost`, `usage_start_time`, `service.description`, `sku.description`. \n"
        "    * Ad-hoc SQL? If NO specific tool matches, you may use `execute_sql_via_mcp` "
        f"       to query `{agent.TARGET_PROJECT_ID}.{agent.TARGET_REGION}.INFORMATION_SCHEMA` directly.\n\n"
        "2.  **Analyze Tool Output:** When a tool returns data, summarize findings. \n"
        "    * If using `forecast_monthly_costs`, explain that this is a linear projection based on recent activity.\n\n"
        "3.  **Handling Images (CRITICAL):**\n"
        "    * The `perform_full_environment_scan` tool returns a Base64 image in the variable `dashboard_image_base64`.\n"
        "    * **DO NOT** output this Base64 string in your response. It is too long and will break the application.\n"
        "    * Instead, simply provide your text summary and append this exact tag at the end: `[DASHBOARD_GENERATED]`.\n"
        "    * The User Interface will automatically detect the image from the tool output and render it.\n\n"
        "4.  **Charts & Visualizations (Vega-Lite):**\n"
        "    If the user asks for a 'chart', 'plot', or 'visual' (and it is NOT a full scan), you must:\n"
        "    * First, provide a text summary.\n"
        "    * Second, generate a complete **Vega-Lite JSON specification** representing the data.\n"
        "    * **Format:** `[VEGA] ...valid json spec... [/VEGA]`\n"
        "    * **Crucial:** You MUST embed the actual data inside the `data: { values: [...] }` field of the spec. Do not use URL references.\n"
        "    * Use the 'dark' theme or suitable colors for a dark UI.\n"
        "\n"
        "5.  **Follow-up Questions (MANDATORY FINAL STEP):**\n"
        "    * **AFTER** your text summary, image tags, or charts, you **MUST** output 3 relevant follow-up questions.\n"
        "    * **Format:** `[FOLLOW_UP][\"Question 1\", \"Question 2\", \"Question 3\"][/FOLLOW_UP]`\n"
        "    * **Example:** `[FOLLOW_UP][\"Show me the most expensive query\", \"Check for public datasets\", \"Forecast next month's cost\"][/FOLLOW_UP]`\n"
        "    * **Constraint:** Valid JSON list ONLY inside tags. NO markdown formatting, NO newlines. This must be the very last thing you generate.\n"
    ),
    tools=[
        # The generic SQL tool (fallback)
        execute_sql_via_mcp,
        # The specific "Playbook" tools
        operational_tools.get_expensive_queries_by_slot_hours,
        operational_tools.identify_large_unpartitioned_tables,
        operational_tools.analyze_storage_compression_model,
        operational_tools.find_unused_tables,
        operational_tools.check_table_permissions,
        operational_tools.find_publicly_exposed_datasets,
        operational_tools.get_recent_table_users,
        operational_tools.get_common_query_errors,
        operational_tools.get_hourly_slot_consumption,
        operational_tools.get_most_frequently_queried_tables,
        operational_tools.check_slot_capacity_saturation,
        operational_tools.suggest_partitioning_keys,
        operational_tools.analyze_recent_queries_for_antipatterns,
        operational_tools.get_top_time_travel_consumers,
        operational_tools.forecast_monthly_costs,
        # BQ Recommendation Engine Tools
        operational_tools.get_partition_cluster_recommendations,
        operational_tools.get_materialized_view_recommendations,
        operational_tools.get_iam_policy_recommendations,
        # Slot Detective Tools
        operational_tools.get_slow_queries,
        operational_tools.analyze_data_skew,
        # Comprehensive Scanner
        operational_tools.perform_full_environment_scan
    ]
)

# --- App & Plugin Integration ---
plugins_list = [auth_plugin.AuthPlugin()]

if agent.ENABLE_ADK_LOGGING: ## <- this is disabling/enabling ADK logging based on config
    bq_logging_plugin = BigQueryAgentAnalyticsPlugin(
        project_id=agent.LOGGING_PROJECT_ID,
        dataset_id=agent.LOGGING_DATASET_ID,
        table_id=agent.LOGGING_TABLE_ID
    )
    plugins_list.append(bq_logging_plugin)

app = App(
    name="agent",
    root_agent=bq_ops_agent,
    plugins=plugins_list
)

root_agent = bq_ops_agent