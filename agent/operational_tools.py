# Contains the core operational tools for BigQuery analysis, including cost, security, and performance checks.
import google.auth
from google.cloud import bigquery
import re
from typing import List, Optional
import os
import base64
import io
import requests
import json
import agent
from . import context

# Vertex AI Imports for Image Generation
try:
    import vertexai

    # Import for Gemini models
    from vertexai.generative_models import GenerativeModel, GenerationConfig
    VERTEX_AI_AVAILABLE = True
except ImportError:
    VERTEX_AI_AVAILABLE = False

# PIL for Image Compression
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: PIL (Pillow) not installed. Images will not be compressed.")

# Initialize Client Helper
def get_client():
    credentials = context.get_credentials()
    # Enforce STRICT authentication. Do not fallback to ADC/Service Account.
    if not credentials:
        print("Error: No OAuth credentials found in context.")
        raise PermissionError("User is not authenticated. Please log in.")
    
    return bigquery.Client(project=agent.TARGET_PROJECT_ID, credentials=credentials)

# --- HELPER: Vertex AI Init with Region Fix ---
def _init_vertex_ai():
    if not VERTEX_AI_AVAILABLE:
        return False
    try:
        # Vertex AI Generative models often require specific regions (like us-central1),
        # not multi-regions (like region-us).
        location = agent.GOOGLE_CLOUD_LOCATION or agent.TARGET_REGION
        # Vertex AI Generative Models support a specific set of regions.
        # If the configured region is 'US', 'EU', or 'region-*', or empty, fallback to 'us-central1'.
        if not location or location.startswith("region-") or location in ["US", "EU"]:
            print(f"Warning: Region '{location}' may not be supported by Vertex AI GenAI. Defaulting to 'us-central1'.")
            location = "us-central1"
            
        vertexai.init(project=agent.QUOTA_PROJECT_ID, location=location)
        return True
    except Exception as e:
        print(f"Warning: Failed to initialize Vertex AI: {e}")
        return False

def _run_query(sql: str, query_params: Optional[List[bigquery.ScalarQueryParameter]] = None):
    """
    Helper to execute SQL and return results as a list of dicts.
    Supports parameterized queries for security.
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=query_params
    ) if query_params else None

    try:
        client = get_client()
        query_job = client.query(sql, job_config=job_config)
        results = query_job.result()
        return [dict(row) for row in results]
    except Exception as e:
        if isinstance(e, PermissionError) or "User is not authenticated" in str(e):
             raise
        return [{"error": f"Error executing query: {str(e)}"}]

def validate_table_id(table_id: str):
    """
    Basic format validation.
    """
    if not table_id:
        raise ValueError("Table ID cannot be empty.")
    if not re.match(r"^[a-zA-Z0-9_.-]+$", table_id):
        raise ValueError(f"Invalid table ID format: {table_id}")

def _parse_table_input(table_input: str):
    """
    Splits 'dataset.table' or returns 'table' and None for dataset.
    """
    parts = table_input.split('.')
    if len(parts) == 2:
        return parts[0], parts[1] # dataset, table
    return None, table_input # no dataset specified, just table

# --- COST TOOLS ---

def get_expensive_queries_by_slot_hours(days: int = 30):
    """Identifies the top 10 most expensive queries based on slot usage."""
    sql = f"""
        SELECT query, total_slot_ms / (1000 * 60 * 60) AS slot_hours
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        ORDER BY total_slot_ms DESC LIMIT 10
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

def get_top_time_travel_consumers():
    """
    Identifies tables where Time Travel storage is costing significant money.
    """
    sql = f"""
        SELECT 
            table_schema AS dataset,
            table_name,
            total_physical_bytes / (1024*1024*1024) AS total_gb,
            time_travel_physical_bytes / (1024*1024*1024) AS time_travel_gb,
            ROUND(SAFE_DIVIDE(time_travel_physical_bytes, total_physical_bytes) * 100, 2) AS time_travel_pct
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLE_STORAGE`
        WHERE time_travel_physical_bytes > 0
        ORDER BY time_travel_physical_bytes DESC
        LIMIT 20
    """
    return _run_query(sql)

def forecast_monthly_costs(days: int = 30):
    """
    Simple linear projection of costs based on USAGE (default: last 30 days).
    """
    sql = f"""
        WITH DailyUsage AS (
            SELECT 
                EXTRACT(DATE FROM creation_time) as usage_date,
                SUM(total_slot_ms) / (1000*60*60) as daily_slot_hours,
                SUM(total_bytes_billed) / (1024*1024*1024*1024) as daily_tb_billed
            FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
            WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
            GROUP BY 1
        )
        SELECT 
            ROUND(AVG(daily_slot_hours), 2) as avg_daily_slot_hours,
            ROUND(AVG(daily_tb_billed), 2) as avg_daily_tb_billed,
            ROUND(AVG(daily_slot_hours) * 30, 2) as forecasted_monthly_slot_hours,
            ROUND(AVG(daily_tb_billed) * 30, 2) as forecasted_monthly_tb_billed,
            'Projections based on last ' || CAST(@days AS STRING) || ' days average' as note
        FROM DailyUsage
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

def identify_large_unpartitioned_tables():
    """Finds tables that are large but do not have partitioning enabled."""
    sql = f"""
        SELECT t.table_schema, t.table_name, t.total_logical_bytes
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLE_STORAGE` AS t
        JOIN `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLES` AS tbl
        ON t.table_schema = tbl.table_schema AND t.table_name = tbl.table_name
        WHERE tbl.ddl NOT LIKE '%PARTITION BY%' AND t.total_logical_bytes > 0
        ORDER BY t.total_logical_bytes DESC LIMIT 20
    """
    return _run_query(sql)

# Pricing Constants (US Multi-region estimates)
LOGICAL_ACTIVE_PRICE = 0.02
LOGICAL_LONG_TERM_PRICE = 0.01
PHYSICAL_ACTIVE_PRICE = 0.04
PHYSICAL_LONG_TERM_PRICE = 0.02

def analyze_storage_compression_model():
    """
    Compares Logical vs. Physical storage costs and estimates savings.
    
    IMPORTANT: When presenting these results, you MUST:
    1. Mention that the savings are "indicative" and based on US Multi-region list prices.
    2. Explicitly state the "effective_compression_ratio" for each table.
    """
    sql = f"""
        WITH StorageData AS (
            SELECT 
                t.table_schema, 
                t.table_name,
                t.active_logical_bytes,
                t.long_term_logical_bytes,
                t.active_physical_bytes,
                t.long_term_physical_bytes,
                t.time_travel_physical_bytes,
                t.fail_safe_physical_bytes,
                t.total_logical_bytes,
                t.total_physical_bytes,
                s.option_value as billing_model
            FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLE_STORAGE` AS t
            LEFT JOIN `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.SCHEMATA_OPTIONS` AS s
            ON t.table_schema = s.schema_name AND s.option_name = 'storage_billing_model'
            WHERE t.total_physical_bytes > 0
        ),
        CostCalculation AS (
            SELECT
                *,
                -- Logical Cost Calculation
                ((active_logical_bytes / POW(1024, 3)) * {LOGICAL_ACTIVE_PRICE}) + 
                ((long_term_logical_bytes / POW(1024, 3)) * {LOGICAL_LONG_TERM_PRICE}) AS monthly_logical_cost_usd,
                
                -- Physical Cost Calculation (Time Travel & Fail Safe are usually charged at Active Physical rates)
                ((active_physical_bytes / POW(1024, 3)) * {PHYSICAL_ACTIVE_PRICE}) + 
                ((long_term_physical_bytes / POW(1024, 3)) * {PHYSICAL_LONG_TERM_PRICE}) +
                (((time_travel_physical_bytes + fail_safe_physical_bytes) / POW(1024, 3)) * {PHYSICAL_ACTIVE_PRICE}) AS monthly_physical_cost_model_usd
            FROM StorageData
        )
        SELECT 
            table_schema, 
            table_name,
            ROUND(SAFE_DIVIDE(total_logical_bytes, total_physical_bytes), 2) AS normal_compression_ratio,
            ROUND(SAFE_DIVIDE(total_logical_bytes, (total_physical_bytes + time_travel_physical_bytes + fail_safe_physical_bytes)), 2) AS effective_compression_ratio,
            ROUND(monthly_logical_cost_usd, 2) AS current_monthly_cost_usd,
            ROUND(monthly_physical_cost_model_usd, 2) AS estimated_physical_cost_usd,
            ROUND(monthly_logical_cost_usd - monthly_physical_cost_model_usd, 2) AS potential_savings_usd,
            'Savings are indicative (based on US Multi-region list prices)' AS pricing_note,
            total_logical_bytes,
            (total_physical_bytes + time_travel_physical_bytes + fail_safe_physical_bytes) AS total_physical_bytes_all_features
        FROM CostCalculation
        WHERE (billing_model = 'LOGICAL' OR billing_model IS NULL)
        ORDER BY potential_savings_usd DESC LIMIT 20
    """
    return _run_query(sql)

def find_unused_tables(days_inactive: int = 180):
    """Identifies tables that have not been queried in the last N days."""
    sql = f"""
        SELECT DISTINCT t.table_schema, t.table_name, t.total_logical_bytes
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLE_STORAGE` AS t
        WHERE NOT EXISTS (
          SELECT 1 FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT` AS j,
          UNNEST(j.referenced_tables) AS ref
          WHERE j.creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days_inactive DAY)
          AND ref.table_id = t.table_name AND ref.dataset_id = t.table_schema
        ) AND t.total_logical_bytes > 0 ORDER BY t.total_logical_bytes DESC LIMIT 50
    """
    params = [bigquery.ScalarQueryParameter("days_inactive", "INT64", days_inactive)]
    return _run_query(sql, params)

# --- GOVERNANCE TOOLS ---

def check_table_permissions(table_name: str):
    """
    Lists users (grantees) who have SELECT privileges on a specific table.
    """
    try:
        validate_table_id(table_name)
    except ValueError as e:
        return [{"error": str(e)}]

    dataset, table = _parse_table_input(table_name)
    
    where_clause = "object_name = @table_name"
    params = [bigquery.ScalarQueryParameter("table_name", "STRING", table)]

    if dataset:
        where_clause += " AND object_schema = @dataset_name"
        params.append(bigquery.ScalarQueryParameter("dataset_name", "STRING", dataset))

    sql = f"""
        SELECT grantee, privilege_type, object_schema, object_name
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.OBJECT_PRIVILEGES`
        WHERE object_type = 'TABLE' AND {where_clause} AND privilege_type = 'SELECT'
    """
    return _run_query(sql, params)

def find_publicly_exposed_datasets():
    """
    Checks for datasets that are exposed to 'allUsers' or 'allAuthenticatedUsers'.
    """
    exposed_datasets = []
    
    try:
        client = get_client()
        datasets = list(client.list_datasets(project=agent.TARGET_PROJECT_ID))
        
        for ds_item in datasets:
            try:
                dataset_ref = client.dataset(ds_item.dataset_id, project=agent.TARGET_PROJECT_ID)
                dataset = client.get_dataset(dataset_ref)
                
                for entry in dataset.access_entries:
                    if entry.special_group in ['allUsers', 'allAuthenticatedUsers']:
                        exposed_datasets.append({
                            "object_name": dataset.dataset_id,
                            "grantee": entry.special_group,
                            "role": entry.role,
                            "note": "Detected via API scan"
                        })
            except Exception as inner_e:
                print(f"Warning: Could not check dataset {ds_item.dataset_id}: {inner_e}")
                continue

    except Exception as e:
        if isinstance(e, PermissionError) or "User is not authenticated" in str(e):
             raise
        return [{"error": f"Error scanning datasets via API: {str(e)}"}]

    if not exposed_datasets:
        return [{"message": "No publicly exposed datasets found."}]

    return exposed_datasets

def get_recent_table_users(table_name: str, days: int = 30):
    """
    Returns a list of users who have queried a specific table.
    """
    try:
        validate_table_id(table_name)
    except ValueError as e:
        return [{"error": str(e)}]

    dataset, table = _parse_table_input(table_name)
    
    params = [
        bigquery.ScalarQueryParameter("table_id", "STRING", table),
        bigquery.ScalarQueryParameter("days", "INT64", days)
    ]

    extra_filter = ""
    if dataset:
        extra_filter = "AND ref.dataset_id = @dataset_id"
        params.append(bigquery.ScalarQueryParameter("dataset_id", "STRING", dataset))

    sql = f"""
        SELECT DISTINCT user_email, creation_time, query
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`,
        UNNEST(referenced_tables) AS ref
        WHERE ref.table_id = @table_id {extra_filter}
        AND creation_time BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY) AND CURRENT_TIMESTAMP()
        ORDER BY creation_time DESC LIMIT 50
    """
    return _run_query(sql, params)

def get_iam_policy_recommendations():
    """
    Fetches active IAM policy recommendations (Security).
    """
    sql = f"""
        SELECT
            last_updated_time,
            description,
            target_resources,
            primary_impact,
            additional_details
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.RECOMMENDATIONS`
        WHERE recommender = 'google.iam.policy.Recommender'
        AND state = 'ACTIVE'
        ORDER BY last_updated_time DESC
        LIMIT 20
    """
    return _run_query(sql)

# --- PERFORMANCE TOOLS ---

def get_common_query_errors(days: int = 30):
    """Returns the most frequent error messages from the last N days (Default: 30)."""
    sql = f"""
        SELECT error_result.reason, COUNT(*) AS error_count
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        AND error_result IS NOT NULL
        GROUP BY 1 ORDER BY error_count DESC LIMIT 10
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

def get_hourly_slot_consumption(days: int = 30):
    """Analyzes query load time aggregated by hour of day (Default: 30)."""
    sql = f"""
        SELECT EXTRACT(HOUR FROM creation_time) AS hour_of_day,
        SUM(total_slot_ms) / (1000 * 60 * 60) AS total_slot_hours
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        GROUP BY 1 ORDER BY total_slot_hours DESC
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

def get_most_frequently_queried_tables(days: int = 30):
    """Returns the top 20 tables that are queried most often (Default: 30)."""
    sql = f"""
        SELECT ref.table_id, ref.dataset_id, COUNT(*) AS query_count
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`,
        UNNEST(referenced_tables) AS ref
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        GROUP BY 1, 2 ORDER BY query_count DESC LIMIT 20
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

# --- INFRASTRUCTURE & ADVANCED OPTIMIZATION ---

def check_slot_capacity_saturation():
    """Checks if the project is hitting slot capacity limits."""
    sql = f"""
        SELECT period_start,
        SUM(period_slot_ms) / 1000 AS total_slot_seconds,
        COUNT(DISTINCT job_id) AS active_jobs
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_TIMELINE_BY_PROJECT`
        WHERE period_start > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 6 HOUR)
        GROUP BY 1 ORDER BY 1 DESC LIMIT 100
    """
    return _run_query(sql)

def suggest_partitioning_keys(days: int = 30):
    """Finds large unpartitioned tables and suggests keys."""
    sql = f"""
        WITH LargeUnpart AS (
            SELECT t.table_schema, t.table_name, t.total_logical_bytes
            FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLE_STORAGE` t
            JOIN `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.TABLES` tbl
            ON t.table_schema = tbl.table_schema AND t.table_name = tbl.table_name
            WHERE tbl.ddl NOT LIKE '%PARTITION BY%'
            AND t.total_logical_bytes > 10737418240 -- 10GB
            ORDER BY t.total_logical_bytes DESC LIMIT 3
        )
        SELECT
            l.table_name,
            l.total_logical_bytes / (1024*1024*1024) as size_gb,
            j.query
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT` j
        CROSS JOIN UNNEST(j.referenced_tables) ref
        JOIN LargeUnpart l ON ref.table_id = l.table_name
        WHERE j.creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        AND j.statement_type = 'SELECT'
        QUALIFY ROW_NUMBER() OVER(PARTITION BY l.table_name ORDER BY j.total_slot_ms DESC) <= 3
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    return _run_query(sql, params)

def detect_antipatterns_in_query(sql: str) -> List[str]:
    """
    Analyzes a SQL string for common BigQuery anti-patterns using Regex.
    """
    findings = []
    
    # 1. SELECT * (Star)
    if re.search(r"SELECT\s+\*\s+FROM", sql, re.IGNORECASE):
        findings.append("SELECT *: Avoid selecting all columns. Select only specific columns to reduce cost.")

    # 2. ORDER BY without LIMIT
    # Heuristic: If ORDER BY presence > LIMIT presence (naive but effective for top-level)
    # A safer check: If there is an ORDER BY but no LIMIT at all.
    if re.search(r"ORDER\s+BY", sql, re.IGNORECASE) and not re.search(r"LIMIT\s+\d+", sql, re.IGNORECASE):
        findings.append("ORDER BY without LIMIT: Sorting large result sets without a limit can be expensive and slow.")

    # 3. REGEXP_CONTAINS vs LIKE
    if re.search(r"REGEXP_CONTAINS", sql, re.IGNORECASE):
        findings.append("REGEXP_CONTAINS: Check if 'LIKE' can be used instead for better performance on simple patterns.")

    # 4. Wildcard at start of LIKE (Non-sargable)
    if re.search(r"LIKE\s+['\"]%[^'\"]+['\"]", sql, re.IGNORECASE):
        findings.append("Leading Wildcard in LIKE: 'LIKE %...' prevents index usage and requires full scans.")

    # 5. Cross Joins
    if re.search(r"CROSS\s+JOIN", sql, re.IGNORECASE):
        findings.append("CROSS JOIN: Avoid cross joins as they can produce massive result sets (Cartesian products).")
        
    # 6. DML Single Row Inserts (VALUES)
    if re.search(r"INSERT\s+INTO\s+.*VALUES\s*\(", sql, re.IGNORECASE):
        findings.append("Single Row INSERT: Avoid frequent single-row inserts. Use streaming or batch loading instead.")

    # 7. String Casting in Filters (Dynamic Predicates)
    if re.search(r"(WHERE|JOIN).*CAST\(\s*\w+\s+AS\s+STRING\s*\)", sql, re.IGNORECASE | re.DOTALL):
         findings.append("String Casting in Filter: Casting columns to STRING in WHERE/JOIN clauses prevents partition pruning.")
         
    # 8. Semi-Join (IN subquery)
    if re.search(r"IN\s*\(\s*SELECT", sql, re.IGNORECASE):
        findings.append("Semi-Join (IN Subquery): IN (SELECT...) can be inefficient. Consider using EXISTS or JOIN.")

    return findings

def analyze_recent_queries_for_antipatterns(days: int = 30):
    """
    Fetches heavy queries from the last N days and analyzes them for specific anti-patterns.
    """
    # 1. Fetch Queries
    sql = f"""
        SELECT user_email, job_id, query,
        ROUND(total_bytes_processed / 1073741824, 2) AS gb_processed,
        ROUND(total_slot_ms / 3600000, 2) AS slot_hours
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
        AND statement_type = 'SELECT'
        QUALIFY ROW_NUMBER() OVER(PARTITION BY query ORDER BY total_slot_ms DESC) = 1
        ORDER BY total_slot_ms DESC LIMIT 10
    """
    params = [bigquery.ScalarQueryParameter("days", "INT64", days)]
    
    rows = _run_query(sql, params)
    
    # 2. Analyze each query
    results = []
    for row in rows:
        # Skip if row is an error dict
        if "error" in row:
            return rows 
            
        query_text = row.get("query", "")
        detected_issues = detect_antipatterns_in_query(query_text)
        
        # Only include if issues are found, or standard "Heavy Query" note?
        # Let's include all heavy queries but annotate them.
        row["detected_antipatterns"] = detected_issues if detected_issues else ["None detected (check logic manually)"]
        results.append(row)
        
    return results

# --- NEW RECOMMENDER TOOLS ---

def get_partition_cluster_recommendations():
    """
    Fetches active partitioning and clustering recommendations from Google Cloud Recommender.
    """
    sql = f"""
        SELECT
            last_updated_time,
            description,
            target_resources,
            primary_impact,
            additional_details
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.RECOMMENDATIONS`
        WHERE recommender = 'google.bigquery.table.PartitionClusterRecommender'
        AND state = 'ACTIVE'
        ORDER BY last_updated_time DESC
        LIMIT 20
    """
    return _run_query(sql)

def get_materialized_view_recommendations():
    """
    Fetches active materialized view recommendations from Google Cloud Recommender.
    """
    sql = f"""
        SELECT
            last_updated_time,
            description,
            target_resources,
            primary_impact,
            additional_details
        FROM `{agent.TARGET_PROJECT_ID}.region-{agent.TARGET_REGION}.INFORMATION_SCHEMA.RECOMMENDATIONS`
        WHERE recommender LIKE 'google.bigquery.materializedview%'
        AND state = 'ACTIVE'
        ORDER BY last_updated_time DESC
        LIMIT 20
    """
    return _run_query(sql)

# --- COMPREHENSIVE SCAN & VISUALIZATION ---

def _create_placeholder_image(text_overlay: str) -> str:
    """Creates a small, lightweight placeholder image with text."""
    if PIL_AVAILABLE:
        # Create a 450x250 placeholder
        img = Image.new('RGB', (450, 250), color=(20, 20, 30))
        d = ImageDraw.Draw(img)
        # Attempt to position text roughly in center
        d.text((50, 110), text_overlay, fill=(255, 100, 100))
        output_buffer = io.BytesIO()
        img.save(output_buffer, format="JPEG", quality=50)
        return base64.b64encode(output_buffer.getvalue()).decode('utf-8')
    return ""

def _create_error_image_b64() -> str:
    """Returns a full Base64 Data URI for a 'Generation Failed' image."""
    b64_str = _create_placeholder_image("Dashboard Generation Failed")
    return f"data:image/jpeg;base64,{b64_str}"

def _compress_and_encode_image(image_bytes: bytes, mime_type: str = "image/png") -> str:
    """
    AGGRESSIVE COMPRESSION:
    Compresses image bytes to ensure it fits within LLM output token limits.
    Updated: HD Resolution allowed as we extract directly from tool output.
    """
    final_mime = "image/jpeg"
    
    if PIL_AVAILABLE:
        try:
            # 1. Load Image
            img = Image.open(io.BytesIO(image_bytes))
            
            # 2. Convert to RGB (Required for JPEG)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            
            # 3. RESIZE: HD Quality (1280x1280 max)
            img.thumbnail((1280, 1280))
            
            # 4. Save as High-Quality JPEG
            output_buffer = io.BytesIO()
            # Quality=85 (Standard High Quality)
            img.save(output_buffer, format="JPEG", quality=85, optimize=True)
            
            image_bytes = output_buffer.getvalue()
        except Exception as e:
            print(f"Image compression failed: {e}. Using original.")
            
    # 5. Base64 Encode
    encoded_string = base64.b64encode(image_bytes).decode('utf-8')
    
    # 6. FAILSAFE: Relaxed Limit (e.g., 5MB limit)
    # Allows High Quality images since we use direct tool extraction.
    if len(encoded_string) > 5000000:
        print(f"WARNING: Generated image is massive ({len(encoded_string)} chars).")

    
    return f"data:{final_mime};base64,{encoded_string}"

def _generate_dashboard_image(summary_text: str) -> Optional[str]:
    """
    Generates an image using Vertex AI, compresses it, and returns a Base64 string.
    """
    if not _init_vertex_ai():
        return _create_error_image_b64()
    
    # Prompt Engineering for a Professional Infographic Dashboard
    prompt = f"""
    Create a professional infographic dashboard for BigQuery Analysis:
    {summary_text}
    
    Guidelines:
    - Dark Mode UI, High contrast.
    - 3 Panels: Cost, Security, Performance.
    - Simple Charts (Donut, Bar).
    - IMPORTANT: Use bold, large text. Do not include fine details.
    - TEXT ACCURACY: Render labels EXACTLY as provided. Do not misspell or hallucinate text.
    - FONT: Use standard, clean sans-serif fonts for maximum legibility.
    """
    
    # Try Gemini First
    try:
        model = GenerativeModel(agent.IMAGE_GENERATION_MODEL)
        response = model.generate_content(
            prompt,
            generation_config=GenerationConfig(
                response_modalities=["IMAGE"]
            )
        )
        
        if response.candidates and response.candidates[0].content.parts:
            for part in response.candidates[0].content.parts:
                if part.inline_data:
                    return _compress_and_encode_image(
                        part.inline_data.data, 
                        part.inline_data.mime_type
                    )
            
    except Exception as e:
        print(f"Gemini Image Gen Error: {e}")
        


    # If both failed, return explicit error image rather than None
    return _create_error_image_b64()

def perform_full_environment_scan():
    """
    Analyzes the entire environment across Cost, Security, and Performance,
    summarizes the findings, and generates a visual dashboard representation.
    """
    
    # 1. Gather Data (Running key lightweight checks in PARALLEL)
    findings = []
    
    # Helper to run functions safely
    def run_safe(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return None

    # Run queries SEQUENTIALLY to avoid contextvars threading issues
    forecast = run_safe(forecast_monthly_costs)
    time_travel = run_safe(get_top_time_travel_consumers)
    unused = run_safe(find_unused_tables, days_inactive=30)
    public_datasets = run_safe(find_publicly_exposed_datasets)
    iam_recs = run_safe(get_iam_policy_recommendations)
    errors = run_safe(get_common_query_errors)

    # 2. Synthesize Summary (Processing the results)
    
    # Cost
    if forecast and isinstance(forecast, list) and 'forecasted_monthly_slot_hours' in forecast[0]:
         findings.append(f"Projected Monthly Slot Hours: {forecast[0]['forecasted_monthly_slot_hours']}")
    
    if time_travel:
        findings.append(f"Tables with heavy Time Travel costs: {len(time_travel)}")
        
    if unused:
        findings.append(f"Unused Tables (30 days): {len(unused)}")

    # Security
    # Only report if the check actually succeeded (is not None)
    if public_datasets is not None:
        if public_datasets and 'message' not in public_datasets[0]:
            findings.append(f"CRITICAL: Found {len(public_datasets)} publicly exposed datasets.")
        else:
            findings.append("Security: No public datasets found.")
        
    if iam_recs:
        findings.append(f"IAM Recommendations available: {len(iam_recs)}")

    # Performance
    if errors:
        top_error = errors[0].get('reason', 'N/A')
        # Sanitize for Image Generation: "notFound" -> "Not Found"
        if top_error == "notFound":
            top_error = "Not Found"
        findings.append(f"Top Query Error: {top_error}")

    # 3. Generate Image (Only if we have findings)
    if not findings:
        return {
            "summary_of_findings": ["Error: Unable to scan environment. Authentication failed for all checks."],
            "note": "Please ensure you are logged in."
        }
        
    summary_text = " | ".join(findings)
    image_b64 = _generate_dashboard_image(summary_text)
    
    return {
        "summary_of_findings": findings,
        "dashboard_image_base64": image_b64, 
        "note": "Image generated successfully. The UI will render it from the tool output. DO NOT repeat the Base64 string in your text response."
    }