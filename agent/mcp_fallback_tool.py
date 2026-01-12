
# Provides a generic SQL execution tool using the BigQuery MCP server as a fallback.
import requests
import json
import google.auth
import google.auth.transport.requests
import agent
from . import context

def execute_sql_via_mcp(query: str):
    """
    Executes a SQL query using the remote BigQuery MCP server.
    Use this for ad-hoc queries, billing/cost analysis, or anything not covered by specific tools.
    """
    mcp_endpoint = "https://bigquery.googleapis.com/mcp"
    
    # 1. Get Authentication
    token = context.get_oauth_token()
    
    # 2. Authenticate if token is missing (Fallback Logic)
    if not token:
        # Try getting from ADC directly
        credentials, _ = google.auth.default(quota_project_id=agent.QUOTA_PROJECT_ID)
        if not credentials.token:
             credentials.refresh(google.auth.transport.requests.Request())
        token = credentials.token

    if not token:
        # If still no token, we can't authenticate.
        return [{"error": "Authentication failed. No user token or ADC token available."}]

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-goog-user-project": agent.QUOTA_PROJECT_ID # CRITICAL for billing/user creds
    }

    # 3. Construct JSON-RPC Request
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "execute_sql",
            "arguments": {
                "query": query,
                "project_id": agent.TARGET_PROJECT_ID
            }
        },
        "id": 1
    }

    try:
        response = requests.post(
            mcp_endpoint, 
            headers=headers, 
            json=payload, 
            timeout=300
        )
        
        try:
            result_json = response.json()
        except json.JSONDecodeError:
            return [{"error": f"Invalid JSON response: {response.text}", "status_code": response.status_code}]

        # 4. Parse MCP Response
        if response.status_code != 200:
             # MCP often returns error details in JSON even on 4xx/5xx
             if "error" in result_json:
                 return [{"error": f"MCP Error ({response.status_code}): {result_json['error'].get('message', 'Unknown')}"}]
             return [{"error": f"HTTP Error {response.status_code}", "raw": str(result_json)}]

        if "error" in result_json:
            return [{"error": f"MCP Error: {result_json['error'].get('message', 'Unknown error')}"}]
            
        if "result" in result_json and "content" in result_json["result"]:
            content_list = result_json["result"]["content"]
            final_data = []
            for item in content_list:
                if item.get("type") == "text":
                    text_content = item["text"]
                    try:
                        # Try to parse the text content as JSON (Mocking what a SQL tool might return)
                        data = json.loads(text_content)
                        if isinstance(data, list):
                            final_data.extend(data)
                        elif isinstance(data, dict):
                            final_data.append(data)
                        else:
                            final_data.append({"info": str(data)})
                    except json.JSONDecodeError:
                        # Return as raw text if not JSON
                        final_data.append({"text": text_content})
            
            if not final_data:
                return [{"message": "Query executed successfully but returned no data."}]
            return final_data

        return [{"error": "MCP response format not recognized", "raw": str(result_json)}]

    except requests.exceptions.Timeout:
        return [{"error": "Request to MCP server timed out (300s limit)."}]
    except requests.exceptions.RequestException as e:
        return [{"error": f"HTTP Request to MCP failed: {str(e)}"}]
    except Exception as e:
        return [{"error": f"Processing failed: {str(e)}"}]
