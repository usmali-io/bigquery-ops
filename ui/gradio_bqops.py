# The main entry point for the Gradio-based frontend application, handling UI and user interactions.


import gradio as gr
from gradio import oauth
import requests
import json
import uuid
import re
import os
import pandas as pd
import altair as alt
import tempfile
import warnings
import base64
import io
import fastapi
import markdown
import asyncio
from fpdf import FPDF
import vl_convert as vlc
from PIL import Image as PILImage
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Suppress noisy warnings
warnings.filterwarnings("ignore", category=UserWarning, module="gradio")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="gradio")

# MONKEYPATCH: Debug Redirect URI
original_generate_redirect_uri = oauth._generate_redirect_uri

def debug_generate_redirect_uri(request: fastapi.Request) -> str:
    uri = original_generate_redirect_uri(request)
    # STRIP QUERY PARAMS: Google requires exact match. Gradio appends ?_target_url=...
    # We strip it to ensure it matches 'http://localhost:7860/login/callback'
    if "?" in uri:
        uri = uri.split("?")[0]
    # print(f"\n[DEBUG] Cleaned Redirect URI: {uri}\n")
    return uri

oauth._generate_redirect_uri = debug_generate_redirect_uri

# MONKEYPATCH: Google OAuth Compatibility for OAuthProfile
# Google returns 'email' but not 'preferred_username'. Gradio expects 'preferred_username'.
original_oauth_profile_init = oauth.OAuthProfile.__init__

def patched_oauth_profile_init(self, data: dict):
    # Ensure all expected keys exist globally before calling original init if possible,
    # or just manually set attributes to avoid KeyError.
    # Actually, the original init calls `self.update(data)` then accesses keys.
    # We can just populate missing keys in `data` before calling original.
    if "preferred_username" not in data and "email" in data:
        data["preferred_username"] = data["email"]
    if "name" not in data and "given_name" in data:
        data["name"] = data["given_name"]
    if "profile" not in data:
        data["profile"] = "https://google.com" # Dummy profile link
    if "picture" not in data:
        data["picture"] = ""
    
    original_oauth_profile_init(self, data)

oauth.OAuthProfile.__init__ = patched_oauth_profile_init

# MONKEYPATCH: LoginButton/Session Compatibility
# LoginButton directly reads request.session["oauth_info"]["userinfo"]["preferred_username"]
# bypassing the OAuthProfile class. We must inject it into the raw token response.
# Since gradio 5.x, oauth structure changed. We must patch _add_oauth_routes instead.

def patched_add_oauth_routes(app: fastapi.FastAPI) -> None:
    """Add OAuth routes to the FastAPI app (login, callback handler and logout)."""
    # print(f"DEBUG: Executing patched_add_oauth_routes for app: {app}")
    try:
        from authlib.integrations.base_client.errors import MismatchingStateError
        from authlib.integrations.starlette_client import OAuth
    except ImportError as e:
        raise ImportError(
            "Cannot initialize OAuth to due a missing library. Please run `pip install gradio[oauth]` or add "
            "`gradio[oauth]` to your requirements.txt file in order to install the required dependencies."
        ) from e

        # Check environment variables
    msg = (
        "OAuth is required but {} environment variable is not set. Make sure you've enabled OAuth in your Space by"
        " setting `hf_oauth: true` in the Space metadata."
    )
    
    # Use global/env vars
    OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
    OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
    OAUTH_SCOPES = os.environ.get("OAUTH_SCOPES")
    OPENID_PROVIDER_URL = os.environ.get("OPENID_PROVIDER_URL")
    MAX_REDIRECTS = 2

    if OAUTH_CLIENT_ID is None:
        raise ValueError(msg.format("OAUTH_CLIENT_ID"))
    if OAUTH_CLIENT_SECRET is None:
        raise ValueError(msg.format("OAUTH_CLIENT_SECRET"))
    if OAUTH_SCOPES is None:
        raise ValueError(msg.format("OAUTH_SCOPES"))
    if OPENID_PROVIDER_URL is None:
        raise ValueError(msg.format("OPENID_PROVIDER_URL"))

    # Register OAuth server
    local_oauth = OAuth()
    local_oauth.register(
        name="google",
        client_id=OAUTH_CLIENT_ID,
        client_secret=OAUTH_CLIENT_SECRET,
        client_kwargs={"scope": OAUTH_SCOPES},
        server_metadata_url=OPENID_PROVIDER_URL + "/.well-known/openid-configuration",
    )

    # Define OAuth routes
    @app.get("/login/google")
    async def oauth_login(request: fastapi.Request):
        """Endpoint that redirects to Google OAuth page."""
        # Define target (where to redirect after login)
        redirect_uri = oauth._generate_redirect_uri(request)
        # Force account selection and consent prompt to ensure logout works effectively
        return await local_oauth.google.authorize_redirect(request, redirect_uri, prompt="consent")

    @app.get("/login/callback")
    async def oauth_redirect_callback(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
        """Endpoint that handles the OAuth callback."""
        from fastapi.responses import RedirectResponse
        import urllib.parse
        
        try:
            oauth_info = await local_oauth.google.authorize_access_token(request)
            
            # --- PATCH START ---
            if "userinfo" in oauth_info:
                if "preferred_username" not in oauth_info["userinfo"] and "email" in oauth_info["userinfo"]:
                    oauth_info["userinfo"]["preferred_username"] = oauth_info["userinfo"]["email"]
                if "name" not in oauth_info["userinfo"] and "given_name" in oauth_info["userinfo"]:
                    oauth_info["userinfo"]["name"] = oauth_info["userinfo"]["given_name"]
            # --- PATCH END ---
            
        except MismatchingStateError:
            # If the state mismatch, it is very likely that the cookie is corrupted.
            # There is a bug reported in authlib that causes the token to grow indefinitely if the user tries to login
            # repeatedly. Since cookies cannot get bigger than 4kb, the token will be truncated at some point - hence
            # losing the state. A workaround is to delete the cookie and redirect the user to the login page again.
            # See https://github.com/lepture/authlib/issues/622 for more details.

            # Delete all keys that are related to the OAuth state, just in case
            for key in list(request.session.keys()):
                if key.startswith("_state_google"):
                    request.session.pop(key)

            # Parse query params
            nb_redirects = int(request.query_params.get("_nb_redirects", 0))
            target_url = request.query_params.get("_target_url")

            # Build /login URI with the same query params as before and bump nb_redirects count
            query_params = {"_nb_redirects": nb_redirects + 1}
            if target_url:
                query_params["_target_url"] = target_url

            login_uri = f"/login/google?{urllib.parse.urlencode(query_params)}"

            # If the user is redirected more than 3 times, it is very likely that the cookie is not working properly.
            # (e.g. browser is blocking third-party cookies in iframe). In this case, redirect the user in the
            # non-iframe view.
            if nb_redirects > MAX_REDIRECTS:
                host = os.environ.get("SPACE_HOST")
                if host is None:  # cannot happen in a Space
                    raise RuntimeError(
                        "Gradio is not running in a Space (SPACE_HOST environment variable is not set)."
                        " Cannot redirect to non-iframe view."
                    ) from None
                host_url = "https://" + host.rstrip("/")
                return RedirectResponse(host_url + login_uri)

            # Redirect the user to the login page again
            return RedirectResponse(login_uri)

        # OAuth login worked => store the user info in the session and redirect
        request.session["oauth_info"] = oauth_info
        return oauth._redirect_to_target(request)

    @app.get("/logout")
    async def oauth_logout(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
        """Endpoint that logs out the user (clears cookie session)."""
        request.session.clear()
        print(f"Logging out user.")
        return oauth._redirect_to_target(request)

# Apply the patch
oauth._add_oauth_routes = patched_add_oauth_routes
oauth._add_mocked_oauth_routes = patched_add_oauth_routes

# --- Configuration ---
ADK_SERVER_BASE_URL = os.getenv("ADK_SERVER_URL", "http://127.0.0.1:8000")
APP_NAME = "agent"

# --- Session Initialization ---
def init_session_state(request: gr.Request) -> dict:
    """Initializes per-user session state."""
    user_id = "gradio_user"
    if request:
        if request.username:
            user_id = request.username
        # Fallback to session info if available
        elif hasattr(request, "session") and "oauth_info" in request.session:
             user_info = request.session["oauth_info"].get("userinfo", {})
             user_id = user_info.get("email") or user_info.get("preferred_username") or user_id

    session_id = f"session_{uuid.uuid4()}"
    print(f"Initializing new session: {session_id} for user: {user_id}")
    
    # Register session on backend
    create_session_if_not_exists(session_id, user_id)
    
    return {
        "session_id": session_id,
        "user_id": user_id
    }

# --- Function to Create the Session on Backend ---
def create_session_if_not_exists(session_id, user_id):
    session_url = f"{ADK_SERVER_BASE_URL}/apps/{APP_NAME}/users/{user_id}/sessions/{session_id}"
    try:
        response = requests.post(session_url)
        if response.status_code not in [200, 404]: 
             response.raise_for_status()
    except Exception as e:
        print(f"Warning: Could not init session (server might be down): {e}")

# --- Helper: Reset Session ---
def reset_conversation(session_state):
    print(f"Resetting session for {session_state.get('user_id', 'unknown')}...")
    # Generate new ID
    new_id = f"session_{uuid.uuid4()}"
    user_id = session_state.get("user_id", "gradio_user")
    
    # Update state
    session_state["session_id"] = new_id
    create_session_if_not_exists(new_id, user_id)
    
    return (
        [],                                     # chatbot
        "",                                     # msg_input
        gr.update(visible=False),               # plot_output
        gr.update(visible=False, value=None),   # image_output
        gr.update(visible=False, scale=0),      # viz_column (Combined visibility & scale)
        gr.update(scale=20),                    # chat_column
        False,                                  # plot_visible_state
        gr.update(visible=False),               # toggle_btn
        gr.update(value=None, visible=False),   # download_btn
        gr.update(samples=[], visible=False),   # suggestion_dataset
        [],                                     # session_viz
        []                                      # session_tables
    )


# --- Helper: Recursive Key Finder ---
def find_key_recursive(obj, target_key):
    """
    Recursively searches a dictionary/list structure for a specific key.
    Returns the value of the first match found.
    """
    if isinstance(obj, dict):
        if target_key in obj:
            return obj[target_key]
        for k, v in obj.items():
            result = find_key_recursive(v, target_key)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = find_key_recursive(item, target_key)
            if result is not None:
                return result
    return None

# --- Helper: Extract Image from Tool Output ---
def extract_image_from_history(agent_response_json):
    """
    Scans the entire conversation history for 'dashboard_image_base64'.
    Uses Deep Recursive Search to find the key regardless of nesting.
    """
    if not isinstance(agent_response_json, list):
        return None

    # print(f"DEBUG: Scanning {len(agent_response_json)} messages for image...")
    
    # Use recursive search on the entire response object
    image_b64 = find_key_recursive(agent_response_json, 'dashboard_image_base64')
    
    if image_b64:
        # print(f"DEBUG: Found 'dashboard_image_base64' (Length: {len(str(image_b64))})")
        return image_b64
    
    # Fallback
    legacy_image = find_key_recursive(agent_response_json, 'dashboard_image_file')
    if legacy_image and str(legacy_image).startswith("data:image"):
        # print(f"DEBUG: Found legacy 'dashboard_image_file' (Length: {len(str(legacy_image))})")
        return legacy_image

    # print("DEBUG: No image found after deep recursive search.")
    return None

# --- Helper: Extract Tables from Tool Output ---
def extract_tables_from_history(agent_response_json):
    """
    Scans the response for specific tool outputs that return lists of dicts
    and converts them into structured table metadata.
    """
    tables = []
    
    # Define interesting tools to capture
    INTERESTING_TOOLS = [
        "find_unused_tables",
        "analyze_storage_compression_model",
        "identify_large_unpartitioned_tables",
        "find_publicly_exposed_datasets",
        "get_top_time_travel_consumers",
        "get_expensive_queries_by_slot_hours",
        "forecast_monthly_costs",
        "check_table_permissions",
        "get_recent_table_users",
        "get_common_query_errors",
        "get_hourly_slot_consumption",
        "get_most_frequently_queried_tables",
        "check_slot_capacity_saturation",
        "suggest_partitioning_keys",
        "analyze_recent_queries_for_antipatterns",
        "get_partition_cluster_recommendations",
        "get_materialized_view_recommendations"
    ]
    
    # 1. Find all `functionResponse` parts
    # The structure is usually: [ { "functionResponse": { "name": "ToolName", "response": { "name": "ToolName", "content": RESULT } } } ]
    # OR sometimes nested differently depending on ADK version. We search recursively for "functionResponse".
    
    def find_function_responses(obj):
        found = []
        if isinstance(obj, dict):
            if "functionResponse" in obj:
                found.append(obj["functionResponse"])
            for k, v in obj.items():
                found.extend(find_function_responses(v))
        elif isinstance(obj, list):
            for item in obj:
                found.extend(find_function_responses(item))
        return found

    responses = find_function_responses(agent_response_json)
    
    print(f"DEBUG: Found {len(responses)} function responses.")

    for resp in responses:
        tool_name = resp.get("name")
        # In some versions, 'response' key holds the actual return, or it's directly in 'content' if flattened?
        # Standard Gemni API: functionResponse = { "name": "...", "response": { "name": "...", "content": ... } }
        
        content = None
        if "response" in resp and isinstance(resp["response"], dict):
            content = resp["response"].get("content")
            # Sometimes content is stringified JSON
            # Sometimes content is the direct object
        
        # Fallback if structure is different
        if not content and "content" in resp:
            content = resp["content"]

        if tool_name in INTERESTING_TOOLS and content:
            print(f"DEBUG: Extracting table for {tool_name}")
            try:
                # If content is a list, we can probably make a table
                data = content
                if isinstance(content, str):
                    try:
                        # Attempt to parse if stringified JSON
                        # Often tools return python lists, but ADK might serialize
                        # Since we are in the client, we receive JSON from `requests.post`. 
                        pass 
                    except:
                        pass
                
                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                    # It's a list of records!
                    # Normalize columns if keys differ
                    df = pd.DataFrame(data)
                    tables.append({
                        "title": tool_name.replace("_", " ").title(),
                        "data": df
                    })
            except Exception as e:
                print(f"DEBUG: Failed to extract table for {tool_name}: {e}")

    return tables

# --- Helper: Create PDF ---
def create_pdf(html_content, session_viz, session_tables):
    """
    Generates a PDF file from HTML content, Visualizations, and Data Tables.
    """
    timestamp = uuid.uuid4().hex[:8]
    filename = f"bqops_report_{timestamp}.pdf"
    file_path = os.path.join(tempfile.gettempdir(), filename)
    
    # Disclaimer Text
    DISCLAIMER_TEXT = (
        "DISCLAIMER: This report was generated by a community-managed AI agent for BigQuery Operations. "
        "It may contain incorrect results or hallucinations. The developer bears no responsibility for any "
        "consequences resulting from the use of this information. Please verify all findings manually."
    )

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # 1. Main Report (HTML)
        # fpdf2's write_html is decent but basic. 
        # We wrap it in try-except to handle potential tag errors.
        pdf.set_font("Helvetica", size=11)
        pdf.write_html(html_content)
        
        # 2. Key Actionable Data (Tables)
        if session_tables:
            pdf.add_page()
            pdf.set_font("Helvetica", style='B', size=16)
            pdf.cell(0, 10, "Appendix A: Actionable Data", new_x="LMARGIN", new_y="NEXT", align='C')
            pdf.ln(5)
            
            for table_info in session_tables:
                pdf.set_font("Helvetica", style='B', size=12)
                pdf.cell(0, 10, table_info["title"], new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
                
                # Render Table
                # fpdf2 has a nice table context manager
                df = table_info["data"]
                
                # Sanitize DF to remove base64 images that might cause issues/printing
                for col in df.columns:
                    # Check first row (if exists) for huge strings starting with data:image
                    if not df.empty and isinstance(df.iloc[0][col], str) and df.iloc[0][col].startswith("data:image") and len(df.iloc[0][col]) > 1000:
                         print(f"DEBUG: Dropping column '{col}' from PDF table '{table_info['title']}' as it appears to contain base64 image data.")
                         df = df.drop(columns=[col])

                # Safety check: if table is too wide, it might look bad.
                # We can try to fit it.
                
                with pdf.table() as table:
                    # Headers
                    row = table.row()
                    for col in df.columns:
                        row.cell(str(col))
                    # Rows
                    pdf.set_font("Helvetica", size=8)
                    for index, r in df.iterrows():
                        row = table.row()
                        for val in r:
                            row.cell(str(val))
                            
                pdf.ln(10) # Spacing between tables

        # 3. Visualizations
        if session_viz:
            pdf.add_page()
            pdf.set_font("Helvetica", style='B', size=16)
            pdf.cell(0, 10, "Appendix B: Session Visualizations", new_x="LMARGIN", new_y="NEXT", align='C')
            pdf.ln(10)
            
            for viz_html in session_viz:
                match = re.search(r'start_src="data:image/png;base64,(.*?)"', viz_html.replace('src="', 'start_src="'))
                if match:
                    img_data = match.group(1)
                    img_bytes = base64.b64decode(img_data)
                    
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_img:
                        tmp_img.write(img_bytes)
                        tmp_img_path = tmp_img.name
                    
                    try:
                        # Center image
                        w = pdf.epw
                        # Check if image is valid?
                        pdf.image(tmp_img_path, w=w) 
                        pdf.ln(10)
                    finally:
                         if os.path.exists(tmp_img_path):
                            os.unlink(tmp_img_path)

        # 4. Disclaimer Footer (Last Page)
        pdf.ln(20)
        pdf.set_font("Helvetica", style='I', size=8)
        pdf.set_text_color(100, 100, 100) # Gray
        pdf.multi_cell(0, 5, DISCLAIMER_TEXT, align='C')

        pdf.output(file_path)
        return file_path

    except Exception as e:
        print(f"PDF generation error: {e}")
        return None

# --- Main Function to Handle Chat and Plotting ---
async def handle_chat_and_plot(message, history, profile: gr.OAuthProfile | None, token: gr.OAuthToken | None, session_viz: list, session_tables: list, session_state: dict):
    print(f"Gradio client received: '{message}' (Session: {session_state.get('session_id')})")
    
    # 1. Call the Agent
    run_url = f"{ADK_SERVER_BASE_URL}/run"
    
    # Extract token if logged in
    state_delta = {}
    if token:
        state_delta["oauth_token"] = token.token
    else:
        # Explicitly clear token in backend if not provided by frontend
        state_delta["oauth_token"] = None

    payload = {
        "app_name": APP_NAME,
        "user_id": session_state["user_id"],
        "session_id": session_state["session_id"],
        "new_message": {"role": "user", "parts": [{"text": message}]},
        "state_delta": state_delta
    }

    try:
        # Added timeout=300 (5 minutes) to prevent premature disconnection
        # optimization: run blocking request in thread
        response = await asyncio.to_thread(requests.post, run_url, json=payload, timeout=300)
        response.raise_for_status()
        agent_response_json = response.json()
    except Exception as e:
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": f"❌ **Error:** {str(e)}\n\n*If this persists, click 'Reset Conversation'.*"})
        # Return error state with consistent output count
        return (
            "", history, 
            gr.update(visible=False), gr.update(visible=False), 
            gr.update(visible=False, scale=0), gr.update(scale=20), 
            False, gr.update(visible=False), gr.update(visible=False),
            gr.update(visible=False),
            session_viz, session_tables
        )

    # 2. Extract Content (Text)
    try:
        full_response_text = agent_response_json[-1]['content']['parts'][0]['text']
    except (KeyError, IndexError):
        full_response_text = "(No response text received from agent)"

    # 3. Extract Content (Visuals)
    dashboard_image_path = extract_image_from_history(agent_response_json)
    
    # Legacy/Fallback
    if not dashboard_image_path:
        image_data_match = re.search(r'\[DASHBOARD_IMAGE\](.*?)\[/DASHBOARD_IMAGE\]', full_response_text, re.DOTALL)
        if image_data_match:
             dashboard_image_path = image_data_match.group(1).strip()

    vega_match = re.search(r'\[VEGA\](.*?)\[/VEGA\]', full_response_text, re.DOTALL)
    # Robust match: optional closing tag or end of string
    followup_match = re.search(r'\[FOLLOW_UP\](.*?)(\[/FOLLOW_UP\]|$)', full_response_text, re.DOTALL)

    # Clean text (Remove tags)
    text_for_chat = re.sub(r'\[VEGA\].*\[/VEGA\]', '', full_response_text, flags=re.DOTALL)
    text_for_chat = re.sub(r'\[DASHBOARD_IMAGE\].*\[/DASHBOARD_IMAGE\]', '', text_for_chat, flags=re.DOTALL)
    text_for_chat = re.sub(r'\[DASHBOARD_GENERATED\]', '', text_for_chat, flags=re.DOTALL)
    # Robust cleanup: remove valid follow-up blocks even if truncated
    text_for_chat = re.sub(r'\[FOLLOW_UP\].*?(\[/FOLLOW_UP\]|$)', '', text_for_chat, flags=re.DOTALL).strip()
    
    # Process Follow-ups
    suggestion_samples = []
    if followup_match:
        raw_text = followup_match.group(1).strip()
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()
        print(f"DEBUG: Follow-up raw text found: {raw_text}")

        try:
            raw_suggestions = json.loads(raw_text)
            if isinstance(raw_suggestions, list):
                suggestion_samples = [[str(s)] for s in raw_suggestions]
            # 1. Try standard JSON
            parsed_list = json.loads(raw_text)
            if isinstance(parsed_list, list):
                suggestion_samples = [[str(s)] for s in parsed_list]
            print(f"DEBUG: Parsed {len(suggestion_samples)} suggestions via JSON.")
        except json.JSONDecodeError:
            # 2. Try ast.literal_eval (handles python-style lists with single quotes etc)
            try:
                import ast
                parsed_list = ast.literal_eval(raw_text)
                if isinstance(parsed_list, list):
                    suggestion_samples = [[str(s)] for s in parsed_list]
                print(f"DEBUG: Parsed {len(suggestion_samples)} suggestions via ast.literal_eval.")
            except Exception:
                # 3. Last resort: Regex split
                 # This is a bit hacky but works for simple lists
                cleaned = raw_text.strip("[]")
                suggestion_samples = [s.strip().strip('"').strip("'") for s in cleaned.split(",")]
                suggestion_samples = [[s] for s in suggestion_samples if s] # Filter out empty strings
                print(f"DEBUG: Parsed {len(suggestion_samples)} suggestions via regex split.")
        except Exception as e:
            print(f"DEBUG: General Follow-up Error: {e}")

    # 4. Process Visuals (Render)
    plot_figure = None
    csv_path = None
    
    # CASE A: Dashboard Image Detected (Base64)
    if dashboard_image_path:
        dashboard_str = str(dashboard_image_path)
        
        # Check if it's a Base64 string (starts with data:image)
        if dashboard_str.startswith("data:image"):
            try:
                # FIX: Convert Base64 string to PIL Image object
                header, encoded = dashboard_str.split(",", 1)
                image_bytes = base64.b64decode(encoded)
                dashboard_image_path = PILImage.open(io.BytesIO(image_bytes))
                text_for_chat += "\n\n**Visual Dashboard Generated.**"
            except Exception as e:
                print(f"DEBUG: Failed to convert Base64 to Image: {e}")
                dashboard_image_path = None
                
        elif os.path.exists(dashboard_str):
             text_for_chat += "\n\n**Visual Dashboard Generated.**"
        else:
             dashboard_image_path = None

    # CASE B: Vega-Lite Chart Detected
    elif vega_match:
        try:
             vega_json_str = vega_match.group(1).strip()
             vega_json_str = vega_json_str.replace("```json", "").replace("```", "").strip()
             vega_spec = json.loads(vega_json_str)

             # --- SANITIZATION & LAYOUT FIXES ---
             if "color" in vega_spec and isinstance(vega_spec["color"], dict):
                 color_def = vega_spec.pop("color")
                 if "encoding" not in vega_spec:
                     vega_spec["encoding"] = {}
                 if "color" not in vega_spec["encoding"]:
                      vega_spec["encoding"]["color"] = color_def

             # Enforce fixed size for visibility
             vega_spec["width"] = 500
             vega_spec["height"] = 320
             
             plot_figure = alt.Chart.from_dict(vega_spec)
             
             if 'data' in vega_spec and 'values' in vega_spec['data']:
                 df = pd.DataFrame(vega_spec['data']['values'])
                 temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode='w')
                 df.to_csv(temp_file.name, index=False)
                 csv_path = temp_file.name
                 text_for_chat += "\n\n**Data available for download.**"
             else:
                 csv_path = None
                 
        except Exception as e:
            print(f"Vega plotting error: {e}")
            text_for_chat += f"\n\n*(Error rendering chart: {e})*"

    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": text_for_chat})

    # 5. Extract Tables
    new_tables = extract_tables_from_history(agent_response_json)
    if new_tables:
        session_tables.extend(new_tables)
        print(f"DEBUG: Extracted {len(new_tables)} new tables. Total: {len(session_tables)}")

    # --- UI Updates ---
    viz_visible = False
    plot_update = gr.update(visible=False)
    image_update = gr.update(visible=False, value=None)
    download_update = gr.update(visible=False, value=None)
    toggle_btn_update = gr.update(visible=False)
    suggestion_update = gr.update(samples=suggestion_samples, visible=True) if suggestion_samples else gr.update(visible=False)
    
    if dashboard_image_path:
        viz_visible = True
        image_update = gr.update(visible=True, value=dashboard_image_path)
        plot_update = gr.update(visible=False)
        toggle_btn_update = gr.update(visible=True, value="Maximize Chart")
    
    elif plot_figure:
        viz_visible = True
        plot_update = gr.update(visible=True, value=plot_figure)
        image_update = gr.update(visible=False)
        download_update = gr.update(visible=True, value=csv_path)
        toggle_btn_update = gr.update(visible=True, value="Maximize Chart")

    if viz_visible:
        # Capture for Report
        try:
            if dashboard_image_path:
                buffered = io.BytesIO()
                dashboard_image_path.save(buffered, format="PNG")
                img_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
                session_viz.append(f'<img src="data:image/png;base64,{img_b64}" width="600" /><br/>')
            elif plot_figure:
                png_bytes = vlc.vegalite_to_png(plot_figure.to_json(), scale=2)
                img_b64 = base64.b64encode(png_bytes).decode("utf-8")
                session_viz.append(f'<img src="data:image/png;base64,{img_b64}" width="600" /><br/>')
        except Exception as e:
            print(f"Error capturing viz: {e}")

        return (
            "", history, plot_update, image_update, 
            gr.update(visible=True, scale=1), gr.update(scale=2), 
            False, toggle_btn_update, download_update,
            suggestion_update,
            suggestion_update,
            session_viz,
            session_tables
        )
    else:
        return (
            "", history, gr.update(visible=False), gr.update(visible=False), 
            gr.update(visible=False, scale=0), gr.update(scale=20), 
            False, gr.update(visible=False), gr.update(value=None, visible=False),
            suggestion_update,
            suggestion_update,
            session_viz,
            session_tables
        )

# --- Helper: Populate Input ---
def populate_input(selection):
    return selection[0]

# --- Toggle Logic ---
def toggle_plot_visibility(is_maximized):
    if is_maximized:
        # Restore: Chat visible (2), Viz visible (1) - Chat takes priority
        return False, gr.update(visible=True, scale=2), gr.update(visible=True, scale=1), gr.update(value="Maximize Chart")
    else:
        # Maximize: Chat hidden, Viz takes full breadth
        return True, gr.update(visible=False), gr.update(visible=True, scale=1), gr.update(value="Restore Chat")

# --- Auth Status Check ---
def check_auth_status(request: gr.Request):
    # print(f"DEBUG: check_auth_status called. Username: {request.username if request else 'None'}")
    
    # Try getting user from session directly if request.username is empty
    user_info = None
    if request:
        try:
            session_data = request.session
            # print(f"DEBUG: Session keys: {list(session_data.keys())}")
            if "oauth_info" in session_data:
                user_info = session_data["oauth_info"].get("userinfo", {})
                # print(f"DEBUG: Found oauth_info. Email: {user_info.get('email')}")
        except Exception as e:
            # print(f"DEBUG: Error accessing session: {e}")
            pass

    username = request.username if (request and request.username) else None
    if not username and user_info:
        username = user_info.get("email") or user_info.get("preferred_username")

    if username:
        # User is logged in
        user_label = f"Logout ({username})"
        return gr.update(visible=False), gr.update(value=user_label, visible=True)
    return gr.update(visible=True), gr.update(visible=False)

# --- PDF Report Generation Logic ---
def generate_pdf_report(history, token: gr.OAuthToken | None, session_viz: list, session_tables: list, session_state: dict):
    """
    Triggers the agent to generate a comprehensive report, converts it to PDF using fpdf2,
    and appends any session visualizations.
    """
    
    # 1. Define the Report Prompt
    report_prompt = (
        "Based on our session so far, please generate a comprehensive 'Key Findings & Recommendations' report. "
        "Format it as a clean Markdown document. "
        "Include sections for: Executive Summary, Cost Optimization Opportunities, Security Risks, Performance Bottlenecks, and Next Steps. "
        "Do not include chat pleasantries, just the report content."
    )
    
    # print(f"DEBUG: Generating PDF report with prompt: {report_prompt}")
    
    # 2. Call Agent
    run_url = f"{ADK_SERVER_BASE_URL}/run"
    state_delta = {}
    if token:
        state_delta["oauth_token"] = token.token
    else:
        state_delta["oauth_token"] = None

    payload = {
        "app_name": APP_NAME,
        "user_id": session_state["user_id"],
        "session_id": session_state["session_id"],
        "new_message": {"role": "user", "parts": [{"text": report_prompt}]},
        "state_delta": state_delta
    }

    full_response_text = ""
    try:
        response = requests.post(run_url, json=payload, timeout=300)
        response.raise_for_status()
        agent_response_json = response.json()
        
        try:
            full_response_text = agent_response_json[-1]['content']['parts'][0]['text']
        except (KeyError, IndexError):
            full_response_text = "# Error: No report content received."

    except Exception as e:
        full_response_text = f"# Error Generating Report\n\n{str(e)}"
    
    # 2.5 Clean up Agent Tags (Follow-ups, etc.)
    full_response_text = re.sub(r'\[FOLLOW_UP\].*?(\[/FOLLOW_UP\]|$)', '', full_response_text, flags=re.DOTALL).strip()
    full_response_text = re.sub(r'\[VEGA\].*?\[/VEGA\]', '', full_response_text, flags=re.DOTALL).strip()
    full_response_text = re.sub(r'\[DASHBOARD_IMAGE\].*?\[/DASHBOARD_IMAGE\]', '', full_response_text, flags=re.DOTALL).strip()
    full_response_text = re.sub(r'\[DASHBOARD_GENERATED\]', '', full_response_text, flags=re.DOTALL).strip()
    
    # Strip markdown images with data URIs to prevent console flooding/rendering issues
    # Matches ![...](data:image...)
    full_response_text = re.sub(r'!\[.*?\]\(data:image.*?\)', '', full_response_text, flags=re.DOTALL).strip()
    # Matches <img ... src="data:image..." ...>
    # Matches <img ... src="data:image..." ...>
    full_response_text = re.sub(r'<img[^>]*?src=["\']data:image.*?["\'][^>]*?>', '', full_response_text, flags=re.DOTALL).strip()
    
    # Nuclear Option: Strip ANY data:image string found (e.g. if inside specific attributes key)
    # This ensures no massive strings are passed to markdown/fpdf whatever the format
    # Using a simpler pattern to avoid backtracking issues on massive strings
    # Match any valid base64 char OR whitespace, until we hit something that clearly isn't (like a quote/tag end) or just consume a lot
    full_response_text = re.sub(r'data:image/[a-zA-Z0-9+.;=,/\s\-]+', '', full_response_text)
    
    # 3. Convert Markdown to HTML
    try:
        html_content = markdown.markdown(full_response_text, extensions=['extra'])
    except Exception as e:
        print(f"Error converting markdown: {e}")
        html_content = f"<p>Error converting report to HTML: {e}</p><pre>{full_response_text}</pre>"
    
    # 4. Generate PDF using Helper
    # Deduplicate tables?
    # Simple deduplication by title
    unique_tables = {}
    for t in session_tables:
        if not isinstance(t, dict):
            print(f"WARNING: Skipping invalid table entry: {t}")
            continue
        unique_tables[t['title']] = t # overwrites, keeping last occurrence
    
    final_tables = list(unique_tables.values())
    
    file_path = create_pdf(html_content, session_viz, final_tables)

    print(f"DEBUG: PDF Report saved to {file_path}")
    
    # 5. Return updates
    history.append({"role": "user", "content": "📑 Generate PDF Report"})
    if file_path:
        history.append({"role": "assistant", "content": f"**PDF Report Generated.**\n\nContains {len(session_viz)} visualizations and {len(final_tables)} data tables.\nDownload it using the button above."})
        return history, gr.update(value=file_path, visible=True)
    else:
        history.append({"role": "assistant", "content": "❌ **Error generating PDF report.**"})
        return history, gr.update(visible=False)

# ... (Auth Check Reuse) ...

# --- Launch ---
if __name__ == "__main__":
    # Session init is now handled by gr.State/init_session_state


    with gr.Blocks(theme=gr.themes.Default(), title="BigQuery Ops Agent") as demo:
        with gr.Row(elem_id="header_row"):
            gr.Image(os.path.join(os.path.dirname(__file__), "logo_bqops.png"), show_label=False, container=False, width=225, height=112,
                show_download_button=False, interactive=False, show_fullscreen_button=False, elem_id="logo_image_left")
            with gr.Column(scale=5):
                 gr.Markdown("# BigQuery Ops Agent", elem_id="header_title")
            with gr.Column(scale=1):
                 login_btn = gr.Button("Sign in with Google", link="/login/google", size="sm", visible=False)
                 logout_btn = gr.Button("Logout", link="/logout", size="sm", visible=False, variant="secondary")
                 toggle_btn = gr.Button("Maximize Chart", size="sm", visible=False) # Moved here
                 # Hidden LoginButton to ensure Gradio enables OAuth hooks if needed
                 gr.LoginButton(visible=False)
            
        demo.css = """
        #header_row { display: flex; align-items: center; }
        #header_title { flex-grow: 1; text-align: center; }
        #logo_image_left { flex-grow: 0; flex-shrink: 0; background: transparent !important; overflow: hidden; border-radius: 8px; }
        #logo_image_left img { object-fit: contain; }
        """

        with gr.Row():
            with gr.Column(scale=20) as chat_column:
                with gr.Row():
                    reset_btn = gr.Button("🔄 Reset Conversation", variant="secondary", size="sm")
                    gen_report_btn = gr.Button("📑 Generate PDF Report", variant="secondary", size="sm")
                    report_download_btn = gr.DownloadButton("Download PDF", visible=False, size="sm")
                
                chatbot = gr.Chatbot(label="Chat History", height=550, type="messages")
                with gr.Row(elem_id="chat_input_row"):
                    # show_label=False to allow perfect alignment with the Send button
                    msg_input = gr.Textbox(show_label=False, placeholder="Ask about costs, security, or performance...", scale=9)
                    send_btn = gr.Button("Send", variant="primary", scale=1)
                
                suggestion_dataset = gr.Dataset(
                    label="Follow-up Suggestions",
                    components=[msg_input],
                    samples=[],
                    visible=False
                )

                # Examples as a clickable Dataset (Optimized: Client-side JS update)
                example_prompts = [
                    ["Analyze my environment and give me overall suggestions"],
                    ["Check system for slot capacity saturation."],
                    ["Forecast our monthly costs based on recent usage trends."],
                    ["Identify tables with high Time Travel storage costs."],
                    ["Analyze recent heavy queries for anti-patterns and suggest optimization."],
                    ["Find active recommendations for partitioning and clustering."],
                    ["Find tables that haven't been queried in the last 180 days."],
                    ["Check for any datasets that are publicly exposed or have risky IAM policies."],
                    ["Show me a visualization of our hourly slot consumption."],
                    ["Which tables should switch to physical storage billing for cost savings?"],
                    ["Are there any materialized view recommendations?"],
                    ["Show top query errors from the last 7 days."]
                ]
                
                examples_dataset = gr.Dataset(
                    label="Example Prompts (Click to use)",
                    components=[msg_input],
                    samples=example_prompts
                )

            
            with gr.Column(scale=0, visible=False) as viz_column:
                plot_output = gr.Plot(label="Chart Analysis")
                image_output = gr.Image(label="Environment Dashboard", interactive=False)
                download_btn = gr.DownloadButton("Download CSV", visible=False)

        # Disclaimer
        gr.Markdown(
            "⚠️ **DISCLAIMER**: This is a community-managed agent for BigQuery Operations. "
            "It can give wrong results and hallucinate. The developer bears no responsibility for any consequences."
        )

        plot_visible_state = gr.State(value=False)
        session_viz = gr.State(value=[])
        session_tables = gr.State(value=[])
        session_state = gr.State(value={})

        # Updated Submit Event: Removed duplicate output viz_column
        # Trigger on Enter
        msg_input.submit(
            handle_chat_and_plot,
            [msg_input, chatbot, session_viz, session_tables, session_state],
            [
                msg_input, 
                chatbot, 
                plot_output, 
                image_output, 
                viz_column, # ONLY LISTED ONCE (handles both scale and visibility)
                chat_column, 
                plot_visible_state, 
                toggle_btn, 
                download_btn,
                suggestion_dataset,
                session_viz,
                session_tables
            ]
        )

        # Trigger on Send Button Click
        send_btn.click(
            handle_chat_and_plot,
            [msg_input, chatbot, session_viz, session_tables, session_state],
            [
                msg_input, 
                chatbot, 
                plot_output, 
                image_output, 
                viz_column, 
                chat_column, 
                plot_visible_state, 
                toggle_btn, 
                download_btn,
                suggestion_dataset,
                session_viz,
                session_tables
            ]
        )
        
        toggle_btn.click(toggle_plot_visibility, [plot_visible_state], [plot_visible_state, chat_column, viz_column, toggle_btn])
        
        # Use Python handler for robustness (JS was failing for user)
        # populate_input simply returns selection[0], which extracts the text from the dataset list
        suggestion_dataset.click(
            populate_input,
            inputs=[suggestion_dataset],
            outputs=[msg_input],
            show_progress="hidden"
        )
        
        examples_dataset.click(
            populate_input, 
            inputs=[examples_dataset], 
            outputs=[msg_input],
            show_progress="hidden"
        )
        
        # Updated Reset Event: Removed duplicate output viz_column
        reset_btn.click(
            reset_conversation, 
            [session_state], 
            [
                chatbot, 
                msg_input, 
                plot_output, 
                image_output, 
                viz_column, 
                chat_column, 
                plot_visible_state, 
                toggle_btn, 
                download_btn,
                suggestion_dataset,
                session_viz,
                session_tables
            ]
        )
        
        # Report Generation Event
        gen_report_btn.click(
            generate_pdf_report,
            inputs=[chatbot, session_viz, session_tables, session_state], 
            outputs=[chatbot, report_download_btn]
        )

        # Check auth status on load to toggle Login/Logout buttons
        demo.load(check_auth_status, None, [login_btn, logout_btn])
        
        # Init Session State on Load (Injects Request)
        demo.load(init_session_state, None, session_state)
    demo.queue().launch(server_name="localhost", server_port=7860)