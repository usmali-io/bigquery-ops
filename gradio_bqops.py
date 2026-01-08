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
from PIL import Image as PILImage
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MONKEYPATCH: Debug Redirect URI
original_generate_redirect_uri = oauth._generate_redirect_uri

def debug_generate_redirect_uri(request: fastapi.Request) -> str:
    uri = original_generate_redirect_uri(request)
    # STRIP QUERY PARAMS: Google requires exact match. Gradio appends ?_target_url=...
    # We strip it to ensure it matches 'http://localhost:7860/login/callback'
    if "?" in uri:
        uri = uri.split("?")[0]
    print(f"\n[DEBUG] Cleaned Redirect URI: {uri}\n")
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
    print(f"DEBUG: Executing patched_add_oauth_routes for app: {app}")
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
        
        # Reset global session state to ensure backend session is also abandoned
        print(f"Logging out: Switching from {SESSION_STATE['session_id']} to new session.")
        SESSION_STATE["session_id"] = f"session_{uuid.uuid4()}"
        
        # Note: We don't strictly need to create it on the backend immediately; 
        # the next chat interaction or reset will handle it, or we can force it here.
        # But calling create_session_if_not_exists() here might be safer to ensure readiness.
        create_session_if_not_exists()
        
        return oauth._redirect_to_target(request)

# Apply the patch
oauth._add_oauth_routes = patched_add_oauth_routes
oauth._add_mocked_oauth_routes = patched_add_oauth_routes

# --- Configuration ---
ADK_SERVER_BASE_URL = os.getenv("ADK_SERVER_URL", "http://127.0.0.1:8000")
APP_NAME = "bqops"


# --- Session State ---
SESSION_STATE = {
    "session_id": f"session_{uuid.uuid4()}",
    "user_id": "gradio_user"
}

# --- Function to Create the Session on Startup ---
def create_session_if_not_exists():
    session_url = f"{ADK_SERVER_BASE_URL}/apps/{APP_NAME}/users/{SESSION_STATE['user_id']}/sessions/{SESSION_STATE['session_id']}"
    try:
        response = requests.post(session_url)
        if response.status_code not in [200, 404]: 
             response.raise_for_status()
    except Exception as e:
        print(f"Warning: Could not init session (server might be down): {e}")

# --- Helper: Reset Session ---
def reset_conversation():
    print("Resetting session...")
    SESSION_STATE["session_id"] = f"session_{uuid.uuid4()}"
    create_session_if_not_exists()
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
        gr.update(samples=[], visible=False)    # suggestion_dataset
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

    print(f"DEBUG: Scanning {len(agent_response_json)} messages for image...")
    
    # Use recursive search on the entire response object
    image_b64 = find_key_recursive(agent_response_json, 'dashboard_image_base64')
    
    if image_b64:
        print(f"DEBUG: Found 'dashboard_image_base64' (Length: {len(str(image_b64))})")
        return image_b64
    
    # Fallback
    legacy_image = find_key_recursive(agent_response_json, 'dashboard_image_file')
    if legacy_image and str(legacy_image).startswith("data:image"):
        print(f"DEBUG: Found legacy 'dashboard_image_file' (Length: {len(str(legacy_image))})")
        return legacy_image

    print("DEBUG: No image found after deep recursive search.")
    return None

# --- Main Function to Handle Chat and Plotting ---
def handle_chat_and_plot(message, history, profile: gr.OAuthProfile | None, token: gr.OAuthToken | None):
    print(f"Gradio client received: '{message}'")
    
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
        "user_id": SESSION_STATE["user_id"],
        "session_id": SESSION_STATE["session_id"],
        "new_message": {"role": "user", "parts": [{"text": message}]},
        "state_delta": state_delta
    }

    try:
        # Added timeout=300 (5 minutes) to prevent premature disconnection during long agent tasks
        response = requests.post(run_url, json=payload, timeout=300)
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
            gr.update(visible=False)
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
                print(f"DEBUG: Parsed {len(suggestion_samples)} suggestions.")
        except json.JSONDecodeError as e:
             # Handle partial JSON or extra data
             if "Extra data" in e.msg:
                 try:
                     raw_suggestions = json.loads(raw_text[:e.pos])
                     if isinstance(raw_suggestions, list):
                         suggestion_samples = [[str(s)] for s in raw_suggestions]
                 except:
                     print(f"DEBUG: JSON Fallback failed: {e}")
             else:
                 print(f"DEBUG: JSON Decode Error: {e}")
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
        return (
            "", history, plot_update, image_update, 
            gr.update(visible=True, scale=1), gr.update(scale=2), 
            False, toggle_btn_update, download_update,
            suggestion_update
        )
    else:
        return (
            "", history, gr.update(visible=False), gr.update(visible=False), 
            gr.update(visible=False, scale=0), gr.update(scale=20), 
            False, gr.update(visible=False), gr.update(value=None, visible=False),
            suggestion_update
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
    print(f"DEBUG: check_auth_status called. Username: {request.username if request else 'None'}")
    
    # Try getting user from session directly if request.username is empty
    user_info = None
    if request:
        try:
            session_data = request.session
            print(f"DEBUG: Session keys: {list(session_data.keys())}")
            if "oauth_info" in session_data:
                user_info = session_data["oauth_info"].get("userinfo", {})
                print(f"DEBUG: Found oauth_info. Email: {user_info.get('email')}")
        except Exception as e:
            print(f"DEBUG: Error accessing session: {e}")

    username = request.username if (request and request.username) else None
    if not username and user_info:
        username = user_info.get("email") or user_info.get("preferred_username")

    if username:
        # User is logged in
        user_label = f"Logout ({username})"
        return gr.update(visible=False), gr.update(value=user_label, visible=True)
    return gr.update(visible=True), gr.update(visible=False)

# --- Launch ---
if __name__ == "__main__":
    create_session_if_not_exists()

    with gr.Blocks(theme=gr.themes.Default(), title="BigQuery Ops Agent") as demo:
        with gr.Row(elem_id="header_row"):
            gr.Image("logo_bqops.png", show_label=False, container=False, width=225, height=112,
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
                
                chatbot = gr.Chatbot(label="Chat History", height=550, type="messages")
                msg_input = gr.Textbox(label="Message", placeholder="Ask about costs, security, or performance...")
                
                suggestion_dataset = gr.Dataset(
                    label="Follow-up Suggestions",
                    components=[msg_input],
                    samples=[],
                    visible=False
                )

                gr.Examples(
                    examples=[
                        "Analyze my environment and give me overall suggestions",
                        "Forecast our monthly costs based on recent usage trends.",
                        "Identify tables with high Time Travel storage costs.",
                        "Analyze recent heavy queries for anti-patterns and suggest optimization.",
                        "Find tables that haven't been queried in the last 180 days.",
                        "Check for any datasets that are publicly exposed.",
                        "Show me a visualization of our hourly slot consumption.",
                        "Which tables should switch to physical storage billing?"
                    ],
                    inputs=msg_input,
                    label="Example Prompts (Click to use)"
                )


            
            with gr.Column(scale=0, visible=False) as viz_column:
                plot_output = gr.Plot(label="Chart Analysis")
                image_output = gr.Image(label="Environment Dashboard", interactive=False)
                download_btn = gr.DownloadButton("Download CSV", visible=False)

        plot_visible_state = gr.State(value=False)

        # Updated Submit Event: Removed duplicate output viz_column
        msg_input.submit(
            handle_chat_and_plot,
            [msg_input, chatbot],
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
                suggestion_dataset
            ]
        )
        
        toggle_btn.click(toggle_plot_visibility, [plot_visible_state], [plot_visible_state, chat_column, viz_column, toggle_btn])
        
        # New Feature: Click to Auto-Submit Follow-ups
        suggestion_dataset.click(
            populate_input, 
            inputs=[suggestion_dataset], 
            outputs=[msg_input]
        ).then(
            handle_chat_and_plot,
            [msg_input, chatbot],
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
                suggestion_dataset
            ]
        )
        
        # Updated Reset Event: Removed duplicate output viz_column
        reset_btn.click(
            reset_conversation, 
            [], 
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
                suggestion_dataset
            ]
        )

        # Check auth status on load to toggle Login/Logout buttons
        demo.load(check_auth_status, None, [login_btn, logout_btn])

    demo.queue().launch(server_name="0.0.0.0", server_port=7860)
