# Manages context variables for storing and retrieving OAuth tokens and credentials.
import contextvars
from typing import Optional
import google.oauth2.credentials
import agent

_oauth_token_ctx = contextvars.ContextVar("_oauth_token_ctx", default=None)

def set_oauth_token(token: str):
    """Sets the OAuth token for the current context."""
    _oauth_token_ctx.set(token)

def get_oauth_token() -> Optional[str]:
    """Gets the OAuth token from the current context."""
    return _oauth_token_ctx.get()

def get_credentials() -> Optional[google.oauth2.credentials.Credentials]:
    """
    Returns Google Credentials object created from the stored OAuth token.
    Returns None if no token is set.
    """
    token = get_oauth_token()
    if token:
        # Create credentials with just the token
        # We MUST provide quota_project_id for user credentials to work with BQ API
        return google.oauth2.credentials.Credentials(
            token,
            quota_project_id=agent.QUOTA_PROJECT_ID
        )
    return None
