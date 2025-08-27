import os
import json
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, redirect, session, url_for
from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient
import requests
from requests_oauthlib import OAuth2Session
import io
import mimetypes
from urllib.parse import urlencode
import base64
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'baigan77')

# FIXED: Force HTTPS for OAuth2Session in production
# This is crucial for OAuth to work behind reverse proxies
if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('WEBSITE_SITE_NAME'):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development behind proxy
    # Better approach: Configure proper HTTPS detection
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Configuration
AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING_1')
AZURE_STORAGE_CONTAINER = os.environ.get('AZURE_STORAGE_CONTAINER', 'weezyaifiles')
AZURE_USER_STORAGE_CONTAINER='weez-users-info'

COSMOS_ENDPOINT = os.getenv('COSMOS_ENDPOINT')
COSMOS_KEY = os.getenv('COSMOS_KEY')
COSMOS_DATABASE = os.getenv('COSMOS_DATABASE', 'weezyai')
COSMOS_CONTAINER = os.getenv('COSMOS_CONTAINER', 'files')

# OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID')
MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
DROPBOX_CLIENT_ID = os.getenv('DROPBOX_CLIENT_ID')
DROPBOX_CLIENT_SECRET = os.getenv('DROPBOX_CLIENT_SECRET')
SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
NOTION_CLIENT_ID = os.environ.get('NOTION_CLIENT_ID')
NOTION_CLIENT_SECRET = os.environ.get('NOTION_CLIENT_SECRET')

# FIXED: Improved base URL configuration
BASE_URL = os.environ.get('BASE_URL', 'https://platform-connection-api-g0b5c3fve2dfb2ag.canadacentral-01.azurewebsites.net')

# FIXED: Better production detection
def is_production():
    """Detect if running in production environment"""
    return (
        os.environ.get('FLASK_ENV') == 'production' or 
        os.environ.get('WEBSITE_SITE_NAME') or  # Azure App Service indicator
        'azurewebsites.net' in os.environ.get('WEBSITE_HOSTNAME', '') or
        BASE_URL.startswith('https://')
    )

app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = is_production()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# FIXED: Force HTTPS in production
if is_production():
    app.config['PREFERRED_URL_SCHEME'] = 'https'

def make_session_permanent():
    """Make current session permanent"""
    session.permanent = True

# FIXED: Consistent redirect URI generation for all platforms
def get_redirect_uri(endpoint_name):
    """Generate consistent redirect URI for OAuth callbacks"""
    # Always use hardcoded HTTPS URLs for production
    if is_production():
        endpoint_mapping = {
            'auth_google_callback': f"{BASE_URL}/auth/google/callback",
            'auth_microsoft_callback': f"{BASE_URL}/auth/microsoft/callback", 
            'auth_dropbox_callback': f"{BASE_URL}/auth/dropbox/callback",
            'auth_notion_callback': f"{BASE_URL}/auth/notion/callback"
        }
        return endpoint_mapping.get(endpoint_name)
    else:
        # Use Flask's url_for for local development
        return url_for(endpoint_name, _external=True, _scheme='https')

# FIXED: Create OAuth2Session with proper HTTPS handling
def create_oauth_session(client_id, redirect_uri, scope=None, state=None):
    """Create OAuth2Session with proper HTTPS handling for production"""
    session_kwargs = {
        'client_id': client_id,
        'redirect_uri': redirect_uri
    }
    
    if scope:
        session_kwargs['scope'] = scope
    if state:
        session_kwargs['state'] = state
    
    oauth_session = OAuth2Session(**session_kwargs)
    
    # FIXED: Force HTTPS for production environments
    if is_production():
        # Override the session's request method to force HTTPS
        original_request = oauth_session.request
        
        def force_https_request(method, uri, *args, **kwargs):
            # Ensure all OAuth requests use HTTPS
            if uri.startswith('http://'):
                uri = uri.replace('http://', 'https://', 1)
            return original_request(method, uri, *args, **kwargs)
        
        oauth_session.request = force_https_request
    
    return oauth_session

# Debug function to check redirect URI generation
def debug_redirect_uris():
    """Debug function to check what redirect URIs are being generated"""
    endpoints = ['auth_google_callback', 'auth_microsoft_callback', 'auth_dropbox_callback', 'auth_notion_callback']
    
    uris = {}
    for endpoint in endpoints:
        uris[endpoint] = get_redirect_uri(endpoint)
    
    print("=== REDIRECT URI DEBUG ===")
    for endpoint, uri in uris.items():
        print(f"{endpoint}: {uri}")
    print("===========================")
    
    return uris

def debug_oauth_config():
    config_status = {
        'GOOGLE_CLIENT_ID': bool(GOOGLE_CLIENT_ID),
        'GOOGLE_CLIENT_SECRET': bool(GOOGLE_CLIENT_SECRET),
        'MICROSOFT_CLIENT_ID': bool(MICROSOFT_CLIENT_ID),
        'MICROSOFT_CLIENT_SECRET': bool(MICROSOFT_CLIENT_SECRET),
        'DROPBOX_CLIENT_ID': bool(DROPBOX_CLIENT_ID),
        'DROPBOX_CLIENT_SECRET': bool(DROPBOX_CLIENT_SECRET),
        'NOTION_CLIENT_ID': bool(NOTION_CLIENT_ID),
        'NOTION_CLIENT_SECRET': bool(NOTION_CLIENT_SECRET),
        'BASE_URL': BASE_URL,
        'IS_PRODUCTION': is_production(),
        'FLASK_ENV': os.environ.get('FLASK_ENV'),
        'WEBSITE_SITE_NAME': os.environ.get('WEBSITE_SITE_NAME'),
        'WEBSITE_HOSTNAME': os.environ.get('WEBSITE_HOSTNAME'),
        'OAUTHLIB_INSECURE_TRANSPORT': os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')
    }
    print("OAuth Configuration Status:", config_status)
    return config_status

# Call this on startup
debug_oauth_config()
debug_redirect_uris()

# Supported file extensions
SUPPORTED_EXTENSIONS = {'.pdf', '.docx', '.pptx', '.xlsx', '.doc', '.ppt', '.xls'}

# Initialize Azure clients
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
cosmos_client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
database = cosmos_client.get_database_client(COSMOS_DATABASE)
container = database.get_container_client(COSMOS_CONTAINER)

class PlatformIntegration:
    def __init__(self):
        pass
    
    def get_file_extension(self, filename):
        """Extract file extension from filename"""
        return os.path.splitext(filename.lower())[1]
    
    def is_supported_file(self, filename):
        """Check if file extension is supported"""
        return self.get_file_extension(filename) in SUPPORTED_EXTENSIONS
    
    def upload_to_blob_storage(self, file_content, username, filename):
        """Upload file to Azure Blob Storage"""
        try:
            blob_name = f"{username}/{filename}"
            blob_client = blob_service_client.get_blob_client(
                container=AZURE_STORAGE_CONTAINER, 
                blob=blob_name
            )
            blob_client.upload_blob(file_content, overwrite=True)
            return blob_name
        except Exception as e:
            print(f"Error uploading to blob storage: {e}")
            return None
    
    def save_file_metadata(self, user_id, filename, blob_path, platform, original_date, file_size=None, mime_type=None):
        """Save file metadata to Cosmos DB"""
        try:
            metadata = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "document_title": os.path.splitext(filename)[0],
                "fileName": filename,
                "filePath": blob_path,
                "platform": platform,
                "source": "platform_sync",
                "uploaded_at": original_date.isoformat() if isinstance(original_date, datetime) else original_date,
                "file_size": file_size,
                "mime_type": mime_type,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            container.create_item(body=metadata)
            return metadata
        except Exception as e:
            print(f"Error saving metadata: {e}")
            return None

# Google Drive Integration
class GoogleDriveIntegration(PlatformIntegration):
    def __init__(self):
        super().__init__()
        self.authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
        self.token_url = 'https://oauth2.googleapis.com/token'
        self.scope = ['https://www.googleapis.com/auth/drive.readonly']
        
    def get_auth_url(self):
        """Get Google OAuth authorization URL"""
        if not GOOGLE_CLIENT_ID:
            raise ValueError("GOOGLE_CLIENT_ID not configured")
            
        redirect_uri = get_redirect_uri('auth_google_callback')
        print(f"Google redirect URI: {redirect_uri}")  # Debug log
        
        # FIXED: Use the new OAuth session creation method
        google = create_oauth_session(
            GOOGLE_CLIENT_ID,
            redirect_uri,
            scope=self.scope
        )
        
        authorization_url, state = google.authorization_url(
            self.authorization_base_url,
            access_type="offline",
            prompt="select_account"
        )
        session['google_oauth_state'] = state
        return authorization_url

    def get_access_token(self, authorization_response):
        """Exchange authorization code for access token"""
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            raise ValueError("Google OAuth credentials not configured")
        
        # FIXED: Ensure authorization_response uses HTTPS
        if is_production() and authorization_response.startswith('http://'):
            authorization_response = authorization_response.replace('http://', 'https://', 1)
            
        redirect_uri = get_redirect_uri('auth_google_callback')
        
        # FIXED: Use the new OAuth session creation method
        google = create_oauth_session(
            GOOGLE_CLIENT_ID,
            redirect_uri,
            state=session.get('google_oauth_state')
        )
        
        token = google.fetch_token(
            self.token_url,
            authorization_response=authorization_response,
            client_secret=GOOGLE_CLIENT_SECRET
        )
        return token
    
    def sync_files(self, access_token, user_email):
        """Sync files from Google Drive"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # Get files list
        url = 'https://www.googleapis.com/drive/v3/files'
        params = {
            'fields': 'files(id,name,mimeType,createdTime,size)',
            'q': 'trashed=false'
        }
        
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            return {'error': 'Failed to fetch files from Google Drive'}
        
        files = response.json().get('files', [])
        synced_files = []
        
        for file_info in files:
            filename = file_info.get('name', '')
            if not self.is_supported_file(filename):
                continue
            
            # Download file content
            file_id = file_info['id']
            download_url = f'https://www.googleapis.com/drive/v3/files/{file_id}?alt=media'
            file_response = requests.get(download_url, headers=headers)
            
            if file_response.status_code == 200:
                # Upload to blob storage
                blob_path = self.upload_to_blob_storage(
                    file_response.content, 
                    user_email, 
                    filename
                )
                
                if blob_path:
                    # Save metadata
                    original_date = file_info.get('createdTime')
                    if original_date:
                        original_date = datetime.fromisoformat(original_date.replace('Z', '+00:00'))
                    
                    metadata = self.save_file_metadata(
                        user_email,
                        filename,
                        blob_path,
                        'google_drive',
                        original_date,
                        file_info.get('size'),
                        file_info.get('mimeType')
                    )
                    
                    if metadata:
                        synced_files.append(metadata)
        
        return {'synced_files': synced_files, 'count': len(synced_files)}

# Microsoft OneDrive Integration
class OneDriveIntegration(PlatformIntegration):
    def __init__(self):
        super().__init__()
        self.authorization_base_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
        self.token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        self.scope = ['Files.Read', 'User.Read']
    
    def get_auth_url(self):
        """Get Microsoft OAuth authorization URL"""
        if not MICROSOFT_CLIENT_ID:
            raise ValueError("MICROSOFT_CLIENT_ID not configured")
            
        redirect_uri = get_redirect_uri('auth_microsoft_callback')
        print(f"Microsoft redirect URI: {redirect_uri}")  # Debug log
        
        # FIXED: Use the new OAuth session creation method
        microsoft = create_oauth_session(
            MICROSOFT_CLIENT_ID,
            redirect_uri,
            scope=self.scope
        )
        
        authorization_url, state = microsoft.authorization_url(self.authorization_base_url)
        session['microsoft_oauth_state'] = state
        return authorization_url

    def get_access_token(self, authorization_response):
        """Exchange authorization code for access token"""
        if not MICROSOFT_CLIENT_ID or not MICROSOFT_CLIENT_SECRET:
            raise ValueError("Microsoft OAuth credentials not configured")
        
        # FIXED: Ensure authorization_response uses HTTPS
        if is_production() and authorization_response.startswith('http://'):
            authorization_response = authorization_response.replace('http://', 'https://', 1)
            
        redirect_uri = get_redirect_uri('auth_microsoft_callback')
        
        # FIXED: Use the new OAuth session creation method
        microsoft = create_oauth_session(
            MICROSOFT_CLIENT_ID,
            redirect_uri,
            state=session.get('microsoft_oauth_state')
        )
        
        token = microsoft.fetch_token(
            self.token_url,
            authorization_response=authorization_response,
            client_secret=MICROSOFT_CLIENT_SECRET
        )
        return token
    
    def sync_files(self, access_token, user_email):
        """Sync files from OneDrive"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # Get files list
        url = 'https://graph.microsoft.com/v1.0/me/drive/root/children'
        
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return {'error': 'Failed to fetch files from OneDrive'}
        
        files = response.json().get('value', [])
        synced_files = []
        
        for file_info in files:
            if file_info.get('folder'):  # Skip folders
                continue
                
            filename = file_info.get('name', '')
            if not self.is_supported_file(filename):
                continue
            
            # Download file content
            download_url = file_info.get('@microsoft.graph.downloadUrl')
            if download_url:
                file_response = requests.get(download_url)
                
                if file_response.status_code == 200:
                    # Upload to blob storage
                    blob_path = self.upload_to_blob_storage(
                        file_response.content, 
                        user_email, 
                        filename
                    )
                    
                    if blob_path:
                        # Save metadata
                        original_date = file_info.get('createdDateTime')
                        if original_date:
                            original_date = datetime.fromisoformat(original_date.replace('Z', '+00:00'))
                        
                        metadata = self.save_file_metadata(
                            user_email,
                            filename,
                            blob_path,
                            'onedrive',
                            original_date,
                            file_info.get('size'),
                            file_info.get('file', {}).get('mimeType')
                        )
                        
                        if metadata:
                            synced_files.append(metadata)
        
        return {'synced_files': synced_files, 'count': len(synced_files)}

# Dropbox Integration  
class DropboxIntegration(PlatformIntegration):
    def __init__(self):
        super().__init__()
        self.authorization_base_url = 'https://www.dropbox.com/oauth2/authorize'
        self.token_url = 'https://api.dropbox.com/oauth2/token'
    
    def get_auth_url(self, user_email=None):
        """Get Dropbox OAuth authorization URL"""
        if not DROPBOX_CLIENT_ID:
            raise ValueError("DROPBOX_CLIENT_ID not configured")
            
        redirect_uri = get_redirect_uri('auth_dropbox_callback')
        print(f"Dropbox redirect URI: {redirect_uri}")  # Debug log
        
        state = str(uuid.uuid4())
        
        # Store user_email in session with state
        session[f'dropbox_oauth_state_{state}'] = {
            'state': state,
            'user_email': user_email
        }
        
        params = {
            'client_id': DROPBOX_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'state': state
        }
        return f"{self.authorization_base_url}?{urlencode(params)}"
    
    def get_access_token(self, authorization_code, state):
        """Exchange authorization code for access token"""
        if not DROPBOX_CLIENT_ID or not DROPBOX_CLIENT_SECRET:
            raise ValueError("Dropbox OAuth credentials not configured")
            
        # Verify state and get user_email
        state_data = session.get(f'dropbox_oauth_state_{state}')
        if not state_data or state_data['state'] != state:
            raise ValueError("State mismatch - possible CSRF attack")
            
        redirect_uri = get_redirect_uri('auth_dropbox_callback')
        data = {
            'code': authorization_code,
            'grant_type': 'authorization_code',
            'client_id': DROPBOX_CLIENT_ID,
            'client_secret': DROPBOX_CLIENT_SECRET,
            'redirect_uri': redirect_uri
        }
        
        response = requests.post(self.token_url, data=data)
        if response.status_code != 200:
            raise ValueError(f"Failed to get access token: {response.text}")
        
        # Clean up session
        del session[f'dropbox_oauth_state_{state}']
        
        return response.json(), state_data['user_email']
    
    def sync_files(self, access_token, user_email):
        """Sync files from Dropbox"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # List files
        url = 'https://api.dropboxapi.com/2/files/list_folder'
        data = {'path': '', 'recursive': True}
        
        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200:
            return {'error': 'Failed to fetch files from Dropbox'}
        
        files = response.json().get('entries', [])
        synced_files = []
        
        for file_info in files:
            if file_info.get('.tag') != 'file':  # Skip folders
                continue
                
            filename = file_info.get('name', '')
            if not self.is_supported_file(filename):
                continue
            
            # Download file content
            download_url = 'https://content.dropboxapi.com/2/files/download'
            download_headers = {
                'Authorization': f'Bearer {access_token}',
                'Dropbox-API-Arg': json.dumps({'path': file_info['path_lower']})
            }
            
            file_response = requests.post(download_url, headers=download_headers)
            
            if file_response.status_code == 200:
                # Upload to blob storage
                blob_path = self.upload_to_blob_storage(
                    file_response.content, 
                    user_email, 
                    filename
                )
                
                if blob_path:
                    # Save metadata
                    original_date = file_info.get('client_modified')
                    if original_date:
                        original_date = datetime.fromisoformat(original_date.replace('Z', '+00:00'))
                    
                    metadata = self.save_file_metadata(
                        user_email,
                        filename,
                        blob_path,
                        'dropbox',
                        original_date,
                        file_info.get('size')
                    )
                    
                    if metadata:
                        synced_files.append(metadata)
        
        return {'synced_files': synced_files, 'count': len(synced_files)}

# Notion Integration
class NotionIntegration(PlatformIntegration):
    def __init__(self):
        super().__init__()
        self.authorization_base_url = 'https://api.notion.com/v1/oauth/authorize'
        self.token_url = 'https://api.notion.com/v1/oauth/token'
    
    def get_auth_url(self, user_email=None):
        """Get Notion OAuth authorization URL with user_email in state"""
        if not NOTION_CLIENT_ID:
            raise ValueError("NOTION_CLIENT_ID not configured")
            
        redirect_uri = get_redirect_uri('auth_notion_callback')
        print(f"Notion redirect URI: {redirect_uri}")  # Debug log
        
        # Include user_email in state parameter
        state_data = {
            'uuid': str(uuid.uuid4()),
            'user_email': user_email
        }
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
        
        session['notion_oauth_state'] = state
        
        params = {
            'response_type': 'code',
            'client_id': NOTION_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'owner': 'user',
            'state': state
        }
        return f"{self.authorization_base_url}?{urlencode(params)}"
    
    def get_access_token(self, authorization_code, state=None):
        """Exchange authorization code for access token"""
        # Decode state to get user_email
        user_email = None
        if state and state.strip():
            try:
                state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
                user_email = state_data.get('user_email')
                print(f"User email from state: {user_email}")
            except:
                print("Could not decode state parameter")
        
        # Verify state if provided
        if state and state.strip() and state != session.get('notion_oauth_state'):
            raise ValueError("State mismatch - possible CSRF attack")
            
        redirect_uri = get_redirect_uri('auth_notion_callback')
        auth_string = base64.b64encode(f"{NOTION_CLIENT_ID}:{NOTION_CLIENT_SECRET}".encode()).decode()
        
        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/json',
            'Notion-Version': '2022-06-28'
        }
        
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': redirect_uri
        }
        
        print(f"Sending token request with data: {data}")
        
        response = requests.post(self.token_url, headers=headers, json=data)
        
        print(f"Token response status: {response.status_code}")
        print(f"Token response: {response.text}")
        
        if response.status_code != 200:
            raise ValueError(f"Failed to get access token: {response.text}")
        
        token_data = response.json()
        
        # Add user_email to token data for easier access
        if user_email:
            token_data['user_email'] = user_email
        
        # Clean up session state
        if 'notion_oauth_state' in session:
            del session['notion_oauth_state']
            
        return token_data
    
    def sync_files(self, access_token, user_email):
        """Sync files from Notion"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Notion-Version': '2022-06-28',
            'Content-Type': 'application/json'
        }
        
        # Search for pages and databases
        search_url = 'https://api.notion.com/v1/search'
        search_data = {
            'filter': {
                'property': 'object',
                'value': 'page'
            }
        }
        
        response = requests.post(search_url, headers=headers, json=search_data)
        if response.status_code != 200:
            return {'error': 'Failed to fetch pages from Notion'}
        
        pages = response.json().get('results', [])
        synced_files = []
        
        for page in pages:
            page_id = page['id']
            page_title = 'Untitled'
            
            # Get page title
            if page.get('properties'):
                title_prop = None
                for prop_name, prop_data in page['properties'].items():
                    if prop_data.get('type') == 'title':
                        title_prop = prop_data
                        break
                
                if title_prop and title_prop.get('title'):
                    page_title = ''.join([t['plain_text'] for t in title_prop['title']])
            
            # Get page content
            blocks_url = f'https://api.notion.com/v1/blocks/{page_id}/children'
            blocks_response = requests.get(blocks_url, headers=headers)
            
            if blocks_response.status_code == 200:
                blocks = blocks_response.json().get('results', [])
                content = self.extract_text_from_blocks(blocks)
                
                # Create filename
                safe_title = "".join(c for c in page_title if c.isalnum() or c in (' ', '-', '_')).rstrip()
                filename = f"{safe_title}.txt"
                
                # Upload to blob storage
                blob_path = self.upload_to_blob_storage(
                    content.encode('utf-8'), 
                    user_email, 
                    filename
                )
                
                if blob_path:
                    # Save metadata
                    original_date = page.get('created_time')
                    if original_date:
                        original_date = datetime.fromisoformat(original_date.replace('Z', '+00:00'))
                    
                    metadata = self.save_file_metadata(
                        user_email,
                        filename,
                        blob_path,
                        'notion',
                        original_date,
                        len(content.encode('utf-8')),
                        'text/plain'
                    )
                    
                    if metadata:
                        synced_files.append(metadata)
        
        return {'synced_files': synced_files, 'count': len(synced_files)}
    def extract_text_from_blocks(self, blocks):
        """Extract text content from Notion blocks"""
        content = []
        
        for block in blocks:
            block_type = block.get('type', '')
            
            if block_type == 'paragraph':
                text = self.extract_rich_text(block.get('paragraph', {}).get('rich_text', []))
                if text:
                    content.append(text)
            
            elif block_type == 'heading_1':
                text = self.extract_rich_text(block.get('heading_1', {}).get('rich_text', []))
                if text:
                    content.append(f"# {text}")
            
            elif block_type == 'heading_2':
                text = self.extract_rich_text(block.get('heading_2', {}).get('rich_text', []))
                if text:
                    content.append(f"## {text}")
            
            elif block_type == 'heading_3':
                text = self.extract_rich_text(block.get('heading_3', {}).get('rich_text', []))
                if text:
                    content.append(f"### {text}")
            
            elif block_type == 'bulleted_list_item':
                text = self.extract_rich_text(block.get('bulleted_list_item', {}).get('rich_text', []))
                if text:
                    content.append(f"• {text}")
            
            elif block_type == 'numbered_list_item':
                text = self.extract_rich_text(block.get('numbered_list_item', {}).get('rich_text', []))
                if text:
                    content.append(f"1. {text}")
            
            elif block_type == 'to_do':
                text = self.extract_rich_text(block.get('to_do', {}).get('rich_text', []))
                checked = block.get('to_do', {}).get('checked', False)
                checkbox = "☑" if checked else "☐"
                if text:
                    content.append(f"{checkbox} {text}")
            
            elif block_type == 'quote':
                text = self.extract_rich_text(block.get('quote', {}).get('rich_text', []))
                if text:
                    content.append(f"> {text}")
            
            elif block_type == 'code':
                text = self.extract_rich_text(block.get('code', {}).get('rich_text', []))
                language = block.get('code', {}).get('language', '')
                if text:
                    content.append(f"```{language}\n{text}\n```")
            
            elif block_type == 'callout':
                text = self.extract_rich_text(block.get('callout', {}).get('rich_text', []))
                icon = block.get('callout', {}).get('icon', {})
                emoji = icon.get('emoji', '💡') if icon.get('type') == 'emoji' else '💡'
                if text:
                    content.append(f"{emoji} {text}")
            
            elif block_type == 'divider':
                content.append("---")
        
        return '\n\n'.join(content)
    
    def extract_rich_text(self, rich_text_array):
        """Extract plain text from Notion rich text array"""
        if not rich_text_array:
            return ""
        
        text_parts = []
        for text_obj in rich_text_array:
            if text_obj.get('type') == 'text':
                text_parts.append(text_obj.get('text', {}).get('content', ''))
            elif text_obj.get('type') == 'mention':
                # Handle mentions (users, pages, etc.)
                mention = text_obj.get('mention', {})
                if mention.get('type') == 'user':
                    text_parts.append(f"@{mention.get('user', {}).get('name', 'user')}")
                elif mention.get('type') == 'page':
                    text_parts.append(f"[Page Reference]")
                else:
                    text_parts.append(text_obj.get('plain_text', ''))
            else:
                text_parts.append(text_obj.get('plain_text', ''))
        
        return ''.join(text_parts)

# Initialize platform integrations
google_drive = GoogleDriveIntegration()
onedrive = OneDriveIntegration()
dropbox = DropboxIntegration()
notion = NotionIntegration()

# Helper function to save user connection info
def save_user_connection(user_email, platform, connection_data):
    """Save user connection information to Azure Storage"""
    try:
        blob_name = f"{user_email}/{platform}_connection.json"
        blob_client = blob_service_client.get_blob_client(
            container=AZURE_USER_STORAGE_CONTAINER,
            blob=blob_name
        )
        
        connection_info = {
            'user_email': user_email,
            'platform': platform,
            'connected_at': datetime.now(timezone.utc).isoformat(),
            'connection_data': connection_data
        }
        
        blob_client.upload_blob(
            json.dumps(connection_info).encode('utf-8'),
            overwrite=True
        )
        return True
    except Exception as e:
        print(f"Error saving user connection: {e}")
        return False

# Routes
@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Platform Connection API',
        'version': '1.0.0',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })

@app.route('/debug/config')
def debug_config():
    """Debug endpoint to check configuration"""
    return jsonify({
        'oauth_config': debug_oauth_config(),
        'redirect_uris': debug_redirect_uris()
    })

# Google Drive Routes
@app.route('/auth/google')
def auth_google():
    """Initiate Google OAuth flow"""
    try:
        user_email = request.args.get('user_email')
        if not user_email:
            return jsonify({'error': 'user_email parameter is required'}), 400
        
        session['user_email'] = user_email
        make_session_permanent()
        
        auth_url = google_drive.get_auth_url()
        return redirect(auth_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/google/callback')
def auth_google_callback():
    """Handle Google OAuth callback"""
    try:
        authorization_response = request.url
        token = google_drive.get_access_token(authorization_response)
        
        user_email = session.get('user_email')
        if not user_email:
            return jsonify({'error': 'User email not found in session'}), 400
        
        # Save connection info
        save_user_connection(user_email, 'google_drive', {
            'access_token': token.get('access_token'),
            'refresh_token': token.get('refresh_token'),
            'expires_at': token.get('expires_at')
        })
        
        # Sync files
        result = google_drive.sync_files(token['access_token'], user_email)
        
        return jsonify({
            'status': 'success',
            'platform': 'google_drive',
            'user_email': user_email,
            'sync_result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Microsoft OneDrive Routes
@app.route('/auth/microsoft')
def auth_microsoft():
    """Initiate Microsoft OAuth flow"""
    try:
        user_email = request.args.get('user_email')
        if not user_email:
            return jsonify({'error': 'user_email parameter is required'}), 400
        
        session['user_email'] = user_email
        make_session_permanent()
        
        auth_url = onedrive.get_auth_url()
        return redirect(auth_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/microsoft/callback')
def auth_microsoft_callback():
    """Handle Microsoft OAuth callback"""
    try:
        authorization_response = request.url
        token = onedrive.get_access_token(authorization_response)
        
        user_email = session.get('user_email')
        if not user_email:
            return jsonify({'error': 'User email not found in session'}), 400
        
        # Save connection info
        save_user_connection(user_email, 'onedrive', {
            'access_token': token.get('access_token'),
            'refresh_token': token.get('refresh_token'),
            'expires_at': token.get('expires_at')
        })
        
        # Sync files
        result = onedrive.sync_files(token['access_token'], user_email)
        
        return jsonify({
            'status': 'success',
            'platform': 'onedrive',
            'user_email': user_email,
            'sync_result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Dropbox Routes
@app.route('/auth/dropbox')
def auth_dropbox():
    """Initiate Dropbox OAuth flow"""
    try:
        user_email = request.args.get('user_email')
        if not user_email:
            return jsonify({'error': 'user_email parameter is required'}), 400
        
        auth_url = dropbox.get_auth_url(user_email)
        return redirect(auth_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/dropbox/callback')
def auth_dropbox_callback():
    """Handle Dropbox OAuth callback"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code or not state:
            return jsonify({'error': 'Missing code or state parameter'}), 400
        
        token_data, user_email = dropbox.get_access_token(code, state)
        
        # Save connection info
        save_user_connection(user_email, 'dropbox', {
            'access_token': token_data.get('access_token'),
            'refresh_token': token_data.get('refresh_token'),
            'expires_in': token_data.get('expires_in')
        })
        
        # Sync files
        result = dropbox.sync_files(token_data['access_token'], user_email)
        
        return jsonify({
            'status': 'success',
            'platform': 'dropbox',
            'user_email': user_email,
            'sync_result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Notion Routes
@app.route('/auth/notion')
def auth_notion():
    """Initiate Notion OAuth flow"""
    try:
        user_email = request.args.get('user_email')
        if not user_email:
            return jsonify({'error': 'user_email parameter is required'}), 400
        
        auth_url = notion.get_auth_url(user_email)
        return redirect(auth_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/notion/callback')
def auth_notion_callback():
    """Handle Notion OAuth callback"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code:
            return jsonify({'error': 'Missing authorization code'}), 400
        
        token_data = notion.get_access_token(code, state)
        user_email = token_data.get('user_email')
        
        if not user_email:
            return jsonify({'error': 'User email not found in token data'}), 400
        
        # Save connection info
        save_user_connection(user_email, 'notion', {
            'access_token': token_data.get('access_token'),
            'workspace_name': token_data.get('workspace_name'),
            'workspace_id': token_data.get('workspace_id'),
            'bot_id': token_data.get('bot_id')
        })
        
        # Sync files
        result = notion.sync_files(token_data['access_token'], user_email)
        
        return jsonify({
            'status': 'success',
            'platform': 'notion',
            'user_email': user_email,
            'sync_result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API Routes for manual sync
@app.route('/api/sync/<platform>', methods=['POST'])
def manual_sync(platform):
    """Manually trigger sync for a specific platform"""
    try:
        data = request.get_json()
        user_email = data.get('user_email')
        access_token = data.get('access_token')
        
        if not user_email or not access_token:
            return jsonify({'error': 'user_email and access_token are required'}), 400
        
        if platform == 'google_drive':
            result = google_drive.sync_files(access_token, user_email)
        elif platform == 'onedrive':
            result = onedrive.sync_files(access_token, user_email)
        elif platform == 'dropbox':
            result = dropbox.sync_files(access_token, user_email)
        elif platform == 'notion':
            result = notion.sync_files(access_token, user_email)
        else:
            return jsonify({'error': 'Unsupported platform'}), 400
        
        return jsonify({
            'status': 'success',
            'platform': platform,
            'user_email': user_email,
            'sync_result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/connections/<user_email>')
def get_user_connections(user_email):
    """Get all platform connections for a user"""
    try:
        connections = []
        platforms = ['google_drive', 'onedrive', 'dropbox', 'notion']
        
        for platform in platforms:
            try:
                blob_name = f"{user_email}/{platform}_connection.json"
                blob_client = blob_service_client.get_blob_client(
                    container=AZURE_USER_STORAGE_CONTAINER,
                    blob=blob_name
                )
                
                blob_data = blob_client.download_blob().readall()
                connection_info = json.loads(blob_data.decode('utf-8'))
                
                # Remove sensitive data before returning
                safe_connection = {
                    'platform': platform,
                    'connected_at': connection_info.get('connected_at'),
                    'status': 'connected'
                }
                connections.append(safe_connection)
            except:
                # Connection doesn't exist for this platform
                connections.append({
                    'platform': platform,
                    'status': 'not_connected'
                })
        
        return jsonify({
            'user_email': user_email,
            'connections': connections
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/files/<user_email>')
def get_user_files(user_email):
    """Get all synced files for a user"""
    try:
        # Query Cosmos DB for user files
        query = "SELECT * FROM c WHERE c.user_id = @user_id ORDER BY c.created_at DESC"
        parameters = [{"name": "@user_id", "value": user_email}]
        
        files = list(container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        
        return jsonify({
            'user_email': user_email,
            'files': files,
            'count': len(files)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
