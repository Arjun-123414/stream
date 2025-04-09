import os
import uuid
import json
import datetime
import time
from datetime import timezone
import pandas as pd
from sqlalchemy import create_engine, text
from snowflake.sqlalchemy import URL
from dotenv import load_dotenv
from models import SessionLocal, QueryResult  # Also import ChatHistory from models
from models import ChatHistory  # Make sure ChatHistory is imported
from query_correction import enhance_query_correction, extract_query_components, \
    format_professional_suggestion
from snowflake_utils2 import query_snowflake, get_schema_details
from groq_utils2 import get_groq_response
from action_utils import parse_action_response, execute_action
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from PIL import Image
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# ------------------------
# Constants for Autosave
# ------------------------
AUTOSAVE_ENABLED = True
AUTOSAVE_INTERVAL = 60  # Backup save every 60 seconds (in case immediate save fails)
IMMEDIATE_SAVE_ENABLED = True  # Enable saving after each Q&A exchange

# ------------------------
# 1. Load environment vars
# ------------------------
load_dotenv()

# ------------------------
# 2. Streamlit configuration
# ------------------------
st.set_page_config(
    page_title="❄️ AI Data Assistant ❄️ ",
    page_icon="❄️",
    layout="wide"
)


# Apply custom CSS
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


local_css("style.css")


# ------------------------
# 3. Helper: get Snowflake private key
# ------------------------
def get_private_key_str():
    private_key_content = os.getenv("SNOWFLAKE_PRIVATE_KEY")
    if private_key_content:
        private_key_obj = serialization.load_pem_private_key(
            private_key_content.encode(),
            password=None,
            backend=default_backend()
        )
        der_private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(der_private_key).decode('utf-8')
    else:
        raise ValueError("Private key not found in environment variables")


# ------------------------
# 4. Connect to Snowflake
# ------------------------
def get_snowflake_connection():
    return create_engine(URL(
        account=os.getenv("SNOWFLAKE_ACCOUNT"),
        user=os.getenv("SNOWFLAKE_USER"),
        private_key=get_private_key_str(),
        database=os.getenv("SNOWFLAKE_DATABASE"),
        schema=os.getenv("SNOWFLAKE_SCHEMA"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        role=os.getenv("SNOWFLAKE_ROLE")
    ))


# ------------------------
# 5. User Authentication
# ------------------------
def authenticate_user(email, password):
    if not email.endswith("@ahs.com"):
        return False
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("SELECT COUNT(*) FROM UserPasswordName WHERE username = :email AND password = :password")
        result = conn.execute(query, {"email": email, "password": password}).fetchone()
        return result[0] > 0


def needs_password_change(email):
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("SELECT initial FROM UserPasswordName WHERE username = :email")
        result = conn.execute(query, {"email": email}).fetchone()
        return result[0] if result else False


def update_password(email, new_password):
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("UPDATE UserPasswordName SET password = :new_password, initial = FALSE WHERE username = :email")
        conn.execute(query, {"new_password": new_password, "email": email})
        conn.commit()


# ------------------------
# Updated Login and Password Change Pages with Forest Background
# ------------------------

def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def set_png_as_page_bg(png_file):
    bin_str = get_base64_of_bin_file(png_file)
    page_bg_img = f"""
    <style>
    .stApp {{
        /* Dark gradient overlay for better legibility */
        background: linear-gradient(
            rgba(0, 0, 0, 0.4),
            rgba(0, 0, 0, 0.4)
        ), url("data:image/png;base64,{bin_str}") no-repeat center center fixed;
        background-size: cover;
    }}
    </style>
    """
    return page_bg_img


def login_page():
    # Set the forest background with gradient overlay
    st.markdown(set_png_as_page_bg('bg.jpg'), unsafe_allow_html=True)

    # Load Montserrat font from Google Fonts
    st.markdown(
        '<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap" rel="stylesheet">',
        unsafe_allow_html=True
    )

    # Apply custom CSS
    st.markdown("""
    <style>
    /* Hide Streamlit’s default UI elements */
    #MainMenu, footer, header {
        visibility: hidden;
    }

    /* Fade-in animation for the form container */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Style the login box (the middle column) */
    .stColumn:nth-child(2) {
        max-width: 450px;
        margin: 0 auto;
        padding: 30px;
        margin-top: 100px;
        background-color: rgba(255, 255, 255, 0.75);
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(10px);
        animation: fadeIn 0.8s ease-in-out;
    }

    /* Heading style */
    .login-heading {
        font-family: 'Montserrat', sans-serif;
        font-size: 32px;
        font-weight: 600;
        text-align: center;
        margin-bottom: 30px;
        color: #333333;
        text-transform: uppercase;
    }

    /* Input labels */
    .stTextInput > label {
        font-family: 'Montserrat', sans-serif;
        font-size: 16px;
        color: #333333;
        font-weight: 400;
        margin-bottom: 8px;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        background-color: #F5F5F5;
        border: 1px solid #666666;
        padding: 12px 15px;
        border-radius: 5px;
        font-family: 'Montserrat', sans-serif;
        transition: border-color 0.3s ease;
    }

    /* Focus state for input fields */
    .stTextInput > div > div > input:focus {
        outline: none !important;
        border: 2px solid #1A237E;
    }

    /* Login button */
    .stButton > button {
        font-family: 'Montserrat', sans-serif;
        background-color: #1A237E;
        color: #FFFFFF;
        font-weight: 500;
        border: none;
        padding: 12px 0;
        border-radius: 5px;
        width: 100%;
        margin-top: 10px;
        transition: background-color 0.3s ease, transform 0.2s ease;
        cursor: pointer;
    }

    /* Hover effect on login button */
    .stButton > button:hover {
        background-color: #283593;
        transform: translateY(-2px);
    }

    /* Spacing between inputs */
    .stTextInput {
        margin-bottom: 15px;
    }

    /* Responsive design */
    @media (max-width: 768px) {
        .stColumn:nth-child(2) {
            margin-top: 50px;
            padding: 20px;
        }
    }

    /* Style for messages (e.g., Checking credentials...) */
    .message-text {
        color: #000000;
        font-weight: bold;
        font-family: 'Montserrat', sans-serif;
        text-align: center;
        margin-top: 10px;
    }
    .error-text {
        color: #FF0000;
        font-weight: bold;
        font-family: 'Montserrat', sans-serif;
        text-align: center;
        margin-top: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

    # Center the login box with columns
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        # Heading
        st.markdown("<h1 class='login-heading'>Login</h1>", unsafe_allow_html=True)

        # Form elements with placeholder text and icons for intuitive UI
        email = st.text_input("Email", placeholder="✉️ Enter your email", key="login_email")
        password = st.text_input("Password", type="password", placeholder="🔒 Enter your password", key="login_password")
        login_button = st.button("Login", key="login_button", use_container_width=True)

        # Placeholder for loading messages
        placeholder = st.empty()

        # Login logic with loading messages
        if login_button:
            placeholder.markdown("<div class='message-text'>Checking credentials...</div>", unsafe_allow_html=True)
            time.sleep(1)  # Simulate processing delay
            if authenticate_user(email, password):
                placeholder.markdown("<div class='message-text'>Loading your chat interface...</div>",
                                     unsafe_allow_html=True)
                time.sleep(1)  # Ensure the message is visible
                st.session_state["authenticated"] = True
                st.session_state["user"] = email
                st.rerun()
            else:
                placeholder.markdown("<div class='error-text'>Invalid credentials! Please try again.</div>",
                                     unsafe_allow_html=True)


def password_change_page():
    # Set the forest background with gradient overlay
    st.markdown(set_png_as_page_bg('bg.jpg'), unsafe_allow_html=True)

    # Load Montserrat font
    st.markdown(
        '<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap" rel="stylesheet">',
        unsafe_allow_html=True
    )

    # Apply custom CSS
    st.markdown("""
    <style>
    /* Hide Streamlit’s default UI elements */
    #MainMenu, footer, header {
        visibility: hidden;
    }

    /* Fade-in animation for the password change container */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .stColumn:nth-child(2) {
        max-width: 450px;
        margin: 0 auto;
        padding: 30px;
        margin-top: 100px;
        background-color: rgba(255, 255, 255, 0.75);
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(10px);
        animation: fadeIn 0.8s ease-in-out;
    }

    /* Heading style */
    .password-heading {
        font-family: 'Montserrat', sans-serif;
        font-size: 32px;
        font-weight: 600;
        text-align: center;
        margin-bottom: 30px;
        color: #333333;
        text-transform: uppercase;
    }

    /* Input labels */
    .stTextInput > label {
        font-family: 'Montserrat', sans-serif;
        font-size: 16px;
        color: #333333;
        font-weight: 400;
        margin-bottom: 8px;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        background-color: #F5F5F5;
        border: 1px solid #666666;
        padding: 12px 15px;
        border-radius: 5px;
        font-family: 'Montserrat', sans-serif;
        transition: border-color 0.3s ease;
    }

    .stTextInput > div > div > input:focus {
        outline: none !important;
        border: 2px solid #1A237E;
    }

    /* Change password button */
    .stButton > button {
        font-family: 'Montserrat', sans-serif;
        background-color: #1A237E;
        color: #FFFFFF;
        font-weight: 500;
        border: none;
        padding: 12px 0;
        border-radius: 5px;
        width: 100%;
        margin-top: 10px;
        transition: background-color 0.3s ease, transform 0.2s ease;
        cursor: pointer;
    }

    .stButton > button:hover {
        background-color: #283593;
        transform: translateY(-2px);
    }

    /* Spacing between inputs */
    .stTextInput {
        margin-bottom: 15px;
    }

    /* Responsive design */
    @media (max-width: 768px) {
        .stColumn:nth-child(2) {
            margin-top: 50px;
            padding: 20px;
        }
    }
    </style>
    """, unsafe_allow_html=True)

    # Center the password box with columns
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        # Heading
        st.markdown("<h1 class='password-heading'>Change Password</h1>", unsafe_allow_html=True)

        # Grab the user’s email from session
        email = st.session_state.get("user", "user@example.com")

        # Form elements with placeholder texts and icons for clarity
        current_password = st.text_input("Current Password", type="password", placeholder="🔒 Current Password",
                                         key="current_pwd")
        new_password = st.text_input("New Password", type="password", placeholder="🔒 New Password", key="new_pwd")
        confirm_password = st.text_input("Confirm New Password", type="password", placeholder="🔒 Confirm New Password",
                                         key="confirm_pwd")
        change_button = st.button("Change Password", key="change_pwd_button", use_container_width=True)

        if change_button:
            if authenticate_user(email, current_password):
                if new_password == confirm_password:
                    update_password(email, new_password)
                    st.success("Password changed successfully!")
                    st.session_state["password_changed"] = True
                    st.rerun()
                else:
                    st.error("New passwords do not match!")
            else:
                st.error("Incorrect current password!")


# ---------------------------------------------
# 6. Chat History Persistence (DB + CSV files)
# ---------------------------------------------
PERSISTENT_DF_FOLDER = "chat_data"
os.makedirs(PERSISTENT_DF_FOLDER, exist_ok=True)


# --- NEW FUNCTION: Autosave check ---
def maybe_autosave_chat():
    """Autosave the current chat if enough time has passed since last save."""
    current_time = time.time()

    # Initialize last_save_time if not present
    if "last_save_time" not in st.session_state:
        st.session_state.last_save_time = current_time
        return

    # Skip if no messages or if not enough time has passed
    if not st.session_state.chat_history or (current_time - st.session_state.last_save_time) < AUTOSAVE_INTERVAL:
        return

    # Avoid saving if the conversation hasn't changed
    if "last_saved_message_count" in st.session_state and len(
            st.session_state.chat_history) == st.session_state.last_saved_message_count:
        return

    # Save the current conversation
    save_chat_session_to_db(
        user=st.session_state["user"],
        messages=st.session_state.chat_history,
        persistent_dfs=st.session_state.persistent_dfs
    )

    # Update last save time and message count
    st.session_state.last_save_time = current_time
    st.session_state.last_saved_message_count = len(st.session_state.chat_history)


def save_after_exchange():
    """
    Save the conversation immediately after each user-assistant exchange.
    This ensures no data is lost if the application crashes.
    """
    if not st.session_state.chat_history:
        return

    # Save the current conversation
    save_chat_session_to_db(
        user=st.session_state["user"],
        messages=st.session_state.chat_history,
        persistent_dfs=st.session_state.persistent_dfs
    )

    # Update tracking variables
    st.session_state.last_save_time = time.time()
    st.session_state.last_saved_message_count = len(st.session_state.chat_history)


# --- MODIFIED save_chat_session_to_db ---
def save_chat_session_to_db(user, messages, persistent_dfs):
    """Save the current conversation to DB, storing DataFrames as CSV files.
       Avoid duplicate titles by checking for an existing chat session.
    """
    if not messages:
        return

    # Generate a better title from first user message (not system prompt)
    user_messages = [msg for msg in messages if msg["role"] == "user"]
    if user_messages:
        title = user_messages[0]["content"][:30] + "..."
    else:
        title = "New Chat (" + datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') + ")"

    df_file_paths = []
    for i, df in enumerate(persistent_dfs):
        filename = f"{user}_{datetime.datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}_{i}.csv"
        file_path = os.path.join(PERSISTENT_DF_FOLDER, filename)
        df.to_csv(file_path, index=False)
        df_file_paths.append(file_path)

    messages_json = json.dumps(messages)
    df_paths_json = json.dumps(df_file_paths)

    # Store the mapping between messages and tables
    df_mappings_json = json.dumps(st.session_state.chat_message_tables)

    db_session = SessionLocal()
    try:
        # Check if we already have a chat with the same ID in session
        if "current_chat_id" in st.session_state:
            existing_chat = db_session.query(ChatHistory).filter(
                ChatHistory.id == st.session_state.current_chat_id).first()
            if existing_chat:
                existing_chat.title = title
                existing_chat.timestamp = datetime.datetime.now(timezone.utc)
                existing_chat.messages = messages_json
                existing_chat.persistent_df_paths = df_paths_json
                existing_chat.persistent_df_mappings = df_mappings_json
                db_session.commit()
                return
        # Create new chat record if no existing one
        chat_record = ChatHistory(
            user=user,
            title=title,
            timestamp=datetime.datetime.now(timezone.utc),
            messages=messages_json,
            persistent_df_paths=df_paths_json,
            persistent_df_mappings=df_mappings_json
        )
        db_session.add(chat_record)
        db_session.commit()

        # Store the ID of this chat for future updates
        st.session_state.current_chat_id = chat_record.id
    except Exception as e:
        print(f"Error saving chat session: {e}")
    finally:
        db_session.close()


def load_chat_sessions_for_user(user_email):
    """Return a list of all conversation dicts for this user."""
    db_session = SessionLocal()
    sessions = []
    try:
        results = db_session.query(ChatHistory).filter(ChatHistory.user == user_email).all()
        for s in results:
            sessions.append({
                "id": s.id,
                "user": s.user,
                "title": s.title,
                "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "messages": json.loads(s.messages),
                "persistent_df_paths": json.loads(s.persistent_df_paths)
            })
    except Exception as e:
        print(f"Error loading chat sessions: {e}")
    finally:
        db_session.close()
    return sessions


# --- MODIFIED load_conversation_into_session ---
def load_conversation_into_session(conversation):
    """Load the chosen conversation into session_state so user can continue."""
    # Load the full conversation for context (used for generating responses)
    st.session_state.messages = conversation["messages"]
    # For display, filter out the system message
    st.session_state.chat_history = [msg for msg in conversation["messages"] if msg["role"] != "system"]

    loaded_dfs = []
    for path in conversation["persistent_df_paths"]:
        try:
            loaded_dfs.append(pd.read_csv(path))
        except Exception as e:
            st.error(f"Error loading DataFrame from {path}: {e}")
    st.session_state.persistent_dfs = loaded_dfs

    # Reset the chat_message_tables mapping
    st.session_state.chat_message_tables = {}

    # Only assign tables to messages that mention "result is displayed below" or similar phrases
    df_index = 0
    assistant_index = 0

    for msg in st.session_state.chat_history:
        if msg["role"] == "assistant":
            # Look for phrases that indicate a table should follow
            if (df_index < len(loaded_dfs) and
                    ("result is displayed below" in msg["content"] or
                     "rows. The result is displayed below" in msg["content"] or
                     "below" in msg["content"] and "row" in msg["content"])):
                # This message should have a table
                st.session_state.chat_message_tables[assistant_index] = df_index
                df_index += 1

            assistant_index += 1

    # Store the conversation ID so we can update it rather than create new ones
    st.session_state.current_chat_id = conversation["id"]
    st.session_state.last_saved_message_count = len(conversation["messages"])
    st.session_state.last_save_time = time.time()


# ---------------------------------------------
# 7. Query Logging (existing from your code)
# ---------------------------------------------
def sync_sqlite_to_snowflake():
    try:
        DATABASE_URL = "sqlite:///log.db"
        local_engine = create_engine(DATABASE_URL)
        table_name = "query_result"
        with local_engine.connect() as conn:
            df = pd.read_sql(f"SELECT * FROM {table_name} WHERE synced_to_snowflake = FALSE", conn)
        if df.empty:
            print("No new data to sync.")
            return
        SNOWFLAKE_ACCOUNT = os.getenv("SNOWFLAKE_ACCOUNT")
        SNOWFLAKE_USER = os.getenv("SNOWFLAKE_USER")
        private_key = get_private_key_str()
        SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE")
        SNOWFLAKE_SCHEMA = os.getenv("SNOWFLAKE_SCHEMA")
        SNOWFLAKE_WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
        SNOWFLAKE_ROLE = os.getenv("SNOWFLAKE_ROLE")
        if not all([SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, private_key,
                    SNOWFLAKE_DATABASE, SNOWFLAKE_SCHEMA, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_ROLE]):
            print("Missing Snowflake credentials in environment variables.")
            return
        snowflake_engine = create_engine(URL(
            account=SNOWFLAKE_ACCOUNT,
            user=SNOWFLAKE_USER,
            private_key=private_key,
            database=SNOWFLAKE_DATABASE,
            schema=SNOWFLAKE_SCHEMA,
            warehouse=SNOWFLAKE_WAREHOUSE,
            role=SNOWFLAKE_ROLE
        ))
        snowflake_table_name = "Logtable"
        print(f"Syncing data to Snowflake table: {snowflake_table_name}")
        with snowflake_engine.connect() as conn:
            df.to_sql(
                name=snowflake_table_name,
                con=conn,
                if_exists='append',
                index=False,
                method='multi'
            )
            print(f"Synced {len(df)} new rows to Snowflake.")
            with local_engine.connect() as local_conn:
                for id in df['id']:
                    local_conn.execute(
                        text(f"UPDATE {table_name} SET synced_to_snowflake = TRUE WHERE id = :id"),
                        {"id": id}
                    )
                local_conn.commit()
    except Exception as e:
        print(f"Error syncing data to Snowflake: {e}")


def save_query_result(user_query, natural_language_response, result, sql_query, response_text,
                      tokens_first_call=None, tokens_second_call=None, total_tokens_used=None, error_message=None):
    db_session = SessionLocal()
    try:
        query_result = QueryResult(
            query=user_query,
            answer=str(natural_language_response) if natural_language_response else None,
            sfresult=str(result) if result else None,
            sqlquery=str(sql_query) if sql_query else None,
            raw_response=str(response_text),
            tokens_first_call=tokens_first_call,
            tokens_second_call=tokens_second_call,
            total_tokens_used=total_tokens_used,
            error_message=str(error_message) if error_message else None
        )
        db_session.add(query_result)
        db_session.commit()
        sync_sqlite_to_snowflake()
    except Exception as e:
        print(f"Error saving query and result to database: {e}")
    finally:
        db_session.close()


# ---------------------------------------------
# 8. Main Application
# ---------------------------------------------
def main_app():
    if "user" in st.session_state:
        # username = st.session_state["user"].split("@")[0]
        username = st.session_state["user"]

        st.markdown(
            f"""
            <style>
            /* Container aligned to the right, near the 'Deploy' button */
            .username-container {{
                display: flex;
                justify-content: flex-end;
                margin-top: -54px; /* Adjust as needed */
                margin-right: -5px; /* Adjust spacing from right edge */
            }}
            /* Black text, smaller size to match 'Deploy' */
            .black-text {{
                font-size: 16px;
                color: black;
                font-weight: 600;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }}
            </style>
            <div class="username-container">
                <div class="black-text">
                    Logged in as: {username}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    import re

    def display_query_corrections(correction_suggestions, original_query):
        """
        Create interactive UI for query corrections

        Args:
            correction_suggestions (dict): Suggestions for query corrections
            original_query (str): Original SQL query

        Returns:
            str or None: Corrected query if a suggestion is selected
        """
        # Create a container for corrections
        correction_container = st.container()

        with correction_container:
            st.warning("No results found. Did you mean:")

            # Track selected corrections
            selected_corrections = {}

            # Display corrections for each suggestion
            for i, suggestion in enumerate(correction_suggestions['suggestions']):
                st.write(f"In column '{suggestion['column']}', '{suggestion['original_value']}' might be incorrect.")

                # Create a selectbox for each suggestion
                selected_value = st.selectbox(
                    f"Select a correction for {suggestion['column']}",
                    ['Original Value'] + suggestion['suggested_values'],
                    key=f"correction_{i}"
                )

                # If a different value is selected, store it
                if selected_value != 'Original Value':
                    selected_corrections[suggestion['column']] = selected_value

            # Correction button
            if st.button("Apply Corrections"):
                # Create a corrected query
                corrected_query = original_query

                # Replace values in the query
                for column, new_value in selected_corrections.items():
                    # Use regex to replace the specific column's value
                    # Handles both quoted and unquoted column names
                    corrected_query = re.sub(
                        rf'("{column}"\s*=\s*[\'"]){suggestion["original_value"]}([\'"])',
                        rf'\1{new_value}\2',
                        corrected_query
                    )

                return corrected_query

        return None

    # Modify your existing query execution logic
    def execute_corrected_query(corrected_query):
        """
        Execute the corrected query

        Args:
            corrected_query (str): SQL query with corrections

        Returns:
            list or dict: Query results
        """
        try:
            # Your existing query execution logic
            result = query_snowflake(corrected_query, st.session_state["user"])
            return result
        except Exception as e:
            st.error(f"Error executing corrected query: {e}")
            return None

    def format_query_correction_response(correction_suggestions, original_query):
        """
        Format query correction suggestions into a user-friendly message

        Args:
            correction_suggestions (dict): Suggestions for query corrections
            original_query (str): Original SQL query

        Returns:
            str: Formatted suggestion message
        """
        # Start with a clear, informative header
        suggestion_message = "🔍 Query Correction Suggestions:\n\n"

        # Add details about each suggestion
        for suggestion in correction_suggestions['suggestions']:
            suggestion_message += f"• Column: *{suggestion['column']}*\n"
            suggestion_message += f"  Original Value: `{suggestion['original_value']}`\n"
            suggestion_message += f"  Possible Correct Values:\n"

            # List possible corrections
            for value in suggestion['suggested_values']:
                suggestion_message += f"    - {value}\n"

            suggestion_message += "\n"

        # Add a helpful footer
        suggestion_message += "**Tip:** Consider using one of the suggested values to improve your query results.\n\n"
        suggestion_message += f"*Original Query:* ```sql\n{original_query}\n```"

        return suggestion_message

    def create_correction_dataframe(correction_suggestions):
        """
        Create a DataFrame to display correction suggestions

        Args:
            correction_suggestions (dict): Suggestions for query corrections

        Returns:
            pandas.DataFrame: Formatted suggestions DataFrame
        """
        import pandas as pd

        # Prepare data for DataFrame
        correction_data = []
        for suggestion in correction_suggestions['suggestions']:
            for suggested_value in suggestion['suggested_values']:
                correction_data.append({
                    'Column': suggestion['column'],
                    'Original Value': suggestion['original_value'],
                    'Suggested Value': suggested_value
                })

        # Create DataFrame
        df = pd.DataFrame(correction_data)
        return df

    def get_cached_schema_details(user_email):
        """Get schema details from cache or database"""
        cache_key = f"schema_{user_email}"

        # Check if schema is already in session state cache
        if cache_key in st.session_state:
            return st.session_state[cache_key]

        # If not in cache, retrieve from database
        schema_details = get_schema_details(user_email)

        # Check if we got a valid schema (not an error)
        if isinstance(schema_details, dict) and "error" not in schema_details:
            # Cache the result in session state
            st.session_state[cache_key] = schema_details

        return schema_details

    # Initialize states if not present
    if "total_tokens" not in st.session_state:
        st.session_state.total_tokens = 0
    if "persistent_dfs" not in st.session_state:
        st.session_state.persistent_dfs = []
    if "messages" not in st.session_state:
        st.session_state.messages = []
        st.session_state.chat_history = []

    # ---- AUTOSAVE CHECK ----
    if AUTOSAVE_ENABLED:
        maybe_autosave_chat()

    # -------------------------------
    #  A) SIDEBAR: Show Chat History
    # -------------------------------
    def clear_chat_history(user_email):
        db_session = SessionLocal()
        try:
            db_session.query(ChatHistory).filter(ChatHistory.user == user_email).delete()
            db_session.commit()
        except Exception as e:
            st.error(f"Error clearing chat history: {e}")
        finally:
            db_session.close()

    with st.sidebar:
        logo = Image.open("logo4.png")  # Your logo file
        st.image(logo, width=400)
        st.markdown("## Your Chat History")

        # 1. Load all user's past conversations from DB
        user_email = st.session_state["user"]
        user_conversations = load_chat_sessions_for_user(user_email)

        # 2. Group conversations by date
        if user_conversations:
            # Sort conversations by timestamp (newest first)
            user_conversations.sort(key=lambda x: x['timestamp'], reverse=True)

            # Group conversations by date
            conversations_by_date = {}
            for conv in user_conversations:
                # Extract just the date part from the timestamp (format: YYYY-MM-DD)
                date = conv['timestamp'].split(' ')[0]
                if date not in conversations_by_date:
                    conversations_by_date[date] = []
                conversations_by_date[date].append(conv)

            # Display conversations grouped by date
            for date, convs in conversations_by_date.items():
                # Format date for display (e.g., "15-3-25" instead of "2025-03-15")
                display_date = datetime.datetime.strptime(date, "%Y-%m-%d").strftime("%d-%m-%y")

                # Create a date header with custom styling
                st.markdown(f"""
                <div style="background-color: #f0f2f6; padding: 5px; border-radius: 5px; margin-bottom: 5px;">
                    <span style="font-weight: bold; color: #1A237E;">{display_date}</span>
                </div>
                """, unsafe_allow_html=True)

                # Display conversations for this date
                for conv in convs:
                    # Just show the title without the timestamp since we're already grouped by date
                    button_label = conv['title']
                    if st.button(button_label, key=f"btn_{conv['id']}"):
                        load_conversation_into_session(conv)
                        st.rerun()

        st.write("---")
        # 3. New Chat button
        if st.button("🆕 New Chat"):
            # Save the current conversation (if any)
            if st.session_state.chat_history:
                save_chat_session_to_db(
                    user=st.session_state["user"],
                    messages=st.session_state.chat_history,
                    persistent_dfs=st.session_state.persistent_dfs
                )
            # Clear the active session
            st.session_state.pop("messages", None)
            st.session_state.pop("chat_history", None)
            st.session_state.pop("persistent_dfs", None)
            st.session_state.pop("current_chat_id", None)
            st.session_state.pop("last_saved_message_count", None)
            st.rerun()

        # Clear History button
        if st.button("🗑️ Clear History"):
            clear_chat_history(user_email)
            st.success("Chat history cleared!")
            st.rerun()

        # 4. Logout button
        if st.button("Logout"):
            # Clear all session state variables related to chat and queries
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            # Reinitialize only the authentication state
            st.session_state["authenticated"] = False
            st.rerun()

    # ----------------------------------
    #  B) MAIN: Chat interface
    # ----------------------------------
    st.markdown("""
        <style>
            div.streamlit-expanderHeader {
                font-weight: bold !important;
                font-size: 18px !important; /* Bigger and bolder */
                font-family: 'Arial', sans-serif !important; /* Clean, professional font */
                color: #1A237E !important; /* Dark blue for better visibility */
            }
            div[data-testid="stExpander"] {
                max-width: 500px; /* Adjust width */
                margin-left: 0; /* Align to left */
            }
        </style>
    """, unsafe_allow_html=True)

    # UI Components
    st.title("❄️ AI Data Assistant ❄️")
    st.caption("Ask me about your business analytics queries")

    # Expander with optimized size and font
    with st.expander("📝 Not sure what to ask? Click here for sample questions"):
        st.markdown("""
            <div style="
                background: linear-gradient(to right, #e0f7fa, #b2ebf2);
                border-radius: 10px;
                padding: 15px;">
                <ul style="margin-bottom: 5px;">
                    <li><b>Paid invoice summary details:</b> "Paid Invoice Summary"</li>
                    <li><b>Purchase order details:</b> "Fetch all details of home depot where goods are invoiced"</li>
                    <li><b>Vendor Info:</b> "Vendor Details"</li>
                    <li><b>Purchase requisition details:</b> "Give me a count of purchase requisition for the year 2025"</li>
                </ul>
                <p style="color: #00838f; font-size: 0.9em; margin-bottom: 0;">
                    If you're unsure what to ask, feel free to use the sample questions above or rephrase them to get the insights you need.
                </p>
            </div>
        """, unsafe_allow_html=True)

    # Prepare the system prompt for your LLM
    schema_details = get_cached_schema_details(st.session_state["user"])
    if "error" in schema_details:
        st.error(schema_details["error"])
        st.stop()

    schema_text = ""
    for table, columns in schema_details.items():
        schema_text += f"Table: {table}\n"
        schema_text += "Columns:\n"
        for col_name, col_info in columns.items():
            schema_text += f"  - {col_name} (Data Type: {col_info['data_type']})\n"

            # Add sample values if they exist
            if "sample_values" in col_info and col_info["sample_values"]:
                # Format the sample values as a comma-separated list
                sample_values_str = ", ".join(col_info["sample_values"])
                schema_text += f"    Sample values: [{sample_values_str}]\n"

        schema_text += "\n"

    # Create the system prompt
    system_prompt = f"""
                            You are a Snowflake SQL assistant.Use the schema below :  
                            {schema_text} 
                            **1. GLOBAL RULES**

                                **1.1 General Rules:**
                                    1. Always use correct Snowflake syntax with exact table/column names.
                                    2. **⚠️ MANDATORY RULE: ALWAYS check column data types before constructing your query ⚠️**
                                    3. CAREFULLY EXAMINE COLUMN NAMES to ensure you select the EXACT column needed:
                                       • Pay special attention to similar column names (e.g., "vendor" vs "vendor_name").
                                       • Choose columns based on their semantic meaning and data type, not just naming similarity.
                                       • When unsure, prefer the column whose name most precisely matches the concept in the question.
                                    4. Validate **joins, foreign keys, and relationships** strictly based on the schema.
                                    5. Optimize queries: Avoid unnecessary joins and subqueries.

                                **1.2 Time & Date Handling:**
                                   1. Use DATEDIFF(DAY, col1, col2) instead of DATEDIFF(col1, col2).
                                   2. Use DATEADD() for date arithmetic (e.g., DATEADD(DAY, -7, CURRENT_DATE)).

                                **1.3 Query Structuring:**
                                   1. Use **aliases for readability** (e.g., FROM "order_details" AS od).
                                   2. Never use **ORDER BY inside UNION subqueries**—use LIMIT instead.

                                **1.4 COUNT() USAGE RULES**
                                **⚠️CRITICAL COUNT() USAGE INSTRUCTION⚠️**
                                   • Carefully analyze the user's question to determine the appropriate COUNT method.
                                   • If the word **total** is present in the question, use COUNT() (full count).
                                   • If **total** is NOT present, use COUNT(DISTINCT column_name).
                                   • Case-insensitive search (e.g., "Total", "TOTAL", "total" all count).
                                   • Examples:
                                       • "How many customers?" → COUNT(DISTINCT "customer_id")
                                       • "What is the total number of customers?" → COUNT("customer_id")
                                       • "Total sales this year" → COUNT("sales")
                                       • "Distinct vendors in the last month" → COUNT(DISTINCT "vendor_id")
                                **1.5 QUERY TEMPLATE USAGE (MANDATORY):**
                                   1. **⚠️ CRITICAL INSTRUCTION: ALWAYS use the pre-defined query templates provided below instead of SELECT * ⚠️**
                                   2. For each table, use ONLY the corresponding template when displaying full table data.
                                   3. Only modify these templates when:
                                      • The user explicitly requests specific additional columns not in the template
                                      • The user needs a subset of columns from the template
                                      • The query requires aggregation or transformation of the data
                                   4. NEVER use SELECT * in ANY query - this is strictly prohibited.
                                   5. These templates are carefully designed to show the most relevant columns with proper aliases - using them is MANDATORY.

                            ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                            **2. TABLE-SPECIFIC RULES**

                               **2.1 PO_DETAILS_VIEW TABLE:**
                                    1. ⚠️ **MANDATORY RULE: ALWAYS USE DOUBLE QUOTES ("")** ⚠️  
                                                - **tablename and column name** of PO_DETAILS_VIEW **MUST BE ENCLOSED** in double quotes exactly as in the schema. 
                               **Query Templates**
                                ## SQL Template for Multi-row PO_DETAILS_VIEW TABLE (Always Use for Table Outputs):
                                SELECT 
                                    "Purchase_Order" AS "PO#","Vendor" AS "Vendor#","Vendor_Name" AS "Vendor Name ","Project_ID" AS Project,"JOB_NAME"AS "Project Name ",
                                    "JOB_STAGE" AS "Project Stage","PO_HDR_Status" AS "PO HDR Status","Purchase_Item_Status" AS "PO Line Status","JOB_PROJECT_MANAGER_NAME" AS "Project Manger",
                                    "JOB_PROJ_DIRECTOR_NAME" AS "Project Director ","Project_Category" AS "Project Category","Purchase_Quantity" AS "PO Quantity",
                                    "Quantity Ordered" AS "Quantity Ordered","Unit" AS "Unit","Price" AS "Price","Amount" AS "Amount","Item #" AS "Line #",
                                    "Item_Desc" AS "Line Desc","PROCUREMENT_NAME" AS "Procurement Category","Product_Number" AS "Product #","Product_Name" AS "Product Desc",
                                    "Purchase_Requisition" AS "PO Requisition","PO_HDR_Doc_Status" AS "PO HDR Doc Status","po_entry_date" AS "Accounting Date",
                                    "POC_Date" AS "PO Created Date","Delivery_Date" AS "Delivery Date","Expected_Delivery_Date" AS "Expected Delivery Date",
                                    "Main Account Id" AS "Main Account","Main Account" AS "Main Account Name","Branch" AS "Branch","Department" AS "Department",
                                    "Goods Received" AS "Goods Received","Delivery_Type" AS "Delivery_Type","Delivery_Term_Desc" AS "Delivery Term",
                                    "Delivery_Location" AS "Delivery Location","Delivery_Mode" AS "Delivery Mode","Ordered_By_Name" AS "Order By ","Requester_Name" AS "Requester"
                                FROM "PO_DETAILS_VIEW"



                                **Special Conditions:**

                                • For Open Orders:
                                    • Add column: "JOB_COMPLETION_DATE" AS "Project Completion Date"
                                    • Add Filter: WHERE "Purchase_Itm_StatusID" = 1
                                • For PO with GR Not Invoiced or Goods Received:
                                    • Add Filter: WHERE "Purchase_Itm_StatusID" = 2
                                • For Invoiced:
                                    • Add columns:
                                        • "LATEST_INVOICE" AS "Last Invoice"
                                        • "LATEST_INVOICE_DT" AS "Last Invoice Date"
                                    •Add Filter: WHERE "Purchase_Itm_StatusID" = 3
                                • For All Purchase Orders or All PO:
                                    •Add columns:
                                        • "LATEST_INVOICE" AS "Last Invoice"
                                        • "LATEST_INVOICE_DT" AS "Last Invoice Date"
                                        • "Created_By" AS "Created_By"
                                        • "Created_On" AS "Created_On"

                                When user asks about **Delayed Vendors**  generate the following Snowflake SQL query:
                                    WITH vendor_metrics AS (
                                        SELECT
                                            "Vendor_Name",
                                             COUNT(DISTINCT "Purchase_Order") AS number_of_po,
                                            SUM("Amount") AS po_value,
                                            MAX(
                                                CASE 
                                                    WHEN DATEDIFF('day', "Expected_Delivery_Date", CURRENT_DATE()) > 0 
                                                    THEN DATEDIFF('day', "Expected_Delivery_Date", CURRENT_DATE())
                                                    ELSE 0 
                                                END
                                            ) AS max_delay_days,
                                            SUM(
                                                CASE 
                                                    WHEN "Expected_Delivery_Date" < CURRENT_DATE() 
                                                    THEN 1 
                                                    ELSE 0 
                                                END
                                            ) AS delayed_po_count
                                        FROM
                                            PO_DETAILS_VIEW
                                        WHERE
                                            "Expected_Delivery_Date" < CURRENT_DATE()
                                            AND "Purchase_Itm_StatusID" = 1
                                        GROUP BY
                                            "Vendor_Name"
                                        HAVING
                                            delayed_po_count > 0
                                    )
                                    SELECT
                                        "Vendor_Name" AS "Vendor",
                                        number_of_po AS "Number of PO",
                                        po_value AS "PO Value"
                                    FROM
                                        vendor_metrics
                                    ORDER BY
                                        max_delay_days DESC,
                                        po_value DESC
                                    LIMIT 15;

                                ### PO_DETAILS_VIEW TABLE Field Mappings
                                       * "PO#" or "Purchase Order" → filter on "Purchase_Order"
                                       * "Vendor#" → filter on "Vendor"
                                       *  "Project" or "Project ID" → filter on "Project_ID"
                                       * "Project Name" → filter on "JOB_NAME"
                                       * "Project Stage" → filter on "JOB_STAGE"
                                       * "Line Status" or "PO Line Status" → filter on "Purchase_Item_Status"
                                       * "Procurement Category" → filter on "PROCUREMENT_NAME"
                                       * "Product Description" → filter on "Product_Name"
                                       * "PO Requisition" → filter on "Purchase_Requisition"
                                       * "Main Account" → filter on "Main Account Id"
                                       * "Main Account Name" → filter on "Main Account"


                                **Additional PO_DETAILS_VIEW TABLE Rules**
                                2. **Year & Month Filtering:**
                                      • When filtering/grouping by year, **always use the precomputed "Year" column.**
                                      • DO NOT extract year from "Accounting_Date" or any other column.
                                      • When filtering/grouping by month, **always use the precomputed "Month" column.**
                                      • DO NOT extract month from "Accounting_Date" or any other column.
                                      • For month names, always use three-letter abbreviation (e.g., 'Jan', 'Feb', 'Mar', 'Sep').
                                3. **Location Queries:**
                                      • When filtering by location (city, region), ALWAYS use "Branch_Name" column (NOT "Delivery_Location").
                                      • Examples of branch names: San Francisco, Boston, Los Angeles, Chicago, Seattle.
                                      • Only use "Delivery_Location" when user explicitly asks for delivery location information.
                                4. **Purchase Requisition Count Handling:**
                                      • For PR count queries use:
                                        SELECT COUNT(DISTINCT "Purchase_Requisition") FROM "PO_DETAILS_VIEW" WHERE "Year" = 2025;
                                      • If the user explicitly specifies a year, replace 2025 with the mentioned value.
                                      • If the user does not specify a year, default 2025 to the current year.
                            ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                **2.2 VENDOR TABLE:**
                                   **Query Template**
                                        SELECT 
                                          data_area AS company,
                                          CONCAT(ACCOUNT_NUM, '-', NAME) AS "Vendor",
                                          vend_group,
                                          vendor_hold_desc AS hold_status, 
                                          delivery_mode,
                                          delivery_term,
                                          paym_term_id AS payment_term, 
                                          phone_no as phone,
                                          phone_cp AS contact_person_phone,
                                          email_cp_name AS contact_person_email,
                                          email_cp As Email,
                                          fax,street,state,city,zip_code,
                                          clearing_period,currency,
                                          tax_1099_fields as tax_1099,
                                          tax_1099_reg_num,
                                          one_time_vendor,
                                          small_business,
                                          women_owned,
                                          hubzone,
                                          owner_is_a_service_veteran,
                                          owner_is_disabled  
                                        FROM vendor;

                                   ### VENDOR Field Mappings
                                        * "Company" → filter on data_area
                                        * "Vendor" or "Vendor Name" → 
                                           If the value is numeric → it's ACCOUNT_NUM
                                            e.g., "vendor 7005" or "7005 vendor" → ACCOUNT_NUM = '7005'
                                           If the value is non-numeric (or contains commas) → it's NAME
                                            e.g., "vendor Johnson & Sons" or "Johnson & Sons vendor" → NAME = 'Johnson & Sons'
                                        * "Hold Status" → filter on vendor_hold_desc
                                        * "Payment Term" → filter on paym_term_id
                                        * "Phone" → phone_no
                                        * "contact person phone" → phone_cp
                                        * "contact person email" → email_cp_name
                                        * "Email" → email_cp

                                     - For any filter, generate the SQL WHERE clause as:
                                          WHERE <field_expression> = '<user_input>'

                                    **Notes:**
                                       • For this table, double quotes are NOT required for table names or column names.
                            ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                **2.3 AP_INVOICE_PAID_VIEW TABLE:**
                                   **Query Template**
                                        SELECT 
                                          CONCAT("ACCOUNT_NUM", '-', "ACCOUNT_NAME") AS "Vendor",
                                          CONCAT("COMPANY_CODE", '-', "COMPANY_NAME") AS "Company",
                                          "INVOICE_NO" AS "Invoice",
                                          "INVOICE_DATE",
                                          "INVOICE_DUE_DATE",
                                          "APPROVED_DATE",
                                          Closed_Date AS "Payment_Date",
                                          "INVOICE_AMOUNT",
                                          "PAID_AMOUNT",
                                          "PAYM_MODE" AS "Payment_Mode",
                                          "JOURNAL_NUM" AS "Journal_Number",
                                          "VOUCHER"
                                        FROM "AP_INVOICE_PAID_VIEW";

                                    **Special Conditions**
                                    For Salesforce queries:
                                     •  Add: WHERE "EXF_CLASSIFIED" = 0;

                                    ### AP_INVOICE_PAID_VIEW Field Mappings:

                                    * "Vendor" → 
                                            If the value is numeric → it's ACCOUNT_NUM
                                            e.g., "vendor 5001" or "5001 vendor" → ACCOUNT_NUM = '5001'
                                            If the value is non-numeric (or contains commas) → it's ACCOUNT_NAME
                                            e.g., "vendor Smith Plumbing" or "Smith Plumbing vendor" → ACCOUNT_NAME = 'Smith Plumbing'
                                        * "Company" → 
                                             If the value is numeric → it's COMPANY_CODE
                                                 e.g., "company 200" or "200 company" → COMPANY_CODE = '200'
                                             If the value is non-numeric (or contains commas) → it's COMPANY_NAME
                                                 e.g., "company XYZ Ltd" or "XYZ Ltd company" → COMPANY_NAME = 'XYZ Ltd'
                                        * "Invoice" or "Invoice Number" → filter on "INVOICE_NO"
                                        * "Approval Date" → filter on "APPROVED_DATE"
                                        * "Payment Date" → filter on "Closed_Date"
                                        * "Payment Mode" → filter on "PAYM_MODE"

                                     - For any filter, generate the SQL WHERE clause as:
                                          WHERE <field_expression> = '<user_input>'

                            ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                **2.4  ITEMS TABLE:**
                                   **Query Template**
                                        SELECT 
                                          CONCAT(DATA_AREA_ID, '-', DATA_AREA_NAME) AS "Company",
                                          LOCATION,
                                          TRANS_DATE AS Transaction_date,
                                          JOURNAL_ID AS Journal,
                                          JOURNAL_TYPE_DESC,
                                          PROJ_TRANS_ID AS Transaction_ID,
                                          INVENT_TRANS_ID,
                                          ITEM_ID,
                                          ITEM_DESC,
                                          PROJ_SALES_PRICE AS Sales_Price,
                                          COST_PRICE,
                                          COST_AMOUNT,
                                          UNIT_QTY AS Quantity,
                                          CURRENCY,
                                          UNIT,
                                          CASE 
                                              WHEN PROJ_ID IS NULL AND JOB_NAME IS NULL THEN NULL 
                                              ELSE COALESCE(PROJ_ID, '') || ' - ' || COALESCE(JOB_NAME, '') 
                                          END AS Project
                                        FROM ITEMS;

                                    ### ITEMS Field Mappings
                                          * "Company" → 
                                              If the value is numeric → it's DATA_AREA_ID
                                                e.g., "company 1001" or "1001 company" → DATA_AREA_ID = '1001'
                                              If the value is non-numeric (or contains commas) → it's DATA_AREA_NAME
                                                e.g., "company ABC Corp" or "ABC Corp company" → DATA_AREA_NAME = 'ABC Corp'
                                          * "Transaction date" → filter on TRANS_DATE
                                          * "Journal" → filter on JOURNAL_ID
                                          * "Journal type" → filter on JOURNAL_TYPE_DESC
                                          * "Transaction ID" → filter on PROJ_TRANS_ID
                                          * "Price" → filter on PROJ_SALES_PRICE
                                          * "Cost Price" → filter on COST_PRICE
                                          * "Cost Amount" → filter on COST_AMOUNT
                                          * "Quantity" → filter on UNIT_QTY
                                          * "Currency" → filter on CURRENCY
                                          * "Project" →
                                             If project value is numeric → it's PROJ_ID
                                              e.g., "project 10001" or "10001 project " → PROJ_ID = '10001'
                                            If project value is non-numeric (or contains commas) → it's JOB_NAME
                                              e.g., "project dalto,brian" or "dalto,brian project "→ JOB_NAME = 'dalto,brian'

                                        - For any filter, generate the SQL WHERE clause as:
                                          WHERE <field_expression> = '<user_input>'
                            ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                **2.5  PURCHASE_REQUISITION TABLE:**
                                   **Query Template**  
                                     SELECT 
                                          Purch_ID_Data_Area AS COMPANY,
                                          Purch_Req_ID AS "PR #",
                                          Purch_Req_Name AS Requisition_Name,
                                          Vendor_Name AS Vendor,
                                          VENDOR_ACCOUNT as Vendor_ID,
                                          PR_HDR_Proj_ID AS Project,
                                          job_name AS Project_Name,
                                          JOB_STAGE AS Project_Stage,
                                          job_project_manager_name AS Project_Manager,
                                          JOB_PROJ_DIRECTOR_NAME AS Project_Director,
                                          Proj_Category_ID AS Project_Category,
                                          Purch_Price AS Price,
                                          Purch_Qty AS Quantity,
                                          Line_Amount AS Amount,
                                          Itm_Line_num AS Line_Num,
                                          Line_Disc AS Name,
                                          Item_ID AS Project_Num,
                                          Item_ID_Non_Catalog AS Project_Desc,
                                          PR_Itm_Status AS Item_Status,
                                          Purch_ID AS Purchase_Order,
                                          PO_HDR_Status,
                                          PO_Document_Status,
                                          PR_Created_Date AS Created_Date,
                                          PR_HDR_Trans_Date AS Accounting_Date,
                                          DD_Request_Delivery_Date AS Req_Delivery_Dt,
                                          Approval_Status,
                                          Main_Account,
                                          Main_Account_Description,
                                          Branch,
                                          Department,
                                          DD_Office AS Office,
                                          Location_ID AS Location,
                                          Site_Name AS Site,
                                          Warehouse_Name AS Warehouse,
                                          Submitted_Date_Time AS Submitted_Date,
                                          Submitted_By 
                                        FROM PURCHASE_REQUISITION; 

                                   **Special Conditions:**
                                     • For open purchase requisition queries:
                                        • Add: WHERE "pr_itm_statusid" IN ('0','10')
                                   ### PURCHASE_REQUISITION Field Mappings
                                           * "Company" → filter on Purch_ID_Data_Area
                                            * "PR Number" or "Purchase Requisition Number" → filter on Purch_Req_ID
                                            * "Requisition Name" → filter on Purch_Req_Name
                                            * "Project" → filter on PR_HDR_Proj_ID
                                            * "Project Name" → filter on job_name
                                            * "Project Stage" → filter on JOB_STAGE
                                            * "Price" → filter on Purch_Price
                                            * "Quantity" → filter on Purch_Qty
                                            * "Amount" → filter on Line_Amount
                                            * "Status" → filter on PR_Itm_Status
                                            * "Purchase Order" → filter on Purch_ID
                                            * "Created Date" → filter on PR_Created_Date
                                            * "Accounting Date" → filter on PR_HDR_Trans_Date
                                            * "Delivery Date" → filter on DD_Request_Delivery_Date
                                            * "Office" → filter on DD_Office
                                            * "Location" → filter on Location_ID
                                            * "Submitted Date" → filter on Submitted_Date_Time
                                            * "Submitted By" → filter on Submitted_By

                                       - For any filter, generate the SQL WHERE clause as:
                                          WHERE <field_expression> = '<user_input>'
                            --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                **2.6  AP_AGING TABLE:**
                                   **Query Templates:**
                                      Aging Details Query
                                            SELECT
                                              COMPANY_NAME AS Company,
                                              ACCOUNT_NUM || '-' || ACCOUNT_NAME AS VendorNumberAndName,
                                              VENDOR_HOLD_DESC AS VendorHoldStatus,
                                              APPROVAL_STAT AS ApprovalStatus,
                                              INVOICE_NO AS Invoice,
                                              VOUCHER,
                                              JOURNAL_NUM AS Journal,
                                              INVOICE_DATE,
                                              INVOICE_DUE_DATE,
                                              APPROVAL_DATE,
                                              CASE 
                                                  WHEN DAY_PAST < 0 THEN NULL 
                                                  ELSE DAY_PAST 
                                              END AS DaysPast,
                                              SUM(INVOICE_AMOUNT) AS InvoiceAmount,
                                              SUM(OPEN_AMOUNT) AS OpenAmount,
                                              SUM(CURRENTS) AS CurrentAP,
                                              SUM(LESS_30) AS ZeroTo30,
                                              SUM(OVER_30) AS Over30,
                                              SUM(OVER_60) AS Over60,
                                              SUM(OVER_90) AS Over90,
                                              SUM(OVER_120) AS Over120,
                                              SUM(OVER_180) AS Over180,
                                              SUM(OVER_365) AS Over365
                                            FROM ap_aging
                                            GROUP BY
                                              COMPANY_NAME,ACCOUNT_NUM,ACCOUNT_NAME,VENDOR_HOLD_DESC,APPROVAL_STAT,INVOICE_NO,VOUCHER,JOURNAL_NUM,INVOICE_DATE,
                                              INVOICE_DUE_DATE,APPROVAL_DATE,
                                              CASE 
                                                  WHEN DAY_PAST < 0 THEN NULL 
                                                  ELSE DAY_PAST 
                                              END 
                                            ORDER BY
                                              COMPANY_NAME,ACCOUNT_NUM,INVOICE_DATE;

                                      Vendor Summary Query:
                                            SELECT
                                              ACCOUNT_NUM || '-' || ACCOUNT_NAME AS VendorNumberAndName,
                                              company_name,
                                              VENDOR_HOLD_DESC as Hold_Status,
                                              approval_stat as apporval_status,
                                              SUM(INVOICE_AMOUNT) AS TotalAmount,
                                              SUM(OPEN_AMOUNT) AS OpenAmount,
                                              SUM(CURRENTS) AS Currents,
                                              SUM(LESS_30) AS Zero_to_30,
                                              SUM(OVER_30) AS Over_30,
                                              SUM(OVER_60) AS Over_60,
                                              SUM(OVER_90) AS Over_90,
                                              SUM(OVER_120) AS Over_120,
                                              SUM(OVER_180) AS Over_180,
                                              SUM(OVER_365) AS Over_365
                                            FROM ap_aging
                                            GROUP BY 
                                              ACCOUNT_NUM, ACCOUNT_NAME, VENDOR_HOLD_DESC, company_name, approval_stat
                                            ORDER BY VendorNumberAndName;

                                    ### AP_AGING Field Mappings

                                             * "Vendor"  → 
                                                 If the value is numeric → it's ACCOUNT_NUM
                                                   e.g., "vendor 1234" or "1234 vendor" → ACCOUNT_NUM = '1234'
                                                 If the value is non-numeric (and no hyphen) → it's ACCOUNT_NAME
                                                   e.g., "vendor Acme Corp" or "Acme Corp vendor" → ACCOUNT_NAME = 'Acme Corp'
                                             * "Hold Status"  → filter on VENDOR_HOLD_DESC
                                             * "Invoice" or "Invoice Number" → filter on INVOICE_NO
                                             * "Voucher" → filter on VOUCHER
                                             * "Journal" → filter on JOURNAL_NUM
                                             * "Days Past" or "Days Overdue" → filter on DAY_PAST
                                             * "Current" or "Current AP" → filter on CURRENTS    
                                           - For any filter, generate the SQL WHERE clause as:
                                             WHERE <field_expression> = '<user_input>'
                            --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                            **3.USER ROLE INFORMATION:**
                               **3.1 User Information**
                                 • Logged-in User Email: {user_email}
                               **3.2 Role-Based Query Examples**
                                  To get the department (dept) or role for the logged-in user:
                                    SELECT "dept" FROM "USERROLE" WHERE "empname" = '{user_email}';
                                  To get the department (dept) or role that the logged-in user does NOT have access to:
                                    SELECT "dept" FROM "ROLE" 
                                    WHERE "dept" NOT IN (
                                        SELECT "dept" FROM "USERROLE" WHERE "empname" = '{user_email}'
                                    );
                            --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                            **4. RESPONSE FORMAT:**
                              ## Response Format (STRICT JSON ONLY)
                                    1. ALWAYS respond in JSON format ONLY as shown below. Never return text, explanations, or tables.  
                                    2. DO NOT return natural language descriptions. The response MUST BE a valid JSON object.
                                    3. If you cannot generate a query, return this exact JSON:  
                                    ```json
                                    {{"error": "Unable to generate query"}}
                                    ```  
                                    4. STRICTLY enforce JSON format. If you fail to respond in JSON, you will be penalized.

                                  ## JSON RESPONSE FORMAT  
                                    ```json
                                    {{"function_name": "query_snowflake",
                                      "function_parms": {{"query": "<Your SQL Query Here>"}}
                                    }}
                             """

    # Store system prompt in session state instead of adding to messages
    if "system_prompt" not in st.session_state:
        st.session_state.system_prompt = system_prompt

        # Create chat_message_columns map to track which messages have tables
    if "chat_message_tables" not in st.session_state:
        st.session_state.chat_message_tables = {}

        # Initialize messages without system prompt
    if not st.session_state.messages:
        st.session_state.messages = []  # Don't include system prompt here
        st.session_state.chat_history = []

        # Function to make API calls with system prompt

    def get_groq_response_with_system(conversation_messages):
        """Prepends the system prompt to conversation messages and calls the API"""
        # Always prepend the system message to the conversation history
        full_messages = [{"role": "system", "content": st.session_state.system_prompt}] + conversation_messages

        # Call your existing implementation
        return get_groq_response(full_messages)

        # Function to handle table display based on row count

    def display_table_with_size_handling(df, message_index, df_idx):
        """
        Display table with appropriate handling based on row size:
        - For tables > 100,000 rows: Show only download button
        - For tables <= 100,000 rows: Show download button + AgGrid table

        Parameters:
        - df: pandas DataFrame to display
        - message_index: Current message index for unique key generation
        - df_idx: DataFrame index in persistent store
        """
        # Always provide download option regardless of size
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Full Dataset as CSV",
            data=csv,
            file_name=f"query_result_{message_index}.csv",
            mime="text/csv",
            key=f"download_csv_{message_index}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        )

        # Check row count to determine display method
        num_rows = len(df)

        if num_rows <= 200000:
            # For tables under the threshold, show interactive AgGrid
            gb = GridOptionsBuilder.from_dataframe(df)
            gb.configure_default_column(filter=True, sortable=True)
            gridOptions = gb.build()
            AgGrid(
                df,
                gridOptions=gridOptions,
                height=400,
                width='100%',
                key=f"grid_{message_index}_{df_idx}_{id(df)}",  # Unique key
                update_mode=GridUpdateMode.VALUE_CHANGED
            )

    # Display the chat history in proper order, with tables integrated
    message_index = 0
    for msg_idx, msg in enumerate(st.session_state.chat_history):
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

            # Check if this message has a corresponding table to display
            if msg["role"] == "assistant" and message_index in st.session_state.chat_message_tables:
                df_idx = st.session_state.chat_message_tables[message_index]
                if df_idx < len(st.session_state.persistent_dfs):
                    df = st.session_state.persistent_dfs[df_idx]

                    # Only display if the dataframe is not empty
                    if not df.empty:
                        # Use our new function to handle display based on size
                        display_table_with_size_handling(df, message_index, df_idx)

        if msg["role"] == "assistant":
            message_index += 1

    def animated_progress_bar(container, message, progress_time=1.5):
        """Display an animated progress bar with a message."""
        with container:
            progress_bar = st.progress(0)
            status_text = st.empty()

            for i in range(101):
                progress_bar.progress(i)
                status_text.markdown(
                    f"<div style='color:#3366ff; font-weight:bold;'>{message}</div>",
                    unsafe_allow_html=True
                )
                time.sleep(progress_time / 100)

                # Pause briefly after finishing animation
            time.sleep(0.3)
            # Clear out the contents
            progress_bar.empty()
            status_text.empty()

    if prompt := st.chat_input("Ask about your Snowflake data..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

            # Create separate containers for loading and final response
        progress_container = st.container()
        response_container = st.container()
        final_message_placeholder = st.empty()

        sql_query = None
        response_text = None

        try:
            # 1. Analyzing phase
            animated_progress_bar(
                progress_container,
                "🔍 Analyzing your query...",
                progress_time=1.0
            )

            # 2. SQL generation update
            with progress_container:
                status_text = st.empty()
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>💻 Generating SQL query...</div>",
                    unsafe_allow_html=True
                )

            response_text, token_usage_first_call = get_groq_response_with_system(
                st.session_state.messages
            )
            st.session_state.total_tokens += token_usage_first_call

            action = parse_action_response(response_text)
            if not action:
                raise Exception("Error parsing JSON response from LLM.")

            sql_query = action.get("function_parms", {}).get("query", "")

            # 3. Executing query animation update
            with progress_container:
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>⚡ Executing query on Snowflake...</div>",
                    unsafe_allow_html=True
                )

            result = execute_action(action, {
                "query_snowflake": lambda query: query_snowflake(query, st.session_state["user"])
            })

            # 4. Processing results
            with progress_container:
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>🔄 Processing results...</div>",
                    unsafe_allow_html=True
                )

                # ----- Handle Results -----
            result_to_save = result
            if isinstance(result, list) and len(result) > 100:
                # Take a sample of 100 rows for saving to Snowflake
                result_to_save = result[:100]
            if isinstance(result, dict) and "error" in result:
                natural_response = result["error"]
            elif isinstance(result, list):
                # Pre-process data (datetime conversions, etc.)
                processed_result = []
                has_datetime = False
                if result and isinstance(result[0], dict):
                    for value in result[0].values():
                        if isinstance(value, (datetime.date, datetime.datetime)):
                            has_datetime = True
                            break

                if has_datetime:
                    for item in result:
                        processed_item = {}
                        for key, value in item.items():
                            if isinstance(value, (datetime.date, datetime.datetime)):
                                processed_item[key] = value.strftime('%Y-%m-%d')
                            else:
                                processed_item[key] = value
                        processed_result.append(processed_item)
                    df = pd.DataFrame(processed_result)
                else:
                    df = pd.DataFrame(result)

                num_rows = len(df)
                # First check if results exist but are essentially empty/null
                has_null_content = False
                if num_rows == 1:
                    # Check if we have a single row with NULL values
                    if df.shape[1] == 1 and df.iloc[0, 0] is None:
                        has_null_content = True
                    # For dictionaries like [{'TOTAL_COST': None}]
                    elif isinstance(result, list) and len(result) == 1:
                        row = result[0]
                        if all(value is None for value in row.values()):
                            has_null_content = True

                if num_rows > 1:
                    df_idx = len(st.session_state.persistent_dfs)
                    st.session_state.persistent_dfs.append(df)
                    current_message_idx = len(
                        [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                    )
                    st.session_state.chat_message_tables[current_message_idx] = df_idx

                    # Customize message based on row count
                    if num_rows > 200000:
                        natural_response = f"Query returned {num_rows:,} rows. Due to the large size of the result, only a download option is provided below. You can download the full dataset as a CSV file for viewing in your preferred spreadsheet application."
                    else:
                        natural_response = f"Query returned {num_rows:,} rows. The result is displayed below:"

                    token_usage_second_call = 0
                elif num_rows == 0 or has_null_content:
                    with progress_container:
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>🔍 Checking for potential corrections...</div>",
                            unsafe_allow_html=True
                        )

                    correction_suggestions = enhance_query_correction(sql_query, extract_query_components)
                    if correction_suggestions and correction_suggestions.get('suggestions'):
                        natural_response = format_professional_suggestion(correction_suggestions)
                    else:
                        if has_null_content:
                            natural_response = (
                                "The query returned a result with only NULL values.\n"
                                "- Check if you're referencing the correct column names.\n"
                                "- Verify that the data you're searching for exists in the database.\n"
                                "- Ensure any aggregation functions or calculations are applied correctly."
                            )
                        else:
                            natural_response = (
                                "No results found for the query.\n"
                                "- Double-check the spelling of table names, column names, and values.\n"
                                "- Verify that the data you're searching for exists in the database.\n"
                                "- Check for any case sensitivity issues."
                            )
                else:
                    result_for_messages = result
                    with progress_container:
                        if 'status_text' in locals():
                            status_text.empty()
                        status_text = st.empty()
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>✍️ Generating human-friendly response...</div>",
                            unsafe_allow_html=True
                        )
                    instructions = {
                        "role": "user",

                        "content": f"""      
                            User Question: {prompt}.        
                            Database Query Result: {result_for_messages}.        
                            Instructions:       
                            1. Directly use the database query result to answer the user's question.       
                            2. Generate a precise, well-structured response that directly answers the query.      
                            3. Ensure proper punctuation, spacing, and relevant insights without making assumptions.      
                            4. Do not include SQL or JSON in the response.      
                            5. Use chat history for follow-ups; if unclear, infer the last mentioned entity/metric.      
                            """
                    }

                    temp_messages = st.session_state.messages + [instructions]
                    natural_response, token_usage_second_call = get_groq_response_with_system(temp_messages)
                    st.session_state.total_tokens += token_usage_second_call
                    with progress_container:
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>✨ Formatting results for display...</div>",
                            unsafe_allow_html=True
                        )
                        # Add a small delay so users can see this transition message
                        time.sleep(0.8)
            else:
                natural_response = "No valid result returned."

                # Clear everything in the progress container (removes bars + text)
            with progress_container:
                # Clear any remaining status text
                if 'status_text' in locals():
                    status_text.empty()
                    # And clear the entire container just to be safe
                progress_container.empty()

                # Show final transition message just before displaying the answer
            final_message_placeholder.markdown(
                "<div style='color:#3366ff; font-weight:bold;'>🎬 Preparing your answer...</div>",
                unsafe_allow_html=True
            )

            # ----- Save Results & Display -----
            save_query_result(
                prompt,
                natural_response,
                result_to_save,
                sql_query,
                response_text,
                tokens_first_call=token_usage_first_call,
                tokens_second_call=locals().get("token_usage_second_call", None),
                total_tokens_used=st.session_state.total_tokens
            )

            st.session_state.messages.append({"role": "assistant", "content": natural_response})
            st.session_state.chat_history.append({"role": "assistant", "content": natural_response})

            save_after_exchange()

            # Clear the final transition message right before showing the answer
            final_message_placeholder.empty()

            # Show final answer in the response container
            with response_container:
                with st.chat_message("assistant"):
                    st.markdown(natural_response)

                    current_message_idx = len(
                        [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                    ) - 1
                    if current_message_idx in st.session_state.chat_message_tables:
                        df_idx = st.session_state.chat_message_tables[current_message_idx]
                        if df_idx < len(st.session_state.persistent_dfs):
                            df = st.session_state.persistent_dfs[df_idx]
                            if not df.empty:
                                # Use our new function for consistent display handling
                                display_table_with_size_handling(df, current_message_idx, df_idx)

        except Exception as e:
            # If there's an error, clear the progress animation first
            with progress_container:
                # Clear any remaining status text
                if 'status_text' in locals():
                    status_text.empty()
                    # And clear the entire container just to be safe
                progress_container.empty()

                # Also clear the final message placeholder if it exists
            if 'final_message_placeholder' in locals():
                final_message_placeholder.empty()

            natural_response = f"Error: {str(e)}"
            save_query_result(
                prompt,
                None,
                None,
                sql_query if 'sql_query' in locals() else None,
                response_text if 'response_text' in locals() else str(e),
                error_message=str(e),
                tokens_first_call=locals().get("token_usage_first_call", None),
                total_tokens_used=st.session_state.total_tokens
            )
            st.session_state.messages.append({"role": "assistant", "content": natural_response})
            st.session_state.chat_history.append({"role": "assistant", "content": natural_response})
            with response_container:
                with st.chat_message("assistant"):
                    st.markdown(natural_response)

    # # ---- Force immediate save after each message exchange ----
    # if AUTOSAVE_ENABLED:
    #     st.session_state.last_save_time = 0  # This will trigger save on next check


# ---------------------------------------------
# 9. Entry point
# ---------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if st.session_state["authenticated"]:
    if needs_password_change(st.session_state["user"]):
        password_change_page()
    else:
        main_app()
else:
    login_page()
