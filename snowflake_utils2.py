#snowflake_utils.py
import os
import re
import snowflake.connector
from typing import List, Dict, Any, Tuple, Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_private_key():
    """
    Parse the private key from environment variable
    """
    private_key_content = os.getenv("SNOWFLAKE_PRIVATE_KEY")
    if private_key_content:
        p_key = load_pem_private_key(
            private_key_content.encode(),
            password=None,
            backend=default_backend()
        )
        return p_key
    else:
        raise ValueError("Private key not found in environment variables")


def _query_snowflake(query: str, params: Tuple = ()) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Internal helper to execute a query on Snowflake without performing access checks.
    This is used for metadata queries (e.g., fetching user department or allowed tables).
    """
    conn = None
    cursor = None
    try:
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),  # Use private key instead of password
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results
    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_allowed_tables_for_user(user_email: str) -> List[str]:
    """
    Returns a list of table names the user is allowed to access,
    based on the user's department mapping and department access rules.
    Supports users with multiple departments (comma-separated).
    """
    # Define the two tables that should be accessible to all users.
    always_allowed_tables = ["USERROLE", "ROLE"]

    # Query to get the user's department(s)
    dept_query = """SELECT "dept" FROM "USERROLE" WHERE "empname" = %s"""
    dept_result = _query_snowflake(dept_query, params=(user_email,))

    # If no department is found, return only the always allowed tables.
    if not dept_result or "error" in dept_result[0] or not dept_result[0].get("dept"):
        return always_allowed_tables

    # Extract and handle multiple departments
    dept_list = [dept.strip() for dept in dept_result[0]["dept"].split(",")]

    allowed_tables_set = set()

    for dept in dept_list:
        # Query to get the allowed tables for each department
        access_query = """SELECT "table_access" FROM "ROLE" WHERE "dept" = %s"""
        access_result = _query_snowflake(access_query, params=(dept,))

        if access_result and "error" not in access_result[0] and access_result[0].get("table_access"):
            # Extract and handle multiple tables per department
            tables = [table.strip() for table in access_result[0]["table_access"].split(",")]
            allowed_tables_set.update(tables)

    # Add the always allowed tables to the user's allowed tables
    allowed_tables_set.update(always_allowed_tables)

    return list(allowed_tables_set)



def extract_table_names(query: str) -> List[str]:
    """
    Extract real table names from a SQL query,
    excluding any CTEs defined using WITH ... AS.
    """
    # Normalize whitespace
    query = query.strip().replace("\n", " ").replace("\r", " ")

    # Step 1: Capture all CTEs
    cte_pattern = re.compile(r'WITH\s+([\w"]+)\s+AS\s*\(', re.IGNORECASE)
    cte_names = cte_pattern.findall(query)

    # Step 2: Capture FROM and JOIN table names
    table_pattern = re.compile(r'\b(?:FROM|JOIN)\s+([a-zA-Z0-9_."`]+)', re.IGNORECASE)
    all_tables = table_pattern.findall(query)

    # Step 3: Clean and remove CTEs
    cleaned_tables = [
        tbl.replace('"', '').replace("'", "").strip()
        for tbl in all_tables
        if tbl.replace('"', '').strip().upper() not in [cte.replace('"', '').strip().upper() for cte in cte_names]
    ]

    return list(set(cleaned_tables))  # Remove duplicates


def query_snowflake(query: str, user_email: str, params: Tuple = ()) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Executes a query on Snowflake but first checks if the user has permission to access the referenced tables.
    """
    conn = None
    cursor = None
    try:
        allowed_tables = get_allowed_tables_for_user(user_email)
        if not allowed_tables:
            return {"error": "Access Denied: You do not have permission to access any tables."}

        # Retrieve the roles (departments) not assigned to the user (for error message).
        dept_query = """
        SELECT "dept" FROM ROLE 
        WHERE "dept" NOT IN (
            SELECT value FROM TABLE(SPLIT_TO_TABLE(
                (SELECT "dept" FROM USERROLE WHERE "empname" = %s), ',')));
        """
        dept_result = _query_snowflake(dept_query, params=(user_email,))
        if dept_result and "error" not in dept_result[0] and dept_result[0].get("dept"):
            dept_list = [dept.strip() for dept in dept_result[0]["dept"].split(",")]
            role_str = ", ".join(dept_list)
        else:
            role_str = "Unknown"

        # ✅ Extract and check only real table names
        tables_in_query = extract_table_names(query)

        for table in tables_in_query:
            if table.upper() not in [t.upper() for t in allowed_tables]:
                return {"error": f"Access Denied: You do not have permission to role : \"{role_str}\""}

        # Proceed with query execution
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()
        cursor.execute(query, params)

        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results

    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_schema_details(user_email: str) -> Union[Dict[str, Dict[str, Dict[str, Union[str, List[str]]]]], Dict[str, str]]:
    """
    Fetch schema details dynamically from Snowflake.
    Includes all columns, but only fetches distinct values for non-numeric columns.
    """

    conn = None
    cursor = None
    try:
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()

        # Step 1: Get all tables
        cursor.execute("SHOW TABLES;")
        tables = [row[1] for row in cursor.fetchall()]

        # Step 2: For each table, get column names and data types
        schema_details = {}

        # Define numeric types to skip for distinct value fetching
        numeric_types = {'NUMBER', 'FLOAT', 'DECIMAL', 'DOUBLE', 'INT', 'INTEGER', 'BIGINT', 'SMALLINT','DATE'}

        for table in tables:
            cursor.execute(f"DESCRIBE TABLE {table};")
            columns = cursor.fetchall()
            schema_details[table] = {}

            for col_name, data_type, *_ in columns:
                col_info = {"data_type": data_type}
                # Only fetch distinct values for non-numeric columns
                if not any(numeric in data_type.upper() for numeric in numeric_types):
                    try:
                        cursor.execute(f"SELECT DISTINCT {col_name} FROM {table} LIMIT 4")
                        values = [str(row[0]) for row in cursor.fetchall() if row[0] is not None]
                        col_info["sample_values"] = values
                    except Exception as e:
                        col_info["sample_values"] = f"Error: {str(e)}"

                schema_details[table][col_name] = col_info

        return schema_details

    except Exception as e:
        return {"error": str(e)}

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_user_departments(user_email: str) -> List[str]:
    """
    Retrieves the user's departments from Snowflake based on their email.
    """
    dept_query = """SELECT "dept" FROM "USERROLE" WHERE "empname" = %s"""
    dept_result = _query_snowflake(dept_query, params=(user_email,))

    if dept_result and "error" not in dept_result[0]:
        dept_str = dept_result[0]["dept"]
        return [dept.strip().lower() for dept in dept_str.split(",")]
    return []


# ------------------ Sample Questions ------------------ #

# Map each department to its list of sample questions.
department_sample_questions = {
    "prod": [
        "Fetch all details of home depot where goods are invoiced",
        "Fetch all details of home depot for open order"
    ],
    "misc": [
        "items",
        "items report"
    ],
    "general": [
        "vendor details"
    ],
    "finance": [
        "Paid Invoice Summary"
    ],
    "aging": [
        "aging details",
        "Vendor Summary",
    ],
    "purchase": [
        "show purhcase requisition or show PR or all PR or all purchase requisition"
    ]
}


def get_table_sample_questions(table_name: str, user_email: str) -> List[str]:
    """
    Returns sample questions specific to a table.
    You can customize this with table-specific questions.
    """
    # Add table-specific questions (expand this dictionary as needed)
    table_questions = {
        "USERROLE": [
            "Show me all user roles",
            "Which departments do users belong to?"
        ],
        "ROLE": [
            "What table access does each department have?",
            "Show me role details"
        ],
        # Add more table-specific questions here
    }

    # Combine default questions with any table-specific ones
    if table_name.upper() in table_questions:
        return table_questions[table_name.upper()]
    # return default_questions





