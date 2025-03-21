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

        # Retrieve the roles (departments) that are not assigned to the user for constructing the error message.
        dept_query = """SELECT "dept" FROM ROLE 
WHERE "dept" NOT IN (
    SELECT "dept" FROM USERROLE WHERE "empname" = %s
);"""
        dept_result = _query_snowflake(dept_query, params=(user_email,))
        if dept_result and "error" not in dept_result[0] and dept_result[0].get("dept"):
            # In case of multiple departments, join them with commas.
            dept_list = [dept.strip() for dept in dept_result[0]["dept"].split(",")]
            role_str = ", ".join(dept_list)
        else:
            role_str = "Unknown"

        # Extract table names from the query.
        table_pattern = re.compile(r'FROM\s+([a-zA-Z0-9_".]+)', re.IGNORECASE)
        tables_in_query = table_pattern.findall(query)

        # Check if any table in the query is not allowed.
        for table in tables_in_query:
            clean_table = table.replace('"', '').replace("'", "").strip()
            if clean_table.upper() not in [t.upper() for t in allowed_tables]:
                # Return error with the user's role instead of the table name.
                return {"error": f"Access Denied: You do not have permission to role : \"{role_str}\""}

        # Proceed with executing the query if all tables are allowed.
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

        # Fetch results and return them as a list of dictionaries.
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



def get_schema_details(user_email: str) -> Union[Dict[str, List[Tuple[str, str]]], Dict[str, str]]:
    """
    Fetch schema details dynamically from Snowflake and return the full schema,
    without filtering based on allowed tables.
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

        # Fetch table names from Snowflake.
        cursor.execute("SHOW TABLES;")
        tables = [row[1] for row in cursor.fetchall()]

        # Fetch column details for each table.
        schema_details: Dict[str, List[Tuple[str, str]]] = {}
        for table in tables:
            cursor.execute(f"DESCRIBE TABLE {table};")
            schema_details[table] = [(row[0], row[1]) for row in cursor.fetchall()]

        # Return the full schema details without filtering.
        return schema_details
    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
