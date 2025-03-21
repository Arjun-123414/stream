import os
import re
import sqlparse
import snowflake.connector
from typing import List, Dict, Any, Tuple, Union, Set
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


def extract_tables_from_query(query: str) -> Set[str]:
    """
    Extract table names from a SQL query, properly handling function calls and column references.
    Uses a more sophisticated approach to avoid misidentifying columns or functions as tables.
    """
    # Clean and normalize query
    query = query.strip()

    # Use sqlparse to format and tokenize the query
    try:
        # If sqlparse is available, use it for better parsing
        parsed = sqlparse.parse(query)[0]
        tables = set()

        # Process the FROM clause to extract main tables
        from_seen = False
        from_clause_tokens = []

        for token in parsed.tokens:
            # Look for FROM keyword
            if token.ttype is sqlparse.tokens.Keyword and token.value.upper() == 'FROM':
                from_seen = True
                continue

            # Collect tokens after FROM until we hit another clause
            if from_seen:
                if token.ttype is sqlparse.tokens.Keyword and token.value.upper() in (
                'WHERE', 'GROUP', 'ORDER', 'HAVING', 'LIMIT'):
                    from_seen = False
                else:
                    from_clause_tokens.append(token)

        # Extract table names from the FROM clause tokens
        current_table = ""
        for token in from_clause_tokens:
            if token.ttype in (
            sqlparse.tokens.Name, sqlparse.tokens.Literal.String.Single, sqlparse.tokens.Literal.String.Symbol):
                current_table = token.value.strip('"\'')
                tables.add(current_table.upper())
            elif isinstance(token, sqlparse.sql.Identifier):
                current_table = token.get_real_name().strip('"\'')
                tables.add(current_table.upper())

        # Also look for JOIN clauses
        join_seen = False
        current_identifier = ""

        for token in parsed.tokens:
            if token.ttype is sqlparse.tokens.Keyword and 'JOIN' in token.value.upper():
                join_seen = True
                continue

            if join_seen:
                if isinstance(token, sqlparse.sql.Identifier):
                    current_identifier = token.get_real_name().strip('"\'')
                    tables.add(current_identifier.upper())
                    join_seen = False
                elif token.ttype in (
                sqlparse.tokens.Name, sqlparse.tokens.Literal.String.Single, sqlparse.tokens.Literal.String.Symbol):
                    current_identifier = token.value.strip('"\'')
                    tables.add(current_identifier.upper())
                    join_seen = False

        return tables

    except (ImportError, IndexError):
        # Fallback to regex-based extraction if sqlparse fails or isn't available
        # This regex specifically looks for tables after FROM and JOIN keywords
        # It avoids capturing functions like EXTRACT() or column references
        tables = set()

        # Clean up the query - remove comments, normalize whitespace
        query = re.sub(r'--.*$', ' ', query, flags=re.MULTILINE)
        query = re.sub(r'/\*.*?\*/', ' ', query, flags=re.DOTALL)
        query = re.sub(r'\s+', ' ', query)

        # Pattern to match tables after FROM clauses
        from_pattern = r'FROM\s+(?:"([^"]+)"|([a-zA-Z0-9_]+))(?:\s+(?:AS\s+)?[a-zA-Z0-9_]+)?'
        from_matches = re.finditer(from_pattern, query, re.IGNORECASE)

        for match in from_matches:
            table = next((group for group in match.groups() if group), None)
            if table:
                tables.add(table.upper())

        # Pattern to match tables in JOIN clauses
        join_pattern = r'JOIN\s+(?:"([^"]+)"|([a-zA-Z0-9_]+))(?:\s+(?:AS\s+)?[a-zA-Z0-9_]+)?'
        join_matches = re.finditer(join_pattern, query, re.IGNORECASE)

        for match in join_matches:
            table = next((group for group in match.groups() if group), None)
            if table:
                tables.add(table.upper())

        return tables


def get_table_to_role_mapping() -> Dict[str, List[str]]:
    """
    Build a mapping of tables to the roles that have access to them.
    """
    mapping = {}

    # Query to get all roles and their table access
    roles_query = """SELECT "dept", "table_access" FROM "ROLE";"""
    roles_result = _query_snowflake(roles_query)

    if roles_result and "error" not in roles_result[0]:
        for role_entry in roles_result:
            dept = role_entry.get("dept")
            if dept and role_entry.get("table_access"):
                tables = [table.strip() for table in role_entry["table_access"].split(",")]
                for table in tables:
                    if table not in mapping:
                        mapping[table] = []
                    mapping[table].append(dept)

    return mapping


def query_snowflake(query: str, user_email: str, params: Tuple = ()) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Executes a query on Snowflake but first checks if the user has permission to access the referenced tables.
    """
    conn = None
    cursor = None
    try:
        # Get tables the user is allowed to access
        allowed_tables = get_allowed_tables_for_user(user_email)
        if not allowed_tables:
            return {"error": "Access Denied: You do not have permission to access any tables."}

        # Get the user's roles
        dept_query = """SELECT "dept" FROM "USERROLE" WHERE "empname" = %s"""
        dept_result = _query_snowflake(dept_query, params=(user_email,))
        user_roles = []
        if dept_result and "error" not in dept_result[0] and dept_result[0].get("dept"):
            user_roles = [dept.strip() for dept in dept_result[0]["dept"].split(",")]

        # Extract table names from the query
        tables_in_query = extract_tables_from_query(query)

        # Get a mapping of tables to required roles
        table_role_mapping = get_table_to_role_mapping()

        # Check if any table in the query is not allowed for this user
        unauthorized_tables = []
        for table in tables_in_query:
            if table not in [t.upper() for t in allowed_tables]:
                unauthorized_tables.append(table)

        if unauthorized_tables:
            # Find which roles would be needed to access these tables
            missing_roles = set()
            for table in unauthorized_tables:
                if table in table_role_mapping:
                    for role in table_role_mapping[table]:
                        if role not in user_roles:
                            missing_roles.add(role)

            # Construct a more helpful error message
            if missing_roles:
                missing_roles_str = ", ".join(missing_roles)
                return {
                    "error": f"Access Denied: You need the following role(s) to access the requested data: {missing_roles_str}"}
            else:
                unauthorized_str = ", ".join(unauthorized_tables)
                return {
                    "error": f"Access Denied: You do not have permission to access the following table(s): {unauthorized_str}"}

        # Proceed with executing the query if all tables are allowed
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

        # Fetch results and return them as a list of dictionaries
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
    Fetch schema details dynamically from Snowflake and return the schema for
    tables that the user has permission to access.
    """
    conn = None
    cursor = None
    try:
        # Get the list of tables the user is allowed to access
        allowed_tables = get_allowed_tables_for_user(user_email)

        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()

        # Fetch column details only for tables the user has access to
        schema_details: Dict[str, List[Tuple[str, str]]] = {}
        for table in allowed_tables:
            try:
                cursor.execute(f'DESCRIBE TABLE "{table}";')
                schema_details[table] = [(row[0], row[1]) for row in cursor.fetchall()]
            except Exception as e:
                # Skip tables that might not exist or have other issues
                continue

        return schema_details
    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
