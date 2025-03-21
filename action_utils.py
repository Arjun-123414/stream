# action_utils.py
import re
from json import loads, JSONDecodeError
from typing import Dict, Any

def parse_action_response(response_text: str) -> Dict[str, Any]:
    """Check if the AI’s response is in the right format."""
    try:
        # Use regex to extract the JSON object from the response
        json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
        if not json_match:
            print("Error: No JSON object found in the response.")
            # print(f"Response: {response_text}")  # Debugging: Print the response
            return {}

        # Extract the JSON string
        json_str = json_match.group(0)

        # Validate and parse the JSON
        json_function = loads(json_str)

        # Make sure the response has the right keys
        if not isinstance(json_function, dict) or "function_name" not in json_function or "function_parms" not in json_function:
            print("Error: Response is not in the expected format.")
            # print(f"Response: {response_text}")  # Debugging: Print the response
            return {}

        return json_function

    except JSONDecodeError:
        print("Error: Response is not valid JSON.")
        # print(f"Response: {response_text}")  # Debugging: Print the response
        return {}

    except Exception as e:
        print(f"Error: {str(e)}")
        # print(f"Response: {response_text}")  # Debugging: Print the response
        return {}
def execute_action(action: Dict[str, Any], available_actions: Dict[str, Any]) -> Dict[str, Any]:
    """Do what the AI says (execute the action)."""
    function_name = action.get("function_name")
    function_parms = action.get("function_parms")

    if function_name not in available_actions:
        return {"error": f"Unknown function name: {function_name}"}

    try:
        action_function = available_actions[function_name]
        return action_function(**function_parms)
    except Exception as e:
        return {"error": f"Error executing {function_name}: {str(e)}"}