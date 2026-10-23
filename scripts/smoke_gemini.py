"""Smoke test: does Gemini return a function call for reset_password?"""
import os
import sys

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
model = os.getenv("AGENT_MODEL")
for name, value in (("GEMINI_API_KEY", api_key), ("AGENT_MODEL", model)):
    if not value:
        print(f"Missing {name} in environment / .env")
        sys.exit(1)

reset_password = types.FunctionDeclaration(
    name="reset_password",
    description="Reset the password for a user. The temporary password is sent to the email on file.",
    parameters=types.Schema(
        type="OBJECT",
        properties={"user_id": types.Schema(type="STRING", description="The user's id, e.g. priya.s")},
        required=["user_id"],
    ),
)

config = types.GenerateContentConfig(
    temperature=0,
    tools=[types.Tool(function_declarations=[reset_password])],
    # Only return the call, never execute anything.
    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
)

try:
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents="I forgot my password, my user id is priya.s",
        config=config,
    )
except Exception as e:
    print(f"Gemini call failed: {type(e).__name__}: {e}")
    sys.exit(1)

if response.function_calls:
    for call in response.function_calls:
        print(call.name, dict(call.args))
else:
    print("No function call returned. Text reply:")
    print(response.text)
