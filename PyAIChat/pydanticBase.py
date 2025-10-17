from typing import Literal, Union
from pydantic import BaseModel, Field
from rich.prompt import Prompt
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.tools import RunContext

