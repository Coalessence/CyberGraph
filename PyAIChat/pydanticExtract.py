from dataclasses import dataclass
from GraphFunctions.graphUtils import create_graph_schema, getGraphConnection
from typing import Literal, Union, Annotated, List
from neo4j import GraphDatabase
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
from pydantic_ai.providers.openai import OpenAIProvider
import asyncio


class Entity(BaseModel):
    text: str
    type: str
    confidence: float = 0.8

@dataclass
class MyDeps:
    graphClient: GraphDatabase
    

# Create the entity extraction agent
entity_agent = Agent(
    model_name='llama3.2', 
    provider=OpenAIProvider(base_url='http://localhost:11434/v1'),
    output_type=List[Entity],
    system_prompt="""
    You are an entity extraction agent. Given a user question, extract all relevant entities.

    For each entity found:
    - Extract the exact text from the question
    - Classify it with the most appropriate type
    - Assign a confidence score (0.0 to 1.0)
    
    Be thorough but precise. Only extract entities that are clearly mentioned in the text.
    """
)

async def extract_entities(question: str) -> List[Entity]:
    """Extract entities from a user question"""
    try:
        result = await entity_agent.run(question)
        return result.output
    except Exception as e:
        print(f"Error extracting entities: {e}")
        return List(entities=[])

def print_entities(extracted: List[Entity]):
    """Pretty print the extracted entities"""
    print(f"\nOriginal Question: {extracted.original_question}")
    print("-" * 50)
    
    if not extracted.entities:
        print("No entities found.")
        return
    
    for entity in extracted.entities:
        print(f"Entity: {entity.text}")
        print(f"Type: {entity.type}")
        print(f"Confidence: {entity.confidence:.2f}")
        print("-" * 30)

# Example usage
async def main():
    # Test questions
    test_questions = [
        "What is the weather like in New York tomorrow?",
        "Can you schedule a meeting with John Smith at Microsoft for next Friday?",
        "How much does the iPhone 15 cost at Apple Store?",
        "What programming languages does Google use for their search engine?",
        "When was the last time Tesla stock price was above $200?"
    ]
    
    for question in test_questions:
        print(f"\nProcessing: {question}")
        entities = await extract_entities(question)
        print_entities(entities)
        print("=" * 60)

if __name__ == "__main__":
    # Run the example
    asyncio.run(main())
