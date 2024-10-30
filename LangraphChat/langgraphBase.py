import os
from typing import Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.graph.message import add_messages
import json
from langchain_core.messages import ToolMessage, HumanMessage, RemoveMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from graphTools import *
from IPython.display import Image, display
from pydantic import BaseModel
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from langchain_ollama import ChatOllama
from langchain_nvidia_ai_endpoints import ChatNVIDIA

model=ChatOllama(model="llama3.1:8b",temperature=0)

class State(MessagesState):
    summary: str
    

class BasicToolNode:
    """A node that runs the tools requested in the last AIMessage."""

    def __init__(self, tools: list) -> None:
        self.tools_by_name = {tool.name: tool for tool in tools}

    def __call__(self, inputs: dict):
        if messages := inputs.get("messages", []):
            message = messages[-1]
        else:
            raise ValueError("No message found in input")
        outputs = []
        for tool_call in message.tool_calls:
            tool_result = self.tools_by_name[tool_call["name"]].invoke(
                tool_call["args"]
            )
            outputs.append(
                ToolMessage(
                    content=json.dumps(tool_result),
                    name=tool_call["name"],
                    tool_call_id=tool_call["id"],
                )
            )
        return {"messages": outputs}
     
    
def handle_tool_error(state) -> dict:
    error = state.get("error")
    tool_calls = state["messages"][-1].tool_calls
    return {
        "messages": [
            ToolMessage(
                content=f"Error: {repr(error)}\n please fix your mistakes.",
                tool_call_id=tc["id"],
            )
            for tc in tool_calls
        ]
    }


def create_tool_node_with_fallback(tools: list) -> dict:
    return ToolNode(tools).with_fallbacks(
        [RunnableLambda(handle_tool_error)], exception_key="error"
    )


def _print_event(event: dict, _printed: set, max_length=1500):
    current_state = event.get("dialog_state")
    if current_state:
        print("Currently in: ", current_state[-1])
    message = event.get("messages")
    if message:
        if isinstance(message, list):
            message = message[-1]
        if message.id not in _printed:
            msg_repr = message.pretty_repr(html=True)
            if len(msg_repr) > max_length:
                msg_repr = msg_repr[:max_length] + " ... (truncated)"
            print(msg_repr)
            _printed.add(message.id)
    
class Assistant:
    def __init__(self, runnable: Runnable):
        self.runnable = runnable

    def __call__(self, state: State, config: RunnableConfig):
        while True:
            configuration = config.get("configurable", {})
            id = configuration.get("id", None)
            state = {**state, "user_info": id}
            result = self.runnable.invoke(state)
            if not result.tool_calls and (
                not result.content
                or isinstance(result.content, list)
                and not result.content[0].get("text")
            ):
                messages = state["messages"] + [("user", "Respond with a real output.")]
                state = {**state, "messages": messages}
            else:
                break
        return {"messages": result}

agent_prompt = PromptTemplate(
    template="""system",
    "You are a helpful assistant that finds information about software products vulnerbilities. "
    "If tools require follow up questions, "
    "make sure to ask the user for clarification. Make sure to include any "
    "available options that need to be clarified in the follow up questions "
    "Do only the things the user specifically requested. Do not use your internal knowledge. ",
    Here is the user question: {question} \n""",
    input_variables=["question"]
)


def agent(state):
    """
    Invokes the agent model to generate a response based on the current state. Given
    the question, it will decide to retrieve using the retriever tool, or simply end.

    Args:
        state (messages): The current state

    Returns:
        dict: The updated state with the agent response appended to messages
    """
    
    messages = state["messages"]
    llm_with_tools = model.bind_tools(tools)
    
    #chain = prompt | llm_with_tools | StrOutputParser()
    
    chain =llm_with_tools
    
    response = chain.invoke(messages)
    
    return {"messages": [response]}

def summarize_conversation(state: State, model):

    summary = state.get("summary", "")
    if summary:
        summary_message = (
            f"This is a summary of the conversation to date: {summary}\n\n"
            "Extend the summary by taking into account the new messages above:"
        )

    else:
        summary_message = "Create a summary of the conversation above:"
        
    messages = state["messages"] + [HumanMessage(content=summary_message)]
    response = model.invoke(messages)

    delete_messages = [RemoveMessage(id=m.id) for m in state["messages"][:-2]]
    return {"summary": response.content, "messages": delete_messages}

graph_builder = StateGraph(State)
tool_node = ToolNode(tools)

graph_builder.add_node("agent", agent)
graph_builder.add_node("tools", tool_node)

graph_builder.add_conditional_edges(
    "agent",
    tools_condition,
    ["tools", END],
)
graph_builder.add_edge(START, "agent")
graph_builder.add_edge("tools", "agent")

memory = MemorySaver()

ChatGraph = graph_builder.compile(checkpointer=memory)


try:
    image=Image(ChatGraph.get_graph().draw_mermaid_png(output_file_path="graph.png"))
except Exception:
    pass
