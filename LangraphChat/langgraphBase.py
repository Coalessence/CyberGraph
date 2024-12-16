from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.graph.message import add_messages
import json
from langchain_core.messages import ToolMessage, HumanMessage, RemoveMessage, SystemMessage, AIMessage, AnyMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
from graphTools import *
from operator import add
from IPython.display import Image, display
from pydantic import BaseModel
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver
from entityExtractionBase import EntityExtractionGraph
from utils import bfs_shortest_path, streamline_path, data_entities
from langchain_core.runnables.graph import CurveStyle, MermaidDrawMethod, NodeStyles

def tool_output_add(a,b):
    if isinstance(b, int):
        a=[]
    else:
        a.append(b)
        flat_list = []
        for xs in a:
            for x in xs:
                flat_list.append(x)
        a=flat_list
    return a

class State(MessagesState):
    summary: str
    retry_count: int
    conversation_stage: str
    start_node: str
    start_data: str
    next_step: str
    current_node: str
    current_data: List[str]
    target_node: str
    target_data: List[str]
    tool_messages: Annotated[list[AnyMessage], add_messages]
    path : List[str]
    question: str


class BasicToolNode:
    """A node that runs the tools requested in the last AIMessage."""

    def __init__(self, tools: list) -> None:
        self.tools_by_name = {tool.name: tool for tool in tools}

    def __call__(self, inputs: dict):
        if messages := inputs.get("tool_input", []):
          True  
        else:
            raise ValueError("No message found in input")
        outputs = []
        for message in messages:
            for tool_call in message.tool_calls:
                tool_result = self.tools_by_name[tool_call["name"]].invoke(
                    tool_call["args"]
                )
                outputs.append(
                        content=json.dumps(tool_result),
                )
        return {"tool_output": outputs}

class ChatGraph():
    """
    Advanced conversation management with multiple sophisticated features
    """
    
    
    def __init__(self, model, debug=False):
        self.model = model
        self.cve_tools = tools["cve"]
        self.cna_tools = tools["cna"]
        self.capec_tools = tools["capec"]
        self.cwe_tools = tools["cwe"]
        self.debug = debug
        # Configurable parameters
        self.max_retry_attempts = 3
        self.max_conversation_length = 30
        self.conversation_summary_threshold = 10

    def create_graph(self):
        """
        Create a more sophisticated state graph with multiple nodes and advanced routing
        """
        graph_builder = StateGraph(State)

        graph_builder.add_node("cve_agent", self.cve_agent)
        graph_builder.add_node("cna_agent", self.cna_agent)
        graph_builder.add_node("capec_agent", self.capec_agent)
        graph_builder.add_node("cwe_agent", self.cwe_agent)
        graph_builder.add_node("cve_tools", ToolNode(self.cve_tools, messages_key="tool_messages"))
        graph_builder.add_node("cna_tools", ToolNode(self.cna_tools, messages_key="tool_messages"))
        graph_builder.add_node("capec_tools", ToolNode(self.capec_tools, messages_key="tool_messages"))
        graph_builder.add_node("cwe_tools", ToolNode(self.cwe_tools, messages_key="tool_messages"))
        graph_builder.add_node("human_intervention", self.handle_human_intervention)
        graph_builder.add_node("summarize", self.summarize_conversation)
        graph_builder.add_node("init", self.initialize_state)
        graph_builder.add_node("designPath", self.design_path)
        graph_builder.add_node("router", self.route)
        graph_builder.add_node("update", self.updater)
        graph_builder.add_node("response_agent", self.response_agent)
        graph_builder.add_node("handle_tool_error", self.handle_tool_error)

        entity_extraction_graph = EntityExtractionGraph(self.model).create_entity_extraction_graph()
        graph_builder.add_node("entity_extraction", entity_extraction_graph)
        
        graph_builder.add_edge(START, "init")
        
        graph_builder.add_conditional_edges(
            "init",
            self.should_summarize,
            {
                "summarize": "summarize",
                "continue": "entity_extraction"
            }
        )
        graph_builder.add_edge("summarize", "init")
        graph_builder.add_edge("entity_extraction", "designPath")
        graph_builder.add_edge("designPath", "router")
        
        # Conditional tool routing
        graph_builder.add_conditional_edges(
            "cve_agent", 
            self.advanced_tools_condition, 
            {
                "tools": "cve_tools",
                "human_intervention": "human_intervention",
                "error": "handle_tool_error",
            }
        )
        
        graph_builder.add_conditional_edges(
            "cna_agent", 
            self.advanced_tools_condition, 
            {
                "tools": "cna_tools",
                "human_intervention": "human_intervention",
                "error": "handle_tool_error",
            }
        )
        
        graph_builder.add_conditional_edges(
            "capec_agent", 
            self.advanced_tools_condition, 
            {
                "tools": "capec_tools",
                "human_intervention": "human_intervention",
                "error": "handle_tool_error",
            }
        )
        
        graph_builder.add_conditional_edges(
            "cwe_agent", 
            self.advanced_tools_condition, 
            {
                "tools": "cwe_tools",
                "human_intervention": "human_intervention",
                "error": "handle_tool_error",
            }
        )
        
        graph_builder.add_edge("handle_tool_error", "router")
        
        graph_builder.add_conditional_edges(
            "router",
            self.route_to_data_entity,
            {
                "cve": "cve_agent",
                "cna": "cna_agent",
                "capec": "capec_agent",
                "cwe": "cwe_agent",
                "end": "response_agent"
            }
        )
        graph_builder.add_edge("human_intervention", "router")
        graph_builder.add_edge("cve_tools", "update")
        graph_builder.add_edge("cna_tools", "update")
        graph_builder.add_edge("capec_tools", "update")
        graph_builder.add_edge("cwe_tools", "update")
        
        graph_builder.add_conditional_edges(
            "update",
            self.finish_condition,
            {
                "end": "response_agent",
                "continue": "router"
            }
        )
        
        graph_builder.add_edge("response_agent", END)
        
        # Persistence
        memory = MemorySaver()
        return graph_builder.compile(checkpointer=memory)
    
    def initialize_state(self, state: State):
        """
        Initialize the state with default values
        """
        state["summary"] = ""
        state["retry_count"] = 0
        state["conversation_stage"] = "initialize"
        state["start_node"] = ""
        state["start_data"] = ""
        state["current_node"] = ""
        state["current_data"] = ""
        state["target_node"] = ""
        state["path"] = []
        state["question"] = state["messages"][-1].content
        state["next_step"] = ""
        return state
    
    def handle_tool_error(self, state) -> dict:
        error = state.get("error")
        tool_calls = state["tool_messages"][-1].tool_calls
        return {
            "tool_messages": [
                ToolMessage(
                    content=f"Error: {repr(error)}\n please fix your mistakes.",
                    tool_call_id=tc["id"],
                )
                for tc in tool_calls
            ]
        }
    
    def movePrompt(self):
        
        template = PromptTemplate.from_template(template="""
            Task: You are an intelligent assistant with access to various tools. Your task is to use input data to find the requested output information.
            Instructions:
            
            1. Use only the given input data
            2. Do not use internal knowledge or add additional information
            3. Use tools to find the requested output information
            4. Only find the requested output information
            5. Make only one tool per input data
            6. Do not make duplicate tool calls
            7. Use only the input data as tool call parameters
            8. Do not use history of other tool calls
            
            Here is the input data: {input}
            The input data belongs to the following category: {category}
            Find the requested output information: {output}
            \n""")
        
        return template
    
    def respondPrompt(self):
        
        prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a helpful assistant tasked with converting raw data and a question 
        into a clear, conversational, and easy-to-understand answer. 
        Follow these guidelines:
        - Use natural, friendly language
        - Explain the information in a way that's easy to comprehend
        - Provide context when necessary
        - If the data is complex, break it down into simpler terms
        - Ensure the answer directly addresses the original question"""),
        ("human", """Given the following question:
        {question}
        And this response data:
        {data}
        Please write a clear, concise, and human-friendly answer that directly addresses the question.""")
        ])
        
        return prompt
            
    
    def route (self, state:State):

        path=state.get("path", [])
        stage=state.get("conversation_stage")
        next_step=""
        
        if(self.debug):
            print("path ", path)
            print("stage ", stage)
        
        if path:
            next_step=path.pop(0)
            
            if stage=="initialize":
                stage="first_step"
            else:    
                stage="move_to_data"
        else:
            if stage == "retrive_data":
                stage="respond"
            else:
                stage="retrive_data"
        
        return {"next_step": next_step, "conversation_stage": stage}
         
    def design_path(self, state: State):
        """
        Use function in utils to extract and correct path
        """
        path = bfs_shortest_path(graph_schema, state["start_node"], state["target_node"])
        current_node=path.pop(0)
        corrected_path = streamline_path(path)  
        return {"path": corrected_path, "current_node": current_node, "current_data": state["start_data"]}
    
    def updater(self, state: State):
        """
        Update the state with the next step
        """
        if self.debug:
            print("state ", state)
            print("output: ", state["tool_messages"])
            
        messages=state["tool_messages"]
        stage=state["conversation_stage"]
        current_data=[]
        toRemove=[]
        
        for message in messages:
            if isinstance(message, ToolMessage):
                if stage=="move_to_data" or stage=="first_step":
                    message.content=json.loads(message.content)
                    for answer in message.content:
                        current_data.append(answer["answer"])
                else:
                    message.content=json.loads(message.content)
                    for answer in message.content:
                        current_data.append(answer)
                toRemove.append(RemoveMessage(id=message.id))
        
        return {"current_data": current_data, "tool_messages": toRemove, "current_node": state["next_step"]}
    
    
    def response_agent(self, state: State):
        """
        Invokes the agent model to generate a response based on the current state. Given
        the question, it will decide to retrieve using the retriever tool, or simply end.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with the agent response appended to messages
        """
        try:
            current_data = state["current_data"]
            
            prompt=self.respondPrompt()
            
            chain = prompt | self.model
            
            if self.debug:
                print("response agent invoke with: ", current_data)
            
            response = chain.invoke({
                    "question": state["question"],
                    "data": current_data
            })
            
            if self.debug:
                print("response ", response)
            
            return {"messages": [response]} 

        except Exception as e:
            state['retry_count'] += 1
            if state['retry_count'] <= self.max_retry_attempts:
                return {"conversation_stage": "retry"}
            else:
                return {"conversation_stage": "end"}
    
    def finish_condition(self, state: State):
        """
        Determine if the conversation should end
        """
        if state.get("conversation_stage") == "retrive_data":
            return "end"
        return "continue"
    
    def advanced_tools_condition(self, state: State):
        """
        Advanced decision making for tool usage or human intervention
        """
        messages = state.get('tool_messages', [])
        last_message = messages[-1] if messages else None
        
        if self.debug:
            print("in advanced tools condition ", state)
        
        if last_message and last_message.tool_calls:
            return "tools"
        
        if self.requires_human_intervention(last_message):
            return "human_intervention"
        
        return "error"
    
    def route_to_data_entity(self, state: State):
        """
        Route the conversation to the correct data entity based on the user input
        """
        
        if self.debug:
            print("in route condition ", state)
        
        stage = state.get("conversation_stage")
        
        if stage == "first_step":
            if state["current_node"] in data_entities:
                return state["current_node"]
            else:
                return state["next_step"]
        if stage == "retrive_data":
            return state["current_node"]
        if stage == "move_to_data":
            return state["current_node"]
        if stage == "respond":
            return "end" 
    
    def requires_human_intervention(self, message):
        """
        Determine if human intervention is needed
        """
        # TODO: Implement human intervention logic
        return False
    
    def should_summarize(self, state: State):
        """
        Decide whether to summarize conversation
        """
        messages = state.get('messages', [])
        if len(messages) > self.conversation_summary_threshold:
            return "summarize"
        return "continue"
    
    def cve_agent(self,state: State):
        """
        Invokes the agent model to generate a response based on the current state. Given
        the question, it will decide to retrieve using the retriever tool, or simply end.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with the agent response appended to messages
        """
        try:
            current_data = state.get("current_data")
            current_node = state.get("current_node")
            conversation_stage = state.get("conversation_stage")
            
            if self.debug:
                print("cve Agent")
            
            llm_with_tools = self.model.bind_tools(self.cve_tools)
            
            
            if conversation_stage == "retrive_data":
                target_data = state.get("target_data")
                    
            if conversation_stage == "move_to_data" or conversation_stage == "first_step":
                target_data = state.get("next_step")
            
            prompt=self.movePrompt()
            
            chain =prompt | llm_with_tools
            if self.debug:
                print("invoking chain with ", current_data, current_node, target_data)
            response = chain.invoke({
                    "input": current_data,
                    "category": current_node,
                    "output": target_data
                })
            response.pretty_print()
            
            return {"tool_messages": [response]} 

        except Exception as e:
            print("errore per qulche cazzo di motivo ", e)
            state['retry_count'] += 1
            if state['retry_count'] <= self.max_retry_attempts:
                return {"conversation_stage": "retry"}
            else:
                return {"conversation_stage": "end"}
            
    def cna_agent(self,state: State):
        """
        Invokes the agent model to generate a response based on the current state. Given
        the question, it will decide to retrieve using the retriever tool, or simply end.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with the agent response appended to messages
        """
        try:
            current_data = state.get("current_data")
            current_node = state.get("current_node")
            conversation_stage = state.get("conversation_stage")
            
            if self.debug:
                print("cna Agent")
            
            llm_with_tools = self.model.bind_tools(self.cna_tools)
            
            
            if conversation_stage == "retrive_data":
                target_data = state.get("target_data")
                    
            if conversation_stage == "move_to_data" or conversation_stage == "first_step":
                target_data = state.get("next_step")
            
            prompt=self.movePrompt()
            
            chain =prompt | llm_with_tools
            if self.debug:
                print("invoking chain with ", current_data, current_node, target_data)
            response = chain.invoke({
                    "input": current_data,
                    "category": current_node,
                    "output": target_data
                })
            
            return {"tool_messages": [response]} 

        except Exception as e:
            print("errore per qulche cazzo di motivo ", e)
            state['retry_count'] += 1
            if state['retry_count'] <= self.max_retry_attempts:
                return {"conversation_stage": "retry"}
            else:
                return {"conversation_stage": "end"}

    def capec_agent(self,state: State):
        """
        Invokes the agent model to generate a response based on the current state. Given
        the question, it will decide to retrieve using the retriever tool, or simply end.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with the agent response appended to messages
        """
        try:
            current_data = state.get("current_data")
            current_node = state.get("current_node")
            conversation_stage = state.get("conversation_stage")
            
            if self.debug:
                print("capec Agent")
            
            llm_with_tools = self.model.bind_tools(self.capec_tools)
            
            
            if conversation_stage == "retrive_data":
                target_data = state.get("target_data")
                    
            if conversation_stage == "move_to_data" or conversation_stage == "first_step":
                target_data = state.get("next_step")
            
            prompt=self.movePrompt()
            
            chain =prompt | llm_with_tools
            if self.debug:
                print("invoking chain with ", current_data, current_node, target_data)
            response = chain.invoke({
                    "input": current_data,
                    "category": current_node,
                    "output": target_data
                })
            
            return {"tool_messages": [response]} 

        except Exception as e:
            print("errore per qulche cazzo di motivo ", e)
            state['retry_count'] += 1
            if state['retry_count'] <= self.max_retry_attempts:
                return {"conversation_stage": "retry"}
            else:
                return {"conversation_stage": "end"}
            
    def cwe_agent(self,state: State):
        """
        Invokes the agent model to generate a response based on the current state. Given
        the question, it will decide to retrieve using the retriever tool, or simply end.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with the agent response appended to messages
        """
        try:
            current_data = state.get("current_data")
            current_node = state.get("current_node")
            conversation_stage = state.get("conversation_stage")
            
            if self.debug:
                print("cwe Agent")
            
            llm_with_tools = self.model.bind_tools(self.cwe_tools)
            
            
            if conversation_stage == "retrive_data":
                target_data = state.get("target_data")
                    
            if conversation_stage == "move_to_data" or conversation_stage == "first_step":
                target_data = state.get("next_step")
            
            prompt=self.movePrompt()
            
            chain =prompt | llm_with_tools
            if self.debug:
                print("invoking chain with ", current_data, current_node, target_data)
            response = chain.invoke({
                    "input": current_data,
                    "category": current_node,
                    "output": target_data
                })
            
            return {"tool_messages": [response]} 

        except Exception as e:
            print("errore per qulche cazzo di motivo ", e)
            state['retry_count'] += 1
            if state['retry_count'] <= self.max_retry_attempts:
                return {"conversation_stage": "retry"}
            else:
                return {"conversation_stage": "end"}
            
    def retry_conversation(self, state: State):
        """
        Implement conversation retry logic
        """
        retry_message = AIMessage(
            content=f"I'm having difficulty understanding. Let me try again. "
            f"Attempt {state['retry_count']} of {self.max_retry_attempts}"
        )
        message=state["messages"] + [retry_message]
        return {"messages": message, "conversation_stage": "retry"}
    
    def summarize_conversation(state: State, model):

        summary = state["summary"]
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
    
    def handle_human_intervention(self, state: State):
        """
        Handle cases requiring explicit human input
        """
        intervention_message = AIMessage(
            content="I need clarification on some details. Could you provide more information?"
        )
        message=state['messages'].append(intervention_message)
        
        return {"messages": message, "conversation_stage": "human_intervention"}

def main():
    graph_model = ChatGraph(None)
    graph = graph_model.create_graph()
    
    display(
    Image(
        graph.get_graph().draw_mermaid_png(
            draw_method=MermaidDrawMethod.API,
            output_file_path="graph.png",
        )
    )
)
    
if __name__ == "__main__":
    main()