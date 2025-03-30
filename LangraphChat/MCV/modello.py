from dataclasses import dataclass
from typing import List, Optional
from langchain_core.messages import HumanMessage

@dataclass
class Message:
    content: str
    is_user: bool
    timestamp: str

class ChatModel:
    def __init__(self, model = None, chat_graph = None):
        self.messages: List[Message] = []
        self.model = model
        self.chat_graph = chat_graph
        
    def add_message(self, message: Message):
        self.messages.append(message)
        
    def get_messages(self) -> List[Message]:
        return self.messages
    
    def get_ai_response(self, user_input: str) -> str:
        input_message = HumanMessage(content=user_input)
        config = {"configurable": {"thread_id": "1"}}
        
        response = None
        for event in self.chat_graph.stream(
            {"messages": [input_message]}, 
            config, 
            stream_mode="updates"
        ):
            response = self._process_update(event)
        return response
    
    def _process_update(self, update):
        for k, v in update.items():
            if k in ["response_agent"]:
                for m in v["messages"]:
                    return m.content
                if "summary" in v:
                    return v["summary"]
        return None