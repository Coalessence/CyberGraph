from langgraphBase import ChatGraph
from langchain_core.messages import HumanMessage


def print_update(update):
    for k, v in update.items():
        for m in v["messages"]:
            m.pretty_print()
        if "summary" in v:
            print(v["summary"])   

def continuous_react_chat(config):
    # Initialize conversation history
    history = ""

    print("You can now chat with the assistant. Type 'exit' to stop.")
    
    while True:
        # Get user input
        user_input = input("You: ")

        # Exit condition
        if user_input.lower() == "exit":
            print("Ending the chat.")
            break
        
        history += f"\nUser: {user_input}"

        # Create context for the graph execution
        context = {
            "history": history,
            "user_input": user_input
        }
        
        input_message = HumanMessage(content=user_input)
        input_message.pretty_print()
        for event in ChatGraph.stream({"messages": [input_message]}, config, stream_mode="updates"):
            print_update(event)

if __name__ == "__main__":
    
    config = {"configurable": {"thread_id": "1"}}
    continuous_react_chat(config)