from langgraphBase import ChatGraph
from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama

model=ChatOllama(model="llama3.1:8b",temperature=0)

chat=ChatGraph(model=model, debug=True).create_graph()


def print_update(update):
    for k, v in update.items():
        if k in ["response_agent"]:
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
        for event in chat.stream({"messages": [input_message]}, config, stream_mode="updates"):
            print_update(event)

def debug_chat(config):
    # Initialize conversation history
    
    #cwe 264
    #CVE-1999-1383
    user_input = "What are the attack patterns on php?"
    
    input_message = HumanMessage(content=user_input)
    for chunk in chat.stream({"messages": input_message},config, stream_mode="values"):
        final_result = chunk
        print("new event")
        print(final_result) 

if __name__ == "__main__":
    
    config = {"configurable": {"thread_id": "1"}}
    continuous_react_chat(config)
    #debug_chat(config)