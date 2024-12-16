from typing import TypedDict, Annotated, List, Optional
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, END
from utils import entity_mapping, data_entities
from langchain_ollama import ChatOllama
from graphTools import categories, graph_schema
from langgraph.types import Command, interrupt
from langgraph.checkpoint.memory import MemorySaver
from operator import add

# Define the state for our graph
class EntityState(TypedDict):
    question: str
    start_node: str
    start_data: str
    target_data: str
    target_node: str
    rejected_start: Annotated[list[str], add]
    rejected_target: Annotated[list[str], add]
    feedback: str


class EntityExtractionGraph():

    def __init__(self, model):
        self.llm=model    
    
    
    def extract_entities(self, state: EntityState):
        # Initialize the language model
        llm = self.llm
        
        # Create a prompt for entity extraction
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert at extracting key entities from user questions. 
            Analyze the question and identify:
            1. The known entity (something specific that is already known) 
            2. The desired entity (what needs to be fetched or discovered)
            
            Respond in JSON format with the following structure:
            {{
                "known_entity": "...",
                "desired_entity": "..."
            }}
            
            If no clear known or desired entity can be determined, use null. do not add additional informations"""),
            ("human", "Question: {question}")
        ])
        
        parser = JsonOutputParser()

        chain = prompt | llm | parser

        try:
            result = chain.invoke({"question": state['question']})
            
            return {
                "start_data": result.get('known_entity'),
                "target_data": result.get('desired_entity'),
            }
        except Exception as e:
            print(f"Error in entity extraction: {e}")
            return {
                "start_data": None,
                "target_data": None,
            }


    def verify_entities(self, state: EntityState):
        llm = self.llm
        
        verification_prompt = ChatPromptTemplate.from_messages([
            ("system", """Verify the extracted entities from the original question. 
            Confirm if the known and desired entities make sense in the context of the question.
            
            If the entities seem incorrect or unclear, provide suggestions or null values.
            
            Respond in JSON format:
            {{
                "known_entity": "...",
                "desired_entity": "...",
                "is_valid": true/false
            }}"""),
            ("human", "Question: {question}\nKnown Entity: {start_data}\nDesired Entity: {target_data}")
        ])
        
        parser = JsonOutputParser()
        
        chain = verification_prompt | llm | parser
        
        try:
            result = chain.invoke({
                "question": state['question'], 
                "start_data": state.get('start_data', ''),
                "target_data": state.get('target_data', '')
            })
            
            # If verification fails, reset entities
            if not result.get('is_valid', False):
                return {
                    "start_data": None,
                    "target_data": None,
                }
            
            return state
        except Exception as e:
            print(f"Error in entity verification: {e}")
            return state
        
    def start_entity_categorization(self, state: EntityState):
        
        entity=state.get('start_data')
        
        category_list = "\n".join([f"- {cat}" for cat in categories if cat not in state.get('rejected_start')])
        
        categorization_prompt = PromptTemplate.from_template(template=f"""Task: Categorize the given entity into one of the predefined categories.

            Available Categories:
            {categories}

            Instructions:
            1. Carefully analyze the entity's characteristics, context, and inherent properties.
            2. Select the MOST APPROPRIATE category that best describes the entity.
            3. If the entity does not clearly fit into any category, respond with "UNCATEGORIZED".
            4. Provide a brief (1-2 sentence) explanation for your categorization.
            5. Select only from the Available Categories.
            6. Do not use history of others categorizations.
            7. All software and operating systems names are considered as products.

            Input Entity: {entity}

            Respond in JSON format:
            {{{{
                "category": "Selected Category",
                "reasoning": "Explanation of why this category was chosen"
            }}}}

            Example:
            Entity: "CVE-2011-1425"
            Output: {{{{
                "category": "CVE",
                "reasoning": "The name format matches the CVE standard for vulnerabilities."
            }}}}
            Example:
            Entity: "php"
            Output: {{{{
                "category": "Product",
                "reasoning": "PHP is a software product."
            }}}}
            """, partial_variables={"categories": category_list})

        parser = JsonOutputParser()
        
        chain = categorization_prompt | self.llm | parser
        
        results=chain.invoke({"entity":entity})
        
        start_node=results['category'].lower()
        
        return {"start_node" : start_node}
    
    def target_entity_categorization(self, state: EntityState):
        
        entity=state.get('target_data')
        
        category_list=""
        for cat in data_entities:
            category_list+=f"{cat}: {cat}, "
            for sub in graph_schema[cat]:
                category_list+=f"{sub}, "
            category_list+="\n"
            
        n_top=len(data_entities)
        
        
        categorization_prompt = PromptTemplate.from_template(template=f"""Task: Categorize the given entity into one of the predefined {n_top} categories.

            Available Categories:
            {data_entities}

            Each of this categories has a list of sub entities that can be used to categorize the entity.
            {category_list}
            
            Instructions:
            1. Carefully analyze the entity's characteristics, context, and inherent properties.
            2. Select the MOST APPROPRIATE category that best describes the entity.
            3. If the entity does not clearly fit into any category, respond with "None".
            4. Provide a brief (1-2 sentence) explanation for your categorization.

            
            Input Entity: {entity}

            Respond in JSON format:
            {{{{
                "category": "Selected Category",
                "reasoning": "Explanation of why this category was chosen"
            }}}}

            Example:
            Entity: "lastest cve"
            Output: {{{{
                "category": "CVE",
                "reasoning": "The name suggest it is a CVE."
            }}}}
            """)

        parser = JsonOutputParser()
        
        chain = categorization_prompt | self.llm | parser
        
        results=chain.invoke({"entity":entity})
        
        target_node=results['category'].lower()

        return {"target_node": target_node}
    
    def human_feedback(self, state: EntityState):
        
        feedback=True
        print("================================ Human feedback ================================")
        print(f"""Is Known entity {state.get('start_data')} correctly categorized as {state.get('start_node')}?""")
        feedback_start = input("Is the categorization correct? (yes/no): ")
        if not feedback_start.lower() == "yes":
            state['rejected_start'].append(state.get('start_node'))
            feedback=False
            
        print(f"""Is Desired entity {state.get('target_data')} correctly categorized as {state.get('target_node')}?""")
        feedback_target = input("Is the categorization correct? (yes/no): ")
        if not feedback_target.lower() == "yes":
            state['rejected_target'].append(state.get('target_node'))
            feedback=False
            
        if not feedback:
            print("I will try a different categorization then.")
        
        return {"feedback": feedback}
    
    def final_changes(self, state: EntityState):
        
        start_node=state.get('start_node').lower()
        target_node=state.get('target_node', '').lower()
        start_data=state.get('start_data')
        target_data=state.get('target_data')
        
        return {"start_node" : start_node, "target_node": target_node, "start_data": start_data, "target_data": target_data}
    
# Build the Graph
    def create_entity_extraction_graph(self):
        workflow = StateGraph(EntityState)
        
        # Add nodes
        workflow.add_node("extract", self.extract_entities)
        workflow.add_node("verify", self.verify_entities)
        workflow.add_node("categorize_input", self.start_entity_categorization)
        workflow.add_node("categorize_output", self.target_entity_categorization)
        workflow.add_node("human_feedback", self.human_feedback)
        workflow.add_node("final_changes", self.final_changes)
        
        # Define edges
        workflow.set_entry_point("extract")
        workflow.add_edge("extract", "verify")
        workflow.add_conditional_edges(
            "verify",
            lambda state: "categorize_input" if state['start_data'] and state['target_data'] else "extract",
            {
                "categorize_input": "categorize_input",
                "extract": "extract"
            }
        )
        workflow.add_edge("categorize_input", "categorize_output")
        workflow.add_edge("categorize_output", "human_feedback")
        workflow.add_conditional_edges(
            "human_feedback",
            lambda state: "final_changes" if state['feedback'] else "categorize_input",
            {
                "final_changes": "final_changes",
                "categorize_input": "categorize_input"
            }
        )
             
        # Compile the graph
        return workflow.compile()
    
def main():
    # Create the graph
    entity_graph = EntityExtractionGraph(model=ChatOllama(model="llama3.1:8b",temperature=0)).create_entity_extraction_graph()
    
    # Example questions
    questions = [
        "What are the vulnerabilities of openssl",
        "What is CVE-2021-1234 attack pattern",
        "Get latest cve",
    ]
    
    # Run entity extraction for each question
    for question in questions:
        print(f"\nQuestion: {question}")
        
        result = entity_graph.invoke(input={"question": question})
        print("Extracted Entities:")
        print(f"Known Entity: {result.get('start_data')}")
        print(f"Known Entity Type: {result.get('start_node')}")
        print(f"Desired Entity: {result.get('target_node')}")
        print(f"Desired Entity Type: {result.get('target_data')}")

if __name__ == "__main__":
    main()