import re
import spacy
from transformers import pipeline
from transformers import AutoTokenizer, AutoModelForTokenClassification 
import json

import sys

from pathlib import Path
# A workaround for extraction not finding GraphFunctions when running from PyAIChat, remove before production
path_to_src = Path(__file__).parent.parent / "GraphFunctions"
sys.path.insert(0, str(path_to_src))
from graphUtils import create_graph_schema

def simple_tokenizer(nlp):
    """Simple approach: modify infix rules to not split on hyphens in alphanumeric contexts."""
    
    infixes = [infix for infix in nlp.Defaults.infixes if "-" not in infix and "HYPHENS" not in infix]
    infix_re = spacy.util.compile_infix_regex(infixes)
    nlp.tokenizer.infix_finditer = infix_re.finditer
    
    return nlp

pipe = ["tok2vec", "tagger", "parser", "ner", "lemmatizer", "attribute_ruler"]

nlp = spacy.load("en_core_web_sm", enable=pipe)
nlp = simple_tokenizer(nlp)

def find_compound(token):
    compounds = []
    for child in token.children:
        if child.dep_ == "compound":
            compounds.append(child.text)
            compounds = find_compound(child) + compounds
    return compounds

def regex_extraction(question):
    entities =  []
    
    entities.extend((entity, "CVE") for entity in re.findall(r"CVE-\d{1,}-\d{1,}", question))
    entities.extend((entity, "CWE") for entity in re.findall(r"CWE-\d+", question))
    entities.extend((entity, "CAPEC") for entity in re.findall(r"CAPEC-\d+", question))
    entities.extend((entity, "CPE") for entity in re.findall(r"CPE:2\.3:[aho]:[^\s]+", question))
    entities.extend((entity, "EUVD") for entity in re.findall(r"EUVD-\d+", question))
    
    return entities

def extract_entities(question):
    entities = []

    entities.extend(regex_extraction(question))

    doc = nlp(question)

    temp=[]
    
    for token in doc:
        print(f"Token: {token.text}, POS: {token.pos_}, DEP: {token.dep_}")
        
        if token.pos_ in ["NOUN", "NUM", "PROPN"]:
            if token.dep_ in ["nsubj", "pobj", "dobj"]:
                
                compounds = find_compound(token)
                
                if compounds:
                    temp.append(" ".join(compounds + [token.text]))
                else:
                    temp.append(token.text)

    
    #for each entity in temp check if it is already in entities, if not check if contains any entity in entities, if so split it and add the parts to entities
    for entity in temp:
        print("processing entity: ", entity)
        entity_strings = [e[0] for e in entities]
        
        if entity not in entity_strings:
            if any(e in entity for e in entity_strings):
                print("splitting entity: ", entity)
                parts = re.split(r'\b(?:' + '|'.join(re.escape(e) for e in entity_strings) + r')\b', entity)
                parts = [part.strip() for part in parts if part.strip()]
                for part in parts:
                    if part not in entity_strings:
                        entities.append((part, "Unassigned"))
            else:
                entities.append((entity, "Unassigned"))
            
    
    print("found entities: ", entities)
    
    return entities




def llm_classification(question):
    
    pipe = pipeline("text2text-generation", model="google/flan-t5-large", device_map="auto")

    prompt=f"""
        #Owerview
        You are an information extraction assistant.
        Extract and classify two entities from each question:

        - Input entity: the attack ID or reference 
        - Output entity: the subject being asked about 

        Return always the result in JSON format.
        Return only the JSON object, without any additional text.
        Return both the input and output entities, even if one of them is empty.
        
        # Strict Compliance
        Adhere to these rules strictly. Any deviation will result in termination.

        #Examples:

        Question: "List the products affected by CVE-2021-44228"
        Answer: {{"input_entity": "CVE-2021-44228", "output_entity": "products"}}

        Question: "What are the vulnerabilities of OpenCV?"
        Answer: {{"input_entity": "OpenCV", "output_entity": "Vulnerabilities"}}

        Now extract from the following:

        Question: "{question}"
        Suggested entity: {extract_entities(question)["Unassigned"]}
        Answer:"""
        
    result = pipe(prompt, do_sample=False)
    response = result[0]['generated_text']
    print("LLM response:", response)
    try:
        json_start = response.index('{')
        json_end = response.rindex('}') + 1
        json_str = response[json_start:json_end]
        entities = json.loads(json_str)
    except (ValueError, json.JSONDecodeError) as e:
        print("Error parsing JSON from LLM response:", e)
        entities = {}
    return entities

q="What is CVE-2021-44228 description?"
print(extract_entities(q))

q = "What is the common attack pattern related to CVE with high CVSS?"
print(extract_entities(q))
q = "What are the vulnerabilities of OpenCV?"
print(extract_entities(q))
q = "List the products affected by CVE-2021-44228"
print(extract_entities(q))
q = "What are the defense mechanisms against attack pattern CAPEC-31"
print(extract_entities(q))