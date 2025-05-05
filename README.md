# Project Files Structure
* `webapp`: it's a *react* project that utilizes the CVE graph database (inside they're both defined the *front* and *back* end);
* `retrieve_data.py`: script used to retrieve all sort of info related to vulnetabilities (CNA, CVE, CWE, CAPEC);
* `create_graph.py`: script that uses the files retrieved by the `retrieve_data.py` and creates a *Neo4j* graph database;

# Prerequisite
* Have installed locally *Neo4j Desktop* with *APOC* libraries;
* *Node* and *npm* (by installing node you'll also get npm);
* *Yarn* (after you've installed node, run `npm install --global yarn`)

# How to Run This Code
* `retrieve_data.py`/ `create_graph.py`: 
   * Create a `.env` file in the root folder containing all the credantials, like:
     ```
     NEO4J_URI=...
     NEO4J_USERNAME=...
     NEO4J_PASSWORD=...
     NIST_API_KEY=...
     ```
     Where `NIST_API_KEY` refers to the key provided by the *NIST* and used to call their API, meanwhile `NEO4J_[...]` are all the parameters for connecting to a graph database in the *Neo4j Desktop* application
   * Then, simply run these script using *Python3* (i.e. `python3 [script]`). If you encounter some errors make sure to have locally insalled all the dependencies
* `webapp`: 
   *  Inside the `client` and `server` folder run `yarn install`
   *  Create a `.env` file in the `server` folder containing all the credentials necessary to connect to a local Neo4j graph database (*see previous points*)
   *  Then run in 2 separate terminals `yarn start`, one being inside the `client` folder and the other one being inside the `server` one
=======
# Project Files Structure
* `webapp`: it's a *react* project that utilizes the CVE graph database (inside they're both defined the *front* and *back* end);
* `retrieve_data.py`: script used to retrieve all sort of info related to vulnetabilities (CNA, CVE, CWE, CAPEC);
* `create_graph.py`: script that uses the files retrieved by the `retrieve_data.py` and creates a *Neo4j* graph database;

# Prerequisite
* Have installed locally *Neo4j Desktop* with *APOC* libraries;
* *Node* and *npm* (by installing node you'll also get npm);
* *Yarn* (after you've installed node, run `npm install --global yarn`)

# How to Run This Code
* `retrieve_data.py`/ `create_graph.py`: 
   * Create a `.env` file in the root folder containing all the credantials, like:
     ```
     NEO4J_URI=...
     NEO4J_USERNAME=...
     NEO4J_PASSWORD=...
     NIST_API_KEY=...
     ```
     Where `NIST_API_KEY` refers to the key provided by the *NIST* and used to call their API, meanwhile `NEO4J_[...]` are all the parameters for connecting to a graph database in the *Neo4j Desktop* application
   * Then, simply run these script using *Python3* (i.e. `python3 [script]`). If you encounter some errors make sure to have locally insalled all the dependencies
* `webapp`: 
   *  Inside the `client` and `server` folder run `yarn install`
   *  Create a `.env` file in the `server` folder containing all the credentials necessary to connect to a local Neo4j graph database (*see previous points*)
   *  Then run in 2 separate terminals `yarn start`, one being inside the `client` folder and the other one being inside the `server` one
