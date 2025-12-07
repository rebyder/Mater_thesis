# Software vulnerability detection through Agentic Architecture and CodeQL queries

This is a Master's thesis project that aims to develop an agent-based architecture for generating new, more accurate and predictive CodeQL queries. 
CodeQL queries, written in '.ql' files, are used by the CodeQL SAST tool to analyze source code and detect potential vulnerabilities. 
The proposed architecture is intended to automate and enhance the creation these queries trying to improve their quality and abilities to indetify previously uncovered secutiry issues.

---

## High-level Pipeline

The project executes 5 steps pipeline:

### **1. Input**
- The user have to add the --sataset-èath argument, describing the path to the directory containg all the vulnerble files.

### **2. Analyzer Agent: Dataset Analysis**
The Analyzer Agent inkokes the CodeQL tool to scan each file. Steps:
- the Analyzer Agent call the `CodeQLSastTool`
- the tool creates a CodeQl database wiht this command:
`CODEQL_CLI database create CODEQL_DB_PATH --language=python --source-root`
where "CODEQL_CLI" is the command to invoke CodeQL CLI, "CODEQL_DB_PATH" the path to the new CodeQL database and "source-root" is the path to source code directory
- the tool analyzes the new database with:
`CODEQL_CLI database  "analyze" CODEQL_DB_PATH queries_to_run --format=sarifv2.1.0 --output`
where "queries_to_run" are the eventual new queries that will be crated for the other agents, "format=sarifv2.1." is the output report format and "output" is the path for it.
- the agent call the ParseSarifTool to parse the sarif report in way much more understandable for the LLMs.
- note: the Analyzer agent is not a ReAct agent because it doesn't reason but just invokes the necessaty tool.
### **3. Suggestor Agent**
The Suggest Agent takes the output of the Analyzer and studying the vulnerablities contained in it try to create some suggestions to create new, more accurate and predictive CodeQL queries.
It can call this tools:
- WebSearchTool: for web searching if the agent requires some insights about the vulnerabilities or CodeQL queries
- SuggestTool: tool to generate a detection plan for a new CodeQL query
