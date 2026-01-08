"""
Module that defines the AnalyzerAgent, a ReAct agent responsible for validation of source code analysis
using CodeQL and parsing the SARIF report. 

Principal classes:
    - CodeQLAnalyzerInput (BaseModel): structured input for the AnalyzerAgent
    - AnalyzerAgent: agent that executes CodeQL analysis and SARIF parsing
    - CWEMappingModel: model for mapping CodeQL rule IDs to CWEs

Main functions: 
    - run_analysis: executes CodeQL analysis and SARIF parsing
    - map_rule_to_cwe: maps CodeQL rule IDs to CWEs using LLM
    - add_cwe_snippet: enriches SARIF report with code snippets and CWE mapping
    - step: executes a single step of the ReAct cycle
    - load_existing_queries: loads existing CodeQL queries for a given CWE

"""

from typing import Optional
from tools import CodeQLSastTool, ParseSarifTool
from agents_dir.base_agent import BaseAgent, ReActChain, SharedMemory, BaseTaskInput
from pydantic import BaseModel, Field
from openai import OpenAI
from langchain_core.messages import SystemMessage
from procedures.summ_procedure import SummaryProcedure
from procedures.action_procedure import ActionProcedure
from procedures.tought_procedure import ThoughtProcedure
from prompts import SUMMARY_TEMPLATE, THOUGHT_TEMPLATE, ACTION_TEMPLATE
from config import OUTPUT_QUERIES_PATH
QUERY_PACK_TOT = "/Users/rebeccaderosa/.codeql/packages/codeql/python-queries/1.6.8/Security"
import json
import os
from pathlib import Path

client = OpenAI()

class CodeQLAnalyzerInput(BaseTaskInput):
    """
    Input for the CodeQL analysis tool.
    
    Attributes:
        source_root (str): Path to the source code root directory.
        output_report_filepath (str): Path to the output SARIF report file.
    
    """

    source_root: str = Field(...)
    output_report_filepath: str = Field(...)
       
class CWEMappingModel(BaseModel):
    """
    Pydantic model for mappinf Rule ID -> CWE through LLM.
    
    Attributes:
        cwe (str): CWE ID
        description (str): brief description of the vulnerability

    """
    cwe: str = Field(...)
    description: str = Field(...)



class AnalyzerAgent(BaseAgent):
    """ReAct Agent that executes CodeQL analysis, SARIF parsing and generates enriched report with validation audits.
    
    Args:
        prompt_template (str): the prompt template that will be formatted and used as input to the LLM.
        shared_memory (SharedMemory): shared memory for the agent.
        tools (list): list of tools available to the agent.
        logpath (str | None): optional path for logging.
    
    Attributes:
        prompt_template (str): the prompt template that will be formatted and used as input to the LLM.
        shared_memory (SharedMemory): shared memory for the agent.
        tools (list): list of tools available to the agent.
        logpath (str | None): optional path for logging.
    
    Methods:
        run_analysis(task): executes the CodeQL analysis, SARIF parsing based on the given task and reasoning.
        map_rule_to_cwe(rule_id): maps a CodeQL rule_id to the corris pondent CWE through LLM.
        add_cwe_snippet(report): adds snippet of code for each vulnerability in the SARIF report.
        step(observation): execute eache single step of the ReAct cycle.
        load_existing_queries(cwe): loads existing CodeQL queries for one CWE from the local CodeQL packet.

    """

    def __init__(self, prompt_template: str, shared_memory: SharedMemory, tools: list, logpath: str=None):
        """
        AnalyzerAgent's constructor.
        It initializes the base agent with the provided prompt, memory, tools, and logpath.
        
        Args:
            prompt_template (str): the prompt template that will be formatted and used as input to the LLM.
            shared_memory (SharedMemory): shared memory for the agent.
            tools (list): list of tools available to the agent.
            logpath (str | None): optional path for logging.  
        """
        super().__init__(prompt_template=prompt_template, shared_memory=shared_memory, tools=tools, logpath=logpath)

        self.summ_procedure=SummaryProcedure(self.llm, SUMMARY_TEMPLATE)
        self.thought_procedure=ThoughtProcedure(self.llm, THOUGHT_TEMPLATE)
        self.action_procedure = ActionProcedure(self.llm, ACTION_TEMPLATE)

        self.max_steps=20

    def map_rule_to_cwe(self, rule_id: str) -> str:
            """
            Maps a CodeQL rule_id to the corrispondent CWE through LLM.
            Uses a structured output (CWEMappingModel) to guarantee format's coherence.
            
            Args:
                rule_id (str): CodeQL rule ID
            
            Returns:
                dict: { "CWE": "CWE-XXX"
                        "Description": "..."}
            """

            prompt = f"""Your input is a CodeQL rule_id vulnerabilty: {rule_id}. 
                You must answer following this JSON format: 
                {{
                    CWE: CWE-XXX
                    Description: <one raw>}}
                """
        
            structured_llm = self.llm.with_structured_output(CWEMappingModel)
            llm_out = structured_llm.invoke([SystemMessage(content=prompt)])
            return llm_out.dict()

    def add_cwe_snippet(self, report: str):
        """
        Adds snippet of code (entire file) for each vulnerability in the SARIF report and maps each rule_id 
        to the corrispondent CWE.
                
        Args:
            report (list[dict]): list of vulnerability extracted from the SARIF report.
        """

        files = set()
        for vuln in report:
                
                locations = vuln.get("locations")
                for loc in locations:
                    line = loc.get("line")
                    file = "./vulnerable_code/" + loc.get("uri")
                    files.add(loc.get("uri"))
                    with open(file, "r", encoding="utf-8") as f:
                        full_file = f.read()
                
                    loc["full_file"] = full_file
                rule = vuln.get("rule_id")
                if rule:
                    cwe = self.map_rule_to_cwe(rule)
                    vuln["rule_id"] = rule
                    vuln["cwe"] = cwe["cwe"]
                    vuln["cwe_description"] = cwe["description"]

        folder = Path("./vulnerable_code/")

        for file_path in folder.iterdir():
            if file_path.is_file():
                if file_path.name not in files:
                    try :
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        new_entry = {         
                            "tool": "None",
                            "rule_id": "None",
                            "message": "No vulnerability detected by CodeQL",
                            "locations": [
                            {
                                "uri": file_path.name,
                                "line": 0,
                                "full_file": content
                            }
                            ],
                            "cwe": "None",
                            "cwe_description": "None",
                        }
                        files.add(file_path.name)
                        report.append(new_entry)
                    except Exception as e:
                        print(f"Error in reading the file {file_path.name}")
                    
    def step(self, observation: str) -> ReActChain:
        """
        Execute eache single step of the ReAct cycle.
        
        The cycle includes:
            1. memory update
            2. summary generation
            3. reasoning (thought)
            4. selection/creation next action
            5. existing CodeQL queries integration as inspiration
        
        Args: 
            observation (str): new observation to process
        
        Returns:
            ReActChain: updated chain containing summary, thought and action.

        """

        self.update_memory(observation)

        scratchpad = self.shared_memory.to_messages()
        instructions = self.prompt_template 

        summary_out = self.summ_procedure.run(instructions, scratchpad)
        summary = summary_out.summary

        thought_out =self.thought_procedure.run(summary, scratchpad, self.last_step)
        thought = thought_out.thought
        
        action_out = self.action_procedure.run(summary, scratchpad, self.last_step, thought, self.tools)
        action = action_out.action
    
        self.last_step = ReActChain.format(summary=summary, thought=thought, action=action)

        return self.last_step
    
    def load_existing_queries(self, cwe: str):
        """
        Loads existing CodeQL queries for one CWE from the local CodeQL packet.
        
        Args:
            cwe (str): vulnerability ID

        Returns:
            List[dict]: existing queries, each with:
                - filename
                - content
        """
            
        num = int(cwe[4:])           
        cwe = f"CWE-{num:03d}"
        cwe_path = os.path.join(QUERY_PACK_TOT, cwe)

        if not os.path.exists(cwe_path):
            return []
        
        queries = []
        for file in os.listdir(cwe_path):
            if file.endswith(".ql"):
                try:
                    with open(os.path.join(cwe_path, file), "r") as f:
                        queries.append({
                            "filename": file,
                            "content": f.read()
                        })
                except Exception:
                    continue

        if os.listdir(OUTPUT_QUERIES_PATH):
            for file in os.listdir(OUTPUT_QUERIES_PATH):
                if file.endswith(".ql"):
                    try:
                        with open(file, "r") as f:
                            queries.append({
                                "filename": file,
                                "content": f.read()
                            })
                    except Exception:
                        continue


        return queries

    def run_analysis(self, task: CodeQLAnalyzerInput) -> str:
        """Execute the CodeQL analysis, SARIF parsing based on the given task and report validation for each query.

        Args:
            task (CodeQLAnalyzerInput): the input task containing source root and output report path.

        Returns:
            str: the final result of the analysis, parsing and reasoning.
        """
        self.reset(task)

        try:
            self.last_step.thought="I execute the SAST analysis and parsing as requested."

            sast_tool_istance = CodeQLSastTool(
                source_root=task.source_root,
                output_report_filepath=task.output_report_filepath,
            )

            # execute the CodeQLSastTool for CodeQL scan
            sast_tool_istance.run() 

            parse_tool_instance = ParseSarifTool(
                sarif_filepath=task.output_report_filepath
            )

            final_res = parse_tool_instance.run()

            structured_report = json.loads(final_res)

            # enriches the report
            self.add_cwe_snippet(structured_report)

            self.last_step.action = json.dumps(structured_report, indent=2)
            self.last_step.observation = json.dumps(structured_report, indent=2)

            print(f"\n---Enriched report with cwe and full_file fields---\n{self.last_step.action}")

            self.last_step.observation=structured_report
            last_observation = self.last_step.observation

            for vuln in structured_report:
                cwe = vuln.get("cwe", "None")
                rule_id = vuln.get("rule_id", "None")
                filename = vuln['locations'][0]['uri'] if vuln.get('locations') else "unknown_file"
                
                if rule_id == "None":
                    instruction = (
                        f"MANUAL AUDIT REQUIRED: CodeQL did not find any vulnerability in '{filename}'. "
                        "Your goal is to perform an independent zero-base scan of the 'full_file' "
                        "to identify hidden vulnerabilities, logic gaps, or misconfigurations."
                    )
                else:
                    instruction = (
                        f"VALIDATION REQUIRED: CodeQL flagged a potential vulnerability ({rule_id}). "
                        "Analyze the 'full_file' to confirm if this is a True Positive or a False Positive."
                    )

                analysis_context = {
                    "instruction": instruction,
                    "target_file": filename,
                    "sarif_finding": {
                        "rule_id": rule_id,
                        "message": vuln.get("message", ""),
                        "cwe": cwe
                    },
                    "full_file": vuln['locations'][0].get("full_file", "Source code not available")
                }

                last_observation = f"New audit task: {json.dumps(analysis_context, indent=2)}"

                for step in range(self.max_steps):
                    current_reasoning = self.step(last_observation)  
                    print(f"\n Agent Thought: {current_reasoning.thought}")          
                    current_action = current_reasoning.action

                    if not current_action:
                        last_observation = "\nERROR: not action decided. Analyze your goal and try again."
                        print(f"\nObservation: {last_observation}\n")
                        self.update_memory(last_observation)
                        continue
                    
                    action_name = current_action.__class__.__name__

                    if action_name=="FinishTool":
                        vuln["agent_validation"] = current_action.final_repo
                        print(f"\n Action: FinishTool called with verdict.")
                        break

                    last_observation = "Observation: Alert analyzed against query logic. Waiting for final verdict."


            self.last_step.action = json.dumps(structured_report, indent=2)
            

        except Exception as e:
            error_msg = f"\nError in AnalyzerAgent: {e}"
            self.last_step.error=error_msg
            return error_msg
    
        self.update_memory(self.last_step.observation)
        return json.dumps(structured_report, indent=2)