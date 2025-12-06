"""
Module that defines the OrchestratorAgent, responsible of the management of the
entire multi-agent workflow for:
    
    1. Source code analysis through CodeQL (AnalyzerAgent)
    2. Generation of suggetions for new improved queries (SuggestorAgent)
    3. Creation of new CodeQL queries (CreatorAgent)

The module integrates different agents, each specialized in different tasks, and coordinates
the entire process.

Principal classes:
    - CWEMappingModel (BaseModel): structured model for the output of the CWE mapping
    - OrchestratorAgent: manager of the entire multi-agent workflow

Main functions:
    - map_rule_to_cwe: automatic mapping Rule ID -> CWE through LLM
    - add_cwe_snippet: snippet addiction for each vulnerability
    - run_workflow: complete execution of the process
    """

import shutil
import tempfile
import os
import json

from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI

from tools import WebSearchTool, WriteQueryTool, FinishToolSuggestor, SuggestTool, FinishTool
from agents_dir.base_agent import SharedMemory
from agents_dir.analyzer_agent import AnalyzerAgent, CodeQLAnalyzerInput
from agents_dir.suggestor_agent import SuggestorAgent, SuggestorInput, SuggestorOutput
from agents_dir.creator_agent import CreatorAgent, CreatorInput, CreatorOutput
from prompts import SYSTEM_ANALYZER

CONTEXT = 7 

class CWEMappingModel(BaseModel):
    """
    Pydantic model for mappinf Rule ID -> CWE through LLM.
    
    Attributes:
        cwe (str): CWE ID
        description (str): brief description of the vulnerability

    """
    cwe: str = Field(...)
    description: str = Field(...)


class OrchestratorAgent:
    """
    Principal Orchestrator of the entire multi-agent workflow.

    This agent:
        - executes CodeQL through AnalyzerAgent
        - enriches the SARIF report with code snippet
        - automatically maps rule_id -> CWE
        - created improved suggestion through SuggestorAgent
        - creates new CodeQL queries through CreatorAgent

    Args:
        memory (SharedMemory | None): memory shared among agents

    Attributes: 
        memory (SharedMemory): memory shared among agents
        log_dir (str): temporary directory with all logs inside
        analyzer (AnalyzerAgent): CodeQL Analyzer agent
        suggestor (SuggestorAgent): agent for suggestions generation
        creator (CreatorAgent): agent for new CodeQL queries creation
        llm (ChatOpenAI): LLM for CWE mapping and reasoning.
    
    Methods:
        map_rule_to_cwe(rule_id): maps a CodeQL rule_id to the corris pondent CWE through LLM
        add_cwe_snippet(report): adds snippet of code for each vulnerability in the SARIF report
        run_workflow(dataset_path): execute the entire multi-agent workflow for source-code analysis and new CodeQL queries creation
    """

    def __init__(self, memory: Optional[SharedMemory] = None):
        """
        Orchestrator's constructor.
        
        It initalizes:
            - shared memory
            - directory log
            - the 3 principal agents (Analyzer, Suggestor and Creator)
            - an OpenAI LLM with structured output
        """

        self.memory = memory or SharedMemory()
        self.log_dir = tempfile.mkdtemp(prefix="agent_logs_")
    
        self.analyzer = AnalyzerAgent(prompt_template=SYSTEM_ANALYZER, shared_memory=self.memory, tools=[], logpath=os.path.join(self.log_dir, "analyzer_log"))
        self.suggestor = SuggestorAgent(shared_memory=self.memory, tools=[WebSearchTool, SuggestTool, FinishToolSuggestor], logpath=os.path.join(self.log_dir, "validator_log"))
        self.creator = CreatorAgent(shared_memory=self.memory, tools=[WriteQueryTool, FinishTool], logpath=os.path.join(self.log_dir, "creator_log"))

        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

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
        Adds snippet of code for each vulnerability in the SARIF report and maps each rule_id 
        to the corrispondent CWE.
        
        The snippet consists in a context of `+ or - CONTEXT`raws arounf the vulnerable line.
        
        Args:
            report (list[dict]): list of vulnerability extracted from the SARIF report.
        """

        for vuln in report:
                locations = vuln.get("locations")
                for loc in locations:
                    line = loc.get("line")
                    file = "./vulnerable_code/" + loc.get("uri")
                    with open(file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    
                    start = max(line - CONTEXT - 1, 0)
                    end = min(line + CONTEXT, len(lines))
                    snippet = "".join(lines[start:end])
                    loc["snippet"] = snippet
                rule = vuln.get("rule_id")
                if rule:
                    cwe = self.map_rule_to_cwe(rule)
                    vuln["rule_id"] = rule
                    vuln["cwe"] = cwe["cwe"]
                    vuln["cwe_description"] = cwe["description"]


    def run_workflow(self, dataset_path: str):
        """ Execute the entire multi-agent workflow for source-code analysis and new CodeQL queries creation.
        
        Pipeline:
            1. AnalyzerAgent: CodeQL execution and SARIF report generation
            2. SARIF enrichment with snippet and CWE mapping
            3. SuggestorAgent: new queries suggestions generation
            4. CreatorAgent: new queries creation

        Args:
            dataset_path (str): Path of the directory containing all the vulberable files.
            max_improvements (int): Numero massimo di iterazioni per migliorare le query.
            
        Returns:
            str: final_message of the CreatorAgent
        """
        
        
        print("="*40)
        print("WORKFLOW START")
        print("="*40)

        try:

            output_sarif = tempfile.mkdtemp(prefix="reports_") 
            sarif_report_path = os.path.join(output_sarif, "analysis_report.sarif") # percorso output sarif dell'analyzer: "report-xxxx/analysis_report.sarif"

            analyzer_input = CodeQLAnalyzerInput(
                source_root=dataset_path,
                output_report_filepath=sarif_report_path,
            )

            structured_report = self.analyzer.run_analysis(analyzer_input)

            report = json.loads(structured_report)
            self.add_cwe_snippet(report)

            structured_report = json.dumps(report, indent=2)
            print(f"\nSARIF REPORT from the CodeQL SAST tool:\n {structured_report}")


            validator_input = SuggestorInput(report_content=structured_report)
            self.suggestor.reset(validator_input)
            validator_output: SuggestorOutput = self.suggestor.run()
            print(validator_output)
            
            report_content = validator_output.final_report
            with open("sast_report.md", "w", encoding="utf-8") as f:
                f.write(report_content)

            print("\nReport saved in sast_report.md\n")

            creator_input = CreatorInput(final_report=report_content)
            self.creator.reset(creator_input)

            creator_output: CreatorOutput = self.creator.run()

            final_message = creator_output.final_message
            
            return final_message

          
        finally:
            if output_sarif and os.path.exists(output_sarif):
                shutil.rmtree(output_sarif)
            if self.log_dir and os.path.exists(self.log_dir):
                print(f"\nLogs saved in {self.log_dir}")