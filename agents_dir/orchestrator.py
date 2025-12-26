"""
Module that defines the OrchestratorAgent, responsible of the management of the
entire multi-agent workflow for:

    1. Source code analysis through CodeQL and validation of the CodeQL report (AnalyzerAgent)
    2. Generation of suggetions for new improved queries (SuggestorAgent)
    3. Creation of new CodeQL queries (CreatorAgent)

The module integrates different agents, each specialized in different tasks, and coordinates
the entire process.

Principal class:
    - OrchestratorAgent: manager of the entire multi-agent workflow

Main function:
    - run_workflow: complete execution of the process

"""

import shutil
import tempfile
import os
import json

from typing import Optional
from langchain_openai import ChatOpenAI

from tools import WebSearchTool, WriteQuerySubAgent, FinishToolSuggestor, SuggestSubAgent, FinishTool
from agents_dir.base_agent import SharedMemory
from agents_dir.analyzer_agent import AnalyzerAgent, CodeQLAnalyzerInput
from agents_dir.suggestor_agent import SuggestorAgent, SuggestorInput, SuggestorOutput
from agents_dir.creator_agent import CreatorAgent, CreatorInput, CreatorOutput
from prompts import SYSTEM_ANALYZER



class OrchestratorAgent:
    """
    Principal Orchestrator of the entire multi-agent workflow.

    This agent:
        - executes CodeQL through AnalyzerAgent
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
    
    Method:
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
    
        self.analyzer = AnalyzerAgent(prompt_template=SYSTEM_ANALYZER, shared_memory=self.memory, tools=[FinishTool], logpath=os.path.join(self.log_dir, "analyzer_log"))
        self.suggestor = SuggestorAgent(shared_memory=self.memory, tools=[WebSearchTool, SuggestSubAgent, FinishToolSuggestor], logpath=os.path.join(self.log_dir, "validator_log"))
        self.creator = CreatorAgent(shared_memory=self.memory, tools=[WebSearchTool, WriteQuerySubAgent, FinishTool], logpath=os.path.join(self.log_dir, "creator_log"))

        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    def run_workflow(self, dataset_path: str):
        """ Execute the entire multi-agent workflow for source-code analysis and new CodeQL queries creation.
        
        Pipeline:
            1. AnalyzerAgent: CodeQL execution and SARIF report generation
            2. SuggestorAgent: new queries suggestions generation
            3. CreatorAgent: new queries creation

        Args:
            dataset_path (str): Path of the directory containing all the vulberable files.
            
        Returns:
            str: final_message of the CreatorAgent
        """
        
        print("="*40)
        print("WORKFLOW START")
        print("="*40)

        try:
            output_sarif = tempfile.mkdtemp(prefix="reports_") 
            sarif_report_path = os.path.join(output_sarif, "analysis_report.sarif") # path to the analyzer's report: "report-xxxx/analysis_report.sarif"

            
            analyzer_input = CodeQLAnalyzerInput(
            source_root=dataset_path,
            output_report_filepath=sarif_report_path,
            )

            print("[Orchestrator]: I call the Analyzer")
            structured_report = self.analyzer.run_analysis(analyzer_input)

            report = json.loads(structured_report)

            structured_report = json.dumps(report, indent=2)
            print(f"\nOutput Analyzer - enriched report with agent validation included:\n {structured_report}")

            print("[Orchestrator]: I call the Suggestor")
            suggestor_input = SuggestorInput(report_content=structured_report)
            self.suggestor.reset(suggestor_input)
            suggestor_output: SuggestorOutput = self.suggestor.run()
            print(suggestor_output)
            
            report_content = suggestor_output.final_report
            with open("sast_report.md", "w", encoding="utf-8") as f:
                f.write(report_content)

            print("\nReport of the Suggestor saved in sast_report.md\n")

            print("[Orchestrator]: I call the Creator")

            creator_input = CreatorInput(final_report=report_content)
            self.creator.reset(creator_input)
            creator_output: CreatorOutput = self.creator.run()
            final_message = creator_output.final_message
            
            return final_message
        
        except Exception as e:
            error_msg = f"\nError in AnalyzerAgent: {e}"
            return error_msg
    
            
        finally:
                if output_sarif and os.path.exists(output_sarif):
                    shutil.rmtree(output_sarif)
                if self.log_dir and os.path.exists(self.log_dir):
                    print(f"\nLogs saved in {self.log_dir}")