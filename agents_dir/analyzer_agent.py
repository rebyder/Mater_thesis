"""
Module that defines the AnalyzerAgent, responsible for source code analysis
using CodeQL and parsing the SARIF report.

Principal classes:
    - CodeQLAnalyzerInput (BaseModel): structured input for the AnalyzerAgent
    - AnalyzerAgent: agent that executes CodeQL analysis and SARIF parsing
"""

from typing import Optional
from tools import CodeQLSastTool, ParseSarifTool
from pydantic import Field
from agents_dir.base_agent import BaseAgent, BaseTaskInput, SharedMemory
from openai import OpenAI
import json

client = OpenAI()

class CodeQLAnalyzerInput(BaseTaskInput):
    """
    Input for the CodeQL analysis tool.
    
    Attributes:
        source_root (str): Path to the source code root directory.
        output_report_filepath (str): Path to the output SARIF report file.
        query_path (Optional[str]): Path to the CodeQL query file (if any).
    """
    source_root: str = Field(...)
    output_report_filepath: str = Field(...)
    query_path: Optional[str] = Field(default=None)
   

class AnalyzerAgent(BaseAgent):
    """Agent that executes CodeQL analysis and SARIF parsing.
    
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
        run_analysis(task): executes the CodeQL analysis and SARIF parsing based on the given task.
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


    def run_analysis(self, task: CodeQLAnalyzerInput) -> str:
        """Execute the CodeQL analysis and SARIF parsing based on the given task.
        Args:
            task (CodeQLAnalyzerInput): the input task containing source root, output report path, and optional query path.

        Returns:
            str: the final result of the analysis and parsing.
        """
        self.reset(task)

        try:
            self.last_step.thought="I execute the SAST analysis and parsing as requested."

            sast_tool_istance = CodeQLSastTool(
                source_root=task.source_root,
                output_report_filepath=task.output_report_filepath,
                query_path=task.query_path
            )

            sast_tool_istance.run() 

            parse_tool_instance = ParseSarifTool(
                sarif_filepath=task.output_report_filepath
            )

            final_res = parse_tool_instance.run()

            self.last_step.action=parse_tool_instance.model_dump_json()

            self.last_step.observation=final_res

            
        except Exception as e:
            error_msg = f"\nError in AnalyzerAgent: {e}"
            self.last_step.error=error_msg
            return error_msg
    
        self.update_memory(self.last_step.observation)
        return final_res