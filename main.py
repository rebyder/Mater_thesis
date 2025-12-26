"""
Main script to run the LLM Agent Architecture for detecting software vulnerabilities at source code level.

This script sets up the necessary components, including loading environment variables,
parsing command-line arguments, and initializing the orchestrator agent. It then
executes the workflow to analyze a dataset of source code files for vulnerabilities.

Command-line Arguments:
    --dataset_path (str): path to the dataset JSON file containing the vulnerable-at-source-code files.
        - in this specific example in the ./vulnerable_code directory there are:
            - 10 SQLi files
            - 4 XSS files 
        - the different quantity doesn't compromise or interfere the results
        - However, the CodeQL tool 
    --memory_path (str): path to the shared memory JSON file.
"""

import argparse
import os

from agents_dir.orchestrator import OrchestratorAgent
from agents_dir.base_agent import SharedMemory
from dotenv import load_dotenv

load_dotenv()

def main():
    """Main function to run the LLM Agent Architecture workflow."""
    
    parser = argparse.ArgumentParser(description="Use this script to run an LLM Agent Architecture with the goal of detecting software vulnerabilities at source code level.")

    script_directory = os.path.dirname(os.path.abspath(__file__))
    json_file_path = os.path.join(script_directory, "vulnerable_code")

    parser.add_argument("--dataset_path", type=str, default=json_file_path, help="Path to the dataset JSON file containing the vulnerable-at-source-code files.")
    parser.add_argument("--memory_path", type=str, default="agent_memory.json", help="Path to the shared memory JSON file.")

    args = parser.parse_args()
    
    print("="*40)
    print("Start of Workflow")
    print("="*40)

    memory = SharedMemory(filepath=args.memory_path) 
    orchestrator = OrchestratorAgent(memory=memory)

    try:
        final_message = orchestrator.run_workflow(dataset_path=args.dataset_path)
        print("="*40)
        print("Final Message from the last Agent:")
        print("="*40)

        print(final_message)

    except Exception as e:
        print(f"\nWorkflow failed with exception: {str(e)}")

if __name__ == "__main__":
    main()