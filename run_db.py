import requests
import json
import time
from typing import Optional

class DatabricksNotebookRunner:
    def __init__(self, host: str, token: str):
        """
        Initialize the Databricks notebook runner.
        
        Args:
            host (str): Your Databricks workspace URL (e.g., 'https://your-workspace.cloud.databricks.com')
            token (str): Your Databricks personal access token
        """
        self.host = host.rstrip('/')
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def run_notebook(self, notebook_path: str, cluster_id: str, parameters: Optional[dict] = None) -> str:
        """
        Run a Databricks notebook and return the run ID.
        
        Args:
            notebook_path (str): Path to the notebook in Databricks (e.g., '/Users/your.email@domain.com/notebook_name')
            cluster_id (str): ID of the cluster to run the notebook on
            parameters (dict, optional): Parameters to pass to the notebook
            
        Returns:
            str: The run ID of the notebook execution
        """
        endpoint = f"{self.host}/api/2.0/jobs/runs/submit"
        
        payload = {
            "run_name": f"Notebook run: {notebook_path}",
            "existing_cluster_id": cluster_id,
            "notebook_task": {
                "notebook_path": notebook_path,
                "base_parameters": parameters or {}
            }
        }
        
        response = requests.post(endpoint, headers=self.headers, json=payload)
        response.raise_for_status()
        
        return response.json()['run_id']

    def get_run_status(self, run_id: str) -> dict:
        """
        Get the status of a notebook run.
        
        Args:
            run_id (str): The run ID to check
            
        Returns:
            dict: The run status information
        """
        endpoint = f"{self.host}/api/2.0/jobs/runs/get"
        params = {'run_id': run_id}
        
        response = requests.get(endpoint, headers=self.headers, params=params)
        response.raise_for_status()
        
        return response.json()

    def wait_for_completion(self, run_id: str, poll_interval: int = 10) -> dict:
        """
        Wait for a notebook run to complete and return the final status.
        
        Args:
            run_id (str): The run ID to monitor
            poll_interval (int): How often to check the status (in seconds)
            
        Returns:
            dict: The final run status
        """
        while True:
            status = self.get_run_status(run_id)
            life_cycle_state = status['state']['life_cycle_state']
            
            if life_cycle_state in ['TERMINATED', 'SKIPPED', 'INTERNAL_ERROR']:
                return status
                
            time.sleep(poll_interval)

def main():
    # Example usage
    host = "YOUR_DATABRICKS_WORKSPACE_URL"
    token = "YOUR_DATABRICKS_TOKEN"
    notebook_path = "/Users/your.email@domain.com/your_notebook"
    cluster_id = "YOUR_CLUSTER_ID"
    
    # Initialize the notebook runner
    runner = DatabricksNotebookRunner(host, token)
    
    # Example parameters to pass to the notebook
    parameters = {
        "param1": "value1",
        "param2": "value2"
    }
    
    try:
        # Run the notebook
        run_id = runner.run_notebook(notebook_path, cluster_id, parameters)
        print(f"Notebook run started with ID: {run_id}")
        
        # Wait for completion
        final_status = runner.wait_for_completion(run_id)
        print(f"Notebook run completed with status: {final_status['state']['result_state']}")
        
    except Exception as e:
        print(f"Error running notebook: {str(e)}")

if __name__ == "__main__":
    main() 
