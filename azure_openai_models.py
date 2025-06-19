import json
import os
from typing import List, Dict, Any
from dotenv import load_dotenv
from openai import AzureOpenAI
from snowflake_conn import snowflake_conn

# Load environment variables from .env file
load_dotenv()

class TextToSQLAgent:
    """
    Model 1: Converts natural language to SQL using Azure OpenAI with function calling.
    Has access to get_table_metadata tool.
    """
    
    def __init__(self):
        self.client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            api_version="2024-02-15-preview",
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
        )
        self.conn = snowflake_conn()
        
    def get_table_metadata(self, table_name: str = "H1B_clean") -> str:
        """
        Tool function to get metadata of a Snowflake table.
        
        Args:
            table_name (str): Name of the table to get metadata for
            
        Returns:
            str: Formatted table schema information
        """
        try:
            self.conn.execute('USE DATABASE parsed')
            self.conn.execute(f"""
                SELECT column_name, data_type, is_nullable, column_default
                FROM parsed.information_schema.columns 
                WHERE table_name = '{table_name.upper()}'
                ORDER BY ordinal_position
            """)
            schema_data = self.conn.fetch()
            
            if schema_data:
                schema_str = f"Table: parsed.combined.{table_name.lower()}\nColumns:\n"
                for row in schema_data:
                    nullable = "NULL" if row[2] == "YES" else "NOT NULL"
                    default = f", DEFAULT: {row[3]}" if row[3] else ""
                    schema_str += f"- {row[0]} ({row[1]}, {nullable}{default})\n"
                return schema_str
            else:
                return f"No schema information found for table {table_name}"
        except Exception as e:
            return f"Error retrieving schema: {str(e)}"
    
    def generate_sql(self, user_question: str) -> str:
        """
        Convert natural language question to SQL using Azure OpenAI with function calling.
        
        Args:
            user_question (str): Natural language question from user
            
        Returns:
            str: Generated SQL query
        """
        # Define the tool for getting table metadata
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "get_table_metadata",
                    "description": "Get metadata and schema information for a Snowflake table",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "table_name": {
                                "type": "string",
                                "description": "Name of the table to get metadata for (default: H1B_clean)"
                            }
                        },
                        "required": []
                    }
                }
            }
        ]
        
        # Initial system message
        system_message = """You are a SQL expert that converts natural language questions to Snowflake SQL queries.
You have access to a function to get table metadata. Use it to understand the table structure before generating SQL.

Guidelines:
- The main table is parsed.combined.h1b_clean
- When using WHERE clauses with text columns, use LIKE operator with wildcards
- For date columns like start_date, use EXTRACT(year FROM start_date) to get the year
- Always use proper table qualification: parsed.combined.h1b_clean
- Generate only the SQL query, no explanations"""

        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"Generate SQL for this question: {user_question}"}
        ]
        
        # First call to get table metadata
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0
        )
        
        # Handle tool calls
        while response.choices[0].message.tool_calls:
            messages.append(response.choices[0].message)
            
            for tool_call in response.choices[0].message.tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                if function_name == "get_table_metadata":
                    table_name = function_args.get("table_name", "H1B_clean")
                    function_result = self.get_table_metadata(table_name)
                    
                    messages.append({
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": function_result
                    })
            
            # Continue the conversation
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=0
            )
        
        return response.choices[0].message.content.strip()


class SQLExecutionAgent:
    """
    Model 2: Executes SQL queries and provides natural language responses.
    Has access to execute_sql tool.
    """
    
    def __init__(self):
        self.client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            api_version="2024-02-15-preview",
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
        )
        self.conn = snowflake_conn()
    
    def execute_sql(self, sql_query: str) -> str:
        """
        Tool function to execute SQL query and fetch results.
        
        Args:
            sql_query (str): SQL query to execute
            
        Returns:
            str: Formatted query results
        """
        try:
            self.conn.execute(sql_query)
            results = self.conn.fetch()
            
            if results:
                # Format results as a readable string
                if len(results) == 1 and len(results[0]) == 1:
                    # Single value result
                    return str(results[0][0])
                else:
                    # Multiple rows/columns
                    formatted_results = []
                    for i, row in enumerate(results):
                        if i < 10:  # Limit to first 10 rows for readability
                            formatted_results.append(str(row))
                        else:
                            formatted_results.append(f"... and {len(results) - 10} more rows")
                            break
                    return "\n".join(formatted_results)
            else:
                return "No results returned from the query"
                
        except Exception as e:
            return f"Error executing SQL: {str(e)}"
    
    def generate_response(self, user_question: str, sql_query: str) -> str:
        """
        Execute SQL query and generate natural language response.
        
        Args:
            user_question (str): Original user question
            sql_query (str): SQL query to execute
            
        Returns:
            str: Natural language response
        """
        # Define the tool for executing SQL
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "execute_sql",
                    "description": "Execute a SQL query on Snowflake and return the results",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "sql_query": {
                                "type": "string",
                                "description": "The SQL query to execute"
                            }
                        },
                        "required": ["sql_query"]
                    }
                }
            }
        ]
        
        # System message for natural language response generation
        system_message = """You are a data analyst that executes SQL queries and provides natural language explanations of the results.

Your process:
1. Execute the provided SQL query using the execute_sql function
2. Analyze the results
3. Provide a clear, natural language answer to the user's original question based on the query results

Be concise but informative in your response."""

        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"""
User's Question: {user_question}
SQL Query to Execute: {sql_query}

Please execute this SQL query and provide a natural language answer to the user's question.
"""}
        ]
        
        # Execute the SQL and get response
        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0
        )
        
        # Handle tool calls
        while response.choices[0].message.tool_calls:
            messages.append(response.choices[0].message)
            
            for tool_call in response.choices[0].message.tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                if function_name == "execute_sql":
                    sql_query = function_args["sql_query"]
                    function_result = self.execute_sql(sql_query)
                    
                    messages.append({
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": function_result
                    })
            
            # Continue the conversation
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=0
            )
        
        return response.choices[0].message.content


class TextToSQLPipeline:
    """
    Complete pipeline that combines both models for end-to-end text-to-SQL functionality.
    """
    
    def __init__(self):
        self.sql_generator = TextToSQLAgent()
        self.sql_executor = SQLExecutionAgent()
    
    def process_question(self, user_question: str) -> Dict[str, Any]:
        """
        Process a natural language question through the complete pipeline.
        
        Args:
            user_question (str): Natural language question from user
            
        Returns:
            Dict[str, Any]: Results containing SQL query, execution results, and natural language response
        """
        print(f"Processing question: {user_question}")
        print("-" * 60)
        
        # Step 1: Generate SQL using Model 1
        print("Step 1: Generating SQL query...")
        sql_query = self.sql_generator.generate_sql(user_question)
        print(f"Generated SQL: {sql_query}")
        print()
        
        # Step 2: Execute SQL and generate response using Model 2
        print("Step 2: Executing SQL and generating response...")
        natural_response = self.sql_executor.generate_response(user_question, sql_query)
        print(f"Natural Language Response: {natural_response}")
        print()
        
        return {
            "question": user_question,
            "sql_query": sql_query,
            "natural_response": natural_response
        }


def main():
    """
    Main function to demonstrate the two-model text-to-SQL system.
    """
    print("Initializing Text-to-SQL Pipeline with Azure OpenAI...")
    pipeline = TextToSQLPipeline()
    
    # Test questions
    test_questions = [
        "What's the average salary for carmax engineer in 2024?",
        "How many H1B applications were filed for software engineer positions?",
        "Show me the top 5 companies by number of H1B applications"
    ]
    
    for question in test_questions:
        result = pipeline.process_question(question)
        print("=" * 80)
        print()


if __name__ == "__main__":
    main() 