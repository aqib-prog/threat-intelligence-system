import pandas as pd
import json
import os
from pathlib import Path


class FileParser:
    def __init__(self):
        self.supported_formats = ['.xlsx', '.xls', '.csv', '.json']

    def parse_file(self, file_path):
        """
        Parse uploaded file and return structured data
        """

        file_ext= Path(file_path).suffix.lower()

        if file_ext in ['.xlsx','.xls']:
            return self._parse_excel(file_path)
        
        elif file_ext == '.csv':
            return self._parse_csv(file_path)
        elif file_ext == '.json':
            return self._parse_json(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
    
    def _parse_excel(self, file_path):
        """
        Parsing file
        """
        df = pd.read_excel(file_path)
        return self._dataframe_to_dict(df)
    
    def _parse_csv(self, file_path):
        """Parse CSV file"""
        df = pd.read_csv(file_path)
        return self._dataframe_to_dict(df)
    
    def _parse_json(self, file_path):
        """Parse JSON file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    

    def _dataframe_to_dict(self, df):
        """Convert DataFrame to structured dict"""
        # Clean column names
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
        
        # Convert to dict
        records = df.to_dict('records')
        
        # Remove empty rows
        records = [r for r in records if any(str(v).strip() for v in r.values() if pd.notna(v))]
        
        return {"data": records, "count": len(records)}


if __name__ == "__main__":
    parser = FileParser()
    print("----- File parser ready -----")