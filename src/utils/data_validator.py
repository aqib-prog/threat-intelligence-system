class DataValidator:
    def __init__(self):
        self.asset_required_fields = ['system_name', 'system_type', 'site']
        self.evidence_required_fields = ['assessment_type', 'assessment_date']

    def validate_asset_data(self, data):
        """Validate asset inventory data"""
        if not data or 'data' not in data:
            return {"valid": False, "errors": ["No data found"]}
        
        records = data['data']
        errors = []
        
        for i, record in enumerate(records):
            missing = [field for field in self.asset_required_fields 
                      if field not in record or not str(record[field]).strip()]
            if missing:
                errors.append(f"Row {i+1}: Missing {', '.join(missing)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "record_count": len(records)
        }
    

    def validate_evidence_data(self, data):
        """Validate evidence data"""
        if not data or 'data' not in data:
            return {"valid": False, "errors": ["No data found"]}
        
        records = data['data']
        errors = []
        
        for i, record in enumerate(records):
            missing = [field for field in self.evidence_required_fields 
                      if field not in record or not str(record[field]).strip()]
            if missing:
                errors.append(f"Row {i+1}: Missing {', '.join(missing)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "record_count": len(records)
        }

if __name__ == "__main__":
    validator = DataValidator()
    print("----- Data validator ready ------")
