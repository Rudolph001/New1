"""
ExfilEye Risk Configuration Manager
Configurable risk scoring system with field-based conditions
"""

import json
import streamlit as st
from typing import Dict, List, Any, Union
from domain_classifier import DomainClassifier

class RiskConfigManager:
    def __init__(self, config_file='risk_config.json'):
        self.config_file = config_file
        self.domain_classifier = DomainClassifier()
        self.risk_config = self.load_config()
        
    def load_config(self) -> Dict:
        """Load risk configuration from file or create default"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.get_default_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.risk_config, f, indent=2)
    
    def get_default_config(self) -> Dict:
        """Get default risk configuration"""
        return {
            "risk_levels": {
                "Critical": {
                    "threshold": 80,
                    "conditions": [
                        {
                            "field": "leaver",
                            "operator": "equals",
                            "value": "YES",
                            "points": 30,
                            "description": "Departing employee activity"
                        },
                        {
                            "field": "attachments",
                            "operator": "not_equals",
                            "value": "-",
                            "points": 30,
                            "description": "Email has attachments"
                        },
                        {
                            "field": "Wordlist_attachment",
                            "operator": "not_equals",
                            "value": "-",
                            "points": 30,
                            "description": "Suspicious attachment content detected"
                        },
                        {
                            "field": "Wordlist_subject",
                            "operator": "not_equals",
                            "value": "-",
                            "points": 30,
                            "description": "Suspicious keywords in subject line"
                        }
                    ]
                },
                "High": {
                    "threshold": 60,
                    "conditions": [
                        {
                            "field": "Wordlist_subject",
                            "operator": "not_equals",
                            "value": "-",
                            "points": 30,
                            "description": "Sensitive keywords in subject"
                        },
                        {
                            "field": "recipients_email_domain_classification",
                            "operator": "equals",
                            "value": "free_email",
                            "points": 35,
                            "description": "Free email domain recipient"
                        },
                        {
                            "field": "attachments",
                            "operator": "not_empty",
                            "value": "",
                            "points": 25,
                            "description": "Email contains attachments"
                        },
                        {
                            "field": "_time",
                            "operator": "after_hours",
                            "value": "18:00-06:00",
                            "points": 20,
                            "description": "After-hours email activity"
                        }
                    ]
                },
                "Medium": {
                    "threshold": 30,
                    "conditions": [
                        {
                            "field": "sender_recipient_different_domain",
                            "operator": "equals",
                            "value": "true",
                            "points": 15,
                            "description": "Cross-domain communication"
                        },
                        {
                            "field": "recipients_email_domain_classification",
                            "operator": "equals",
                            "value": "unknown",
                            "points": 20,
                            "description": "Unknown recipient domain"
                        }
                    ]
                },
                "Low": {
                    "threshold": 0,
                    "conditions": [
                        {
                            "field": "sender",
                            "operator": "not_empty",
                            "value": "",
                            "points": 1,
                            "description": "All emails that don't meet higher risk criteria"
                        }
                    ]
                }
            },
            "field_definitions": {
                "leaver": {
                    "type": "categorical",
                    "description": "Employee leaving status",
                    "possible_values": ["YES", "NO", ""]
                },
                "Wordlist_subject": {
                    "type": "text",
                    "description": "Keywords detected in email subject"
                },
                "Wordlist_attachment": {
                    "type": "text", 
                    "description": "Keywords detected in attachments"
                },
                "recipients_email_domain_classification": {
                    "type": "categorical",
                    "description": "Classification of recipient email domain",
                    "possible_values": ["business", "free_email", "government", "education", "temporary_disposable", "suspicious", "unknown"]
                },
                "attachments": {
                    "type": "text",
                    "description": "Attachment information"
                },
                "_time": {
                    "type": "datetime",
                    "description": "Email timestamp"
                },
                "sender": {
                    "type": "email",
                    "description": "Email sender address"
                },
                "recipients": {
                    "type": "email",
                    "description": "Email recipient addresses"
                }
            },
            "operators": {
                "equals": "Exact match",
                "not_equals": "Does not equal",
                "contains": "Contains text",
                "not_contains": "Does not contain text",
                "empty": "Field is empty",
                "not_empty": "Field is not empty", 
                "greater_than": "Greater than (numeric)",
                "less_than": "Less than (numeric)",
                "after_hours": "Time outside business hours",
                "different_domain": "Different email domains"
            }
        }
    
    def evaluate_condition(self, email_data: Dict, condition: Dict) -> tuple:
        """Evaluate a single condition against email data"""
        field = condition.get('field')
        operator = condition.get('operator')
        expected_value = condition.get('value')
        points = condition.get('points', 0)
        
        # Get field value from email data
        if field == "recipients_email_domain_classification":
            # Special handling for domain classification
            recipients = email_data.get('recipients_email_domain', '') or email_data.get('recipients', '')
            if recipients:
                domain = recipients.split('@')[-1].lower() if '@' in recipients else recipients.lower()
                classification = self.domain_classifier.classify_domain(domain)
                field_value = classification.get('classification', 'unknown')
            else:
                field_value = 'unknown'
        elif field == "sender_recipient_different_domain":
            # Special handling for cross-domain check
            sender = email_data.get('sender', '')
            recipients = email_data.get('recipients', '')
            sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
            recipient_domain = recipients.split('@')[-1].lower() if '@' in recipients else ''
            field_value = "true" if sender_domain != recipient_domain and sender_domain and recipient_domain else "false"
        else:
            field_value = str(email_data.get(field, '')).strip()
        
        # Evaluate based on operator
        condition_met = False
        
        if operator == "equals":
            condition_met = field_value.lower() == str(expected_value).lower()
        elif operator == "not_equals":
            condition_met = field_value.lower() != str(expected_value).lower()
        elif operator == "contains":
            condition_met = str(expected_value).lower() in field_value.lower()
        elif operator == "not_contains":
            condition_met = str(expected_value).lower() not in field_value.lower()
        elif operator == "empty":
            condition_met = not field_value or field_value == ""
        elif operator == "not_empty":
            condition_met = bool(field_value and field_value != "" and field_value != "-")
        elif operator == "after_hours":
            # Check if time is after hours (example: 18:00-06:00)
            time_str = field_value
            if ':' in time_str:
                try:
                    # Extract hour from time string
                    if ' ' in time_str:
                        hour_part = time_str.split(' ')[-1].split(':')[0]
                    else:
                        hour_part = time_str.split(':')[0]
                    hour = int(hour_part)
                    condition_met = hour >= 18 or hour <= 6
                except:
                    condition_met = False
            else:
                condition_met = False
        elif operator == "greater_than":
            try:
                condition_met = float(field_value) > float(expected_value)
            except:
                condition_met = False
        elif operator == "less_than":
            try:
                condition_met = float(field_value) < float(expected_value)
            except:
                condition_met = False
        
        return condition_met, points if condition_met else 0
    
    def check_critical_formula(self, email_data: Dict) -> bool:
        """Check if email matches the critical formula:
        leaver=YES AND attachments!="-" AND (Wordlist_attachment != "-" OR Wordlist_subject !="-")
        """
        # Check leaver = YES
        leaver_value = str(email_data.get('leaver', '')).strip().upper()
        if leaver_value != 'YES':
            return False
        
        # Check attachments != "-"
        attachments_value = str(email_data.get('attachments', '')).strip()
        if attachments_value == '-' or attachments_value == '':
            return False
        
        # Check (Wordlist_attachment != "-" OR Wordlist_subject !="-")
        wordlist_attachment = str(email_data.get('Wordlist_attachment', '')).strip()
        wordlist_subject = str(email_data.get('Wordlist_subject', '')).strip()
        
        # At least one of these must be not equal to "-"
        if wordlist_attachment != '-' and wordlist_attachment != '':
            return True
        if wordlist_subject != '-' and wordlist_subject != '':
            return True
        
        return False
    
    def calculate_risk_score(self, email_data: Dict) -> Dict:
        """Calculate risk score based on configured conditions"""
        total_score = 0
        triggered_conditions = []
        
        # Special handling for Critical events with specific formula:
        # leaver=YES AND attachments!="-" AND (Wordlist_attachment != "-" OR Wordlist_subject !="-")
        critical_formula_met = self.check_critical_formula(email_data)
        if critical_formula_met:
            # If critical formula is met, immediately return Critical with high score
            return {
                'risk_score': 1000,  # Very high score to ensure Critical level
                'risk_level': 'Critical',
                'triggered_conditions': [{
                    'description': 'Critical Event: Leaver with attachments and suspicious content',
                    'points': 1000,
                    'risk_level': 'Critical',
                    'field': 'combined_critical_formula',
                    'operator': 'special_formula',
                    'value': 'leaver=YES AND attachments!="-" AND (Wordlist_attachment != "-" OR Wordlist_subject !="-")'
                }],
                'explanation': 'Email meets the critical formula criteria for departing employee with attachments and suspicious content'
            }
        
        # Evaluate all other conditions across all risk levels (excluding Critical level conditions)
        for risk_level, config in self.risk_config["risk_levels"].items():
            # Skip Critical level conditions since we handle them with special formula
            if risk_level == "Critical":
                continue
                
            for condition in config.get("conditions", []):
                condition_met, points = self.evaluate_condition(email_data, condition)
                if condition_met:
                    total_score += points
                    triggered_conditions.append({
                        'description': condition.get('description', 'Unknown condition'),
                        'points': points,
                        'risk_level': risk_level,
                        'field': condition.get('field'),
                        'operator': condition.get('operator'),
                        'value': condition.get('value')
                    })
        
        # Determine risk level based on thresholds (highest to lowest)
        risk_level = "Low"  # Default to Low for all emails
        
        # Check Critical threshold first (but only if formula not already handled)
        critical_threshold = self.risk_config["risk_levels"]["Critical"]["threshold"]
        if total_score >= critical_threshold:
            risk_level = "Critical"
        elif total_score >= self.risk_config["risk_levels"]["High"]["threshold"]:
            risk_level = "High"
        elif total_score >= self.risk_config["risk_levels"]["Medium"]["threshold"]:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Ensure all emails get at least Low risk level
        if risk_level == "Low" and total_score == 0:
            # Add minimal points to ensure Low classification
            total_score = 1
        
        return {
            'risk_score': total_score,
            'risk_level': risk_level,
            'triggered_conditions': triggered_conditions,
            'risk_factors': '; '.join([cond['description'] for cond in triggered_conditions])
        }
    
    def add_condition(self, risk_level: str, field: str, operator: str, value: str, points: int, description: str):
        """Add a new condition to a risk level"""
        if risk_level in self.risk_config["risk_levels"]:
            new_condition = {
                "field": field,
                "operator": operator,
                "value": value,
                "points": points,
                "description": description
            }
            self.risk_config["risk_levels"][risk_level]["conditions"].append(new_condition)
            self.save_config()
    
    def remove_condition(self, risk_level: str, condition_index: int):
        """Remove a condition from a risk level"""
        if risk_level in self.risk_config["risk_levels"]:
            conditions = self.risk_config["risk_levels"][risk_level]["conditions"]
            if 0 <= condition_index < len(conditions):
                conditions.pop(condition_index)
                self.save_config()
    
    def update_threshold(self, risk_level: str, threshold: int):
        """Update threshold for a risk level"""
        if risk_level in self.risk_config["risk_levels"]:
            self.risk_config["risk_levels"][risk_level]["threshold"] = threshold
            self.save_config()
    
    def get_available_fields(self, data: List[Dict]) -> List[str]:
        """Get available fields from uploaded data"""
        if not data:
            return list(self.risk_config["field_definitions"].keys())
        
        # Get fields from actual data plus predefined special fields
        data_fields = list(data[0].keys()) if data else []
        special_fields = [
            "recipients_email_domain_classification",
            "sender_recipient_different_domain"
        ]
        
        all_fields = list(set(data_fields + special_fields))
        return sorted(all_fields)
    
    def export_config(self) -> str:
        """Export configuration as JSON string"""
        return json.dumps(self.risk_config, indent=2)
    
    def import_config(self, config_json: str) -> bool:
        """Import configuration from JSON string"""
        try:
            imported_config = json.loads(config_json)
            # Validate basic structure
            if "risk_levels" in imported_config and "field_definitions" in imported_config:
                self.risk_config = imported_config
                self.save_config()
                return True
        except:
            pass
        return False
    
    def get_config_summary(self) -> Dict:
        """Get summary of current risk configuration for display"""
        summary = {
            'thresholds': {},
            'total_conditions': 0,
            'conditions_by_level': {}
        }
        
        for level, config in self.risk_config["risk_levels"].items():
            summary['thresholds'][level] = config.get("threshold", 0)
            conditions_count = len(config.get("conditions", []))
            summary['conditions_by_level'][level] = conditions_count
            summary['total_conditions'] += conditions_count
        
        return summary