"""
ExfilEye Domain Classification System
Daily updated domain classifier with change tracking
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import streamlit as st

class DomainClassifier:
    def __init__(self, config_file='domain_classifications.json', update_log_file='domain_update_log.json'):
        self.config_file = config_file
        self.update_log_file = update_log_file
        self.classifications = self.load_classifications()
        self.update_log = self.load_update_log()
        
    def load_classifications(self) -> Dict:
        """Load domain classifications from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Default comprehensive classification
        return {
            "last_updated": datetime.now().isoformat(),
            "version": "1.0",
            "free_email_domains": [
                "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
                "aol.com", "icloud.com", "protonmail.com", "tutanota.com",
                "yandex.com", "mail.ru", "163.com", "qq.com", "sina.com",
                "zoho.com", "fastmail.com", "gmx.com", "mail.com"
            ],
            "suspicious_domains": [
                "10minutemail.com", "guerrillamail.com", "mailinator.com",
                "tempmail.org", "throwaway.email", "getnada.com",
                "maildrop.cc", "sharklasers.com", "temp-mail.org",
                "yopmail.com", "dispostable.com", "trashmail.com",
                "mailnesia.com", "emailondeck.com", "fakeinbox.com"
            ],
            "business_domains": [
                "microsoft.com", "google.com", "amazon.com", "apple.com",
                "facebook.com", "salesforce.com", "oracle.com", "ibm.com",
                "cisco.com", "vmware.com", "adobe.com", "intel.com",
                "hp.com", "dell.com", "accenture.com", "deloitte.com"
            ],
            "government_domains": [
                "gov", "mil", "edu", "ac.uk", "gov.uk", "gov.au",
                "gc.ca", "gouv.fr", "gov.de", "go.jp"
            ],
            "financial_domains": [
                "jpmorgan.com", "bankofamerica.com", "wellsfargo.com",
                "citi.com", "goldmansachs.com", "morganstanley.com",
                "blackrock.com", "vanguard.com", "fidelity.com",
                "schwab.com", "td.com", "rbc.com"
            ],
            "cloud_providers": [
                "amazonaws.com", "azure.com", "googlecloud.com",
                "digitalocean.com", "cloudflare.com", "fastly.com"
            ],
            "suspicious_patterns": [
                "temp", "disposable", "throw", "fake", "trash",
                "guerrilla", "10min", "mailinator", "yopmail"
            ]
        }
    
    def load_update_log(self) -> List:
        """Load update log from file"""
        if os.path.exists(self.update_log_file):
            try:
                with open(self.update_log_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def save_classifications(self):
        """Save classifications to file"""
        self.classifications["last_updated"] = datetime.now().isoformat()
        with open(self.config_file, 'w') as f:
            json.dump(self.classifications, f, indent=2)
    
    def save_update_log(self):
        """Save update log to file"""
        with open(self.update_log_file, 'w') as f:
            json.dump(self.update_log, f, indent=2)
    
    def classify_domain(self, domain: str) -> Dict:
        """Classify a single domain"""
        if not domain:
            return {"classification": "unknown", "category": "unknown", "is_suspicious": False, "is_free": False}
        
        domain = domain.lower().strip()
        
        # Check free email domains
        if domain in self.classifications.get("free_email_domains", []):
            return {
                "classification": "free_email",
                "category": "personal",
                "is_suspicious": False,
                "is_free": True,
                "risk_level": "medium"
            }
        
        # Check suspicious domains
        if domain in self.classifications.get("suspicious_domains", []):
            return {
                "classification": "suspicious",
                "category": "suspicious",
                "is_suspicious": True,
                "is_free": True,
                "risk_level": "high"
            }
        
        # Check suspicious patterns
        for pattern in self.classifications.get("suspicious_patterns", []):
            if pattern in domain:
                return {
                    "classification": "suspicious",
                    "category": "suspicious",
                    "is_suspicious": True,
                    "is_free": True,
                    "risk_level": "high"
                }
        
        # Check business domains
        if domain in self.classifications.get("business_domains", []):
            return {
                "classification": "business",
                "category": "corporate",
                "is_suspicious": False,
                "is_free": False,
                "risk_level": "low"
            }
        
        # Check government domains
        government_domains = self.classifications.get("government_domains", [])
        if any(domain.endswith(gov_domain) for gov_domain in government_domains):
            return {
                "classification": "government",
                "category": "government",
                "is_suspicious": False,
                "is_free": False,
                "risk_level": "low"
            }
        
        # Check financial domains
        if domain in self.classifications.get("financial_domains", []):
            return {
                "classification": "financial",
                "category": "financial",
                "is_suspicious": False,
                "is_free": False,
                "risk_level": "low"
            }
        
        # Check cloud providers
        if domain in self.classifications.get("cloud_providers", []):
            return {
                "classification": "cloud_provider",
                "category": "technology",
                "is_suspicious": False,
                "is_free": False,
                "risk_level": "medium"
            }
        
        # Unknown domain
        return {
            "classification": "unknown",
            "category": "unknown",
            "is_suspicious": False,
            "is_free": False,
            "risk_level": "medium"
        }
    
    def add_domains(self, category: str, domains: List[str], reason: str = "Manual addition"):
        """Add new domains to a category and log the change"""
        if category not in self.classifications:
            self.classifications[category] = []
        
        new_domains = []
        for domain in domains:
            domain = domain.lower().strip()
            if domain and domain not in self.classifications[category]:
                self.classifications[category].append(domain)
                new_domains.append(domain)
        
        if new_domains:
            # Log the update
            update_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "add",
                "category": category,
                "domains": new_domains,
                "reason": reason,
                "count": len(new_domains)
            }
            self.update_log.append(update_entry)
            
            # Save changes
            self.save_classifications()
            self.save_update_log()
            
            return True, f"Added {len(new_domains)} domains to {category}"
        
        return False, "No new domains were added"
    
    def remove_domains(self, category: str, domains: List[str], reason: str = "Manual removal"):
        """Remove domains from a category and log the change"""
        if category not in self.classifications:
            return False, f"Category {category} does not exist"
        
        removed_domains = []
        for domain in domains:
            domain = domain.lower().strip()
            if domain in self.classifications[category]:
                self.classifications[category].remove(domain)
                removed_domains.append(domain)
        
        if removed_domains:
            # Log the update
            update_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "remove",
                "category": category,
                "domains": removed_domains,
                "reason": reason,
                "count": len(removed_domains)
            }
            self.update_log.append(update_entry)
            
            # Save changes
            self.save_classifications()
            self.save_update_log()
            
            return True, f"Removed {len(removed_domains)} domains from {category}"
        
        return False, "No domains were removed"
    
    def get_daily_updates(self, days: int = 1) -> List[Dict]:
        """Get updates from the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_updates = []
        for update in self.update_log:
            try:
                update_date = datetime.fromisoformat(update["timestamp"])
                if update_date >= cutoff_date:
                    recent_updates.append(update)
            except:
                continue
        
        return sorted(recent_updates, key=lambda x: x["timestamp"], reverse=True)
    
    def get_classification_stats(self) -> Dict:
        """Get statistics about domain classifications"""
        stats = {}
        for category, domains in self.classifications.items():
            if isinstance(domains, list):
                stats[category] = len(domains)
        
        return stats
    
    def needs_daily_update(self) -> bool:
        """Check if daily update is needed"""
        try:
            last_updated = datetime.fromisoformat(self.classifications.get("last_updated", ""))
            return (datetime.now() - last_updated).days >= 1
        except:
            return True
    
    def perform_daily_update(self) -> Tuple[bool, str, List[Dict]]:
        """Perform daily update with threat intelligence feeds"""
        updates_made = []
        
        # Simulate threat intelligence updates (in real implementation, this would connect to threat feeds)
        new_suspicious_domains = [
            "tempmail24.com", "fakeemail.net", "disposableinbox.com",
            "throwawaymails.com", "quickemailverification.com"
        ]
        
        new_free_domains = [
            "tutamail.com", "cock.li", "guerrillamailblock.com"
        ]
        
        # Add new suspicious domains
        success, msg = self.add_domains("suspicious_domains", new_suspicious_domains, "Daily threat intelligence update")
        if success:
            updates_made.append({
                "category": "suspicious_domains",
                "action": "added",
                "count": len(new_suspicious_domains),
                "domains": new_suspicious_domains
            })
        
        # Add new free email domains
        success, msg = self.add_domains("free_email_domains", new_free_domains, "Daily domain registry update")
        if success:
            updates_made.append({
                "category": "free_email_domains", 
                "action": "added",
                "count": len(new_free_domains),
                "domains": new_free_domains
            })
        
        return len(updates_made) > 0, f"Daily update completed: {len(updates_made)} categories updated", updates_made

# Global instance
domain_classifier = DomainClassifier()