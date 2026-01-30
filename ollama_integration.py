import requests
from rich.console import Console

console = Console()

class OllamaAnalyzer:
    """Use Ollama LLMs for intelligent log analysis"""
    
    def __init__(self, model="llama3.2", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.available = False
        self.models_available = []
        
        self._check_ollama()
    
    def _check_ollama(self):
        """Check if Ollama is running and models are available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.models_available = [model['name'] for model in data.get('models', [])]
                
                if self.model in [m.split(':')[0] for m in self.models_available]:
                    console.print(f"[green]✅ Ollama connected! Using model: {self.model}[/green]")
                    self.available = True
                else:
                    console.print(f"[yellow]Model '{self.model}' not found. Available: {self.models_available}[/yellow]")
                    console.print("[dim]Using rule-based fallback[/dim]")
            else:
                console.print("[yellow]Ollama running but API error[/yellow]")
        except requests.exceptions.ConnectionError:
            console.print("[yellow]Ollama is not running. Using rule-based analysis.[/yellow]")
            console.print("[dim]To enable AI: Install Ollama and run: ollama serve[/dim]")
        except Exception as e:
            console.print(f"[yellow] Ollama error: {e}[/yellow]")
    
    def analyze_with_llm(self, log, ml_score, context=None):
        """Analyze log using Ollama LLM"""
        if not self.available:
            return self._rule_based_fallback(log, ml_score)
        
        try:
            prompt = self._create_prompt(log, ml_score, context)
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 200
                }
            }
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis = result['response'].strip()
                
                # Parse the structured response
                return self._parse_llm_response(analysis)
            else:
                console.print(f"[red]❌ Ollama API error: {response.status_code}[/red]")
                return self._rule_based_fallback(log, ml_score)
                
        except Exception as e:
            console.print(f"[red]❌ LLM analysis failed: {e}[/red]")
            return self._rule_based_fallback(log, ml_score)
    
    def _create_prompt(self, log, ml_score, context):
        """Create a structured prompt for the LLM"""
        return f"""You are a cybersecurity analyst reviewing security logs. Analyze this log entry:

LOG: {log}
ML ANOMALY SCORE: {ml_score:.3f}
CONTEXT: {context if context else "No additional context"}

Please provide analysis in this EXACT format:
THREAT_LEVEL: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
ATTACK_TYPE: [SQL_INJECTION/XSS/PATH_TRAVERSAL/BRUTE_FORCE/COMMAND_INJECTION/UNKNOWN/NONE]
CONFIDENCE: [0-100]%
ANALYSIS: [Brief analysis of why this is or isn't suspicious]
RECOMMENDATION: [Specific action to take]
IMPACT: [Potential impact if this is an attack]

Focus on security implications. Keep analysis concise."""
    
    def _parse_llm_response(self, response):
        """Parse LLM response into structured format"""
        try:
            result = {
                "threat_level": "UNKNOWN",
                "attack_type": "UNKNOWN",
                "confidence": 50,
                "analysis": "Could not parse LLM response",
                "recommendation": "Review manually",
                "impact": "Unknown"
            }
            
            lines = response.split('\n')
            for line in lines:
                if 'THREAT_LEVEL:' in line:
                    result["threat_level"] = line.split(':')[1].strip()
                elif 'ATTACK_TYPE:' in line:
                    result["attack_type"] = line.split(':')[1].strip()
                elif 'CONFIDENCE:' in line:
                    try:
                        result["confidence"] = int(line.split(':')[1].replace('%', '').strip())
                    except:
                        pass
                elif 'ANALYSIS:' in line:
                    result["analysis"] = line.split(':')[1].strip()
                elif 'RECOMMENDATION:' in line:
                    result["recommendation"] = line.split(':')[1].strip()
                elif 'IMPACT:' in line:
                    result["impact"] = line.split(':')[1].strip()
            
            return result
            
        except Exception as e:
            console.print(f"[red]❌ Failed to parse LLM response: {e}[/red]")
            return self._rule_based_fallback("", 0)
    
    def _rule_based_fallback(self, log, ml_score):
        """Fallback to rule-based analysis when LLM fails"""
        log_lower = log.lower()
        
        if 'select' in log_lower and ('1=1' in log_lower or 'union' in log_lower):
            return {
                "threat_level": "HIGH",
                "attack_type": "SQL_INJECTION",
                "confidence": 85,
                "analysis": "Contains SQL injection patterns (SELECT with 1=1)",
                "recommendation": "Block IP, audit database queries",
                "impact": "Data theft, database corruption"
            }
        elif 'script>' in log_lower or 'alert(' in log_lower:
            return {
                "threat_level": "MEDIUM",
                "attack_type": "XSS",
                "confidence": 80,
                "analysis": "Contains JavaScript/XSS patterns",
                "recommendation": "Sanitize inputs, block request",
                "impact": "Session hijacking, data theft"
            }
        elif '../' in log or '..\\' in log:
            return {
                "threat_level": "HIGH",
                "attack_type": "PATH_TRAVERSAL",
                "confidence": 75,
                "analysis": "Path traversal attempt",
                "recommendation": "Restrict file access, block IP",
                "impact": "File system access, sensitive data exposure"
            }
        elif 'rm -rf' in log_lower or 'exec(' in log_lower:
            return {
                "threat_level": "CRITICAL",
                "attack_type": "COMMAND_INJECTION",
                "confidence": 90,
                "analysis": "Command injection attempt",
                "recommendation": "IMMEDIATE BLOCK, investigate system",
                "impact": "Complete system compromise"
            }
        elif 'failed login' in log_lower:
            return {
                "threat_level": "MEDIUM",
                "attack_type": "BRUTE_FORCE",
                "confidence": 70,
                "analysis": "Multiple failed login attempts",
                "recommendation": "Rate limit IP, lock account temporarily",
                "impact": "Account compromise"
            }
        elif ml_score < -0.2:
            return {
                "threat_level": "LOW",
                "attack_type": "UNKNOWN",
                "confidence": 60,
                "analysis": "Statistical anomaly detected",
                "recommendation": "Monitor for patterns",
                "impact": "Potentially new attack vector"
            }
        else:
            return {
                "threat_level": "INFO",
                "attack_type": "NONE",
                "confidence": 95,
                "analysis": "Normal system activity",
                "recommendation": "No action required",
                "impact": "None"
            }
            
    def get_model_info(self):
        """Get information about available models"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                return response.json()
        except:
            return {"models": []}