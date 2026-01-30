#!/usr/bin/env python3
import numpy as np
from sklearn.ensemble import IsolationForest
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
import time
import sys

try:
    from ollama_integration import OllamaAnalyzer
    OLLAMA = True
except ImportError:
    OLLAMA = False

console = Console()

class Detector:
    def __init__(self):
        self.model = None
        self.is_trained = False
    
    def extract_features(self, logs):
        features = []
        for log in logs:
            f1 = len(log)
            f2 = sum(1 for c in log if c in "<>();'\"/")
            suspicious = ['select', 'script', 'exec', '../', 'rm -rf', 'alert(', 'union', 'or 1=1']
            f3 = 1 if any(word in log.lower() for word in suspicious) else 0
            levels = {'INFO': 0, 'WARNING': 1, 'ERROR': 2, 'CRITICAL': 3, 'ALERT': 4}
            f4 = next((levels[l] for l in levels if f"[{l}]" in log), 0)
            features.append([f1, f2, f3, f4])
        return np.array(features)
    
    def train(self, logs):
        features = self.extract_features(logs)
        self.model = IsolationForest(contamination=0.3, random_state=42)
        self.model.fit(features)
        self.is_trained = True
    
    def detect(self, logs):
        if not self.is_trained:
            return [False] * len(logs), [0] * len(logs)
        features = self.extract_features(logs)
        predictions = self.model.predict(features)
        scores = self.model.decision_function(features)
        return predictions == -1, scores


class System:
    def __init__(self, use_ollama=True):
        
        self.ml = Detector()
        
        if use_ollama and OLLAMA:
            console.print("\n[cyan]Initializing Ollama LLM...[/cyan]")
            self.llm = OllamaAnalyzer(model="llama3.2")
            self.has_llm = self.llm.available
        else:
            self.has_llm = False
        
        if self.has_llm:
            console.print("[green]Real AI (LLM) analysis is enabled[/green]")
        else:
            console.print("[yellow]AI was not enabled (install Ollama for LLM)[/yellow]")
    
    def load_logs(self, filename):
        try:
            with open(filename, 'r') as f:
                logs = [line.strip() for line in f if line.strip()]
            return logs
        except:
            return [
                "[INFO] Normal user login",
                "[WARNING] SELECT * FROM users",
                "[CRITICAL] <script>alert(1)</script>",
                "[ERROR] ../../../etc/passwd",
                "[ALERT] rm -rf / attempted"
            ]
    
    def run_full_demo(self):
        console.clear()
        console.print(Panel.fit(
            f"[white]LLM Status: {'✅ ENABLED' if self.has_llm else 'RULE-BASED'}[/]", border_style="green"
        ))
        logs = self.load_logs("sample_logs.txt")
        console.print(Panel(
            "[bold] Sample Logs:[/]\n" + 
            "\n".join([f"  {i+1}. {log}" for i, log in enumerate(logs[:5])]) +
            f"\n[dim] total {len(logs)} logs[/dim]",
            border_style="cyan"
        ))
        console.print("\n" + "="*70)
        console.print("[bold]STEP 1: Model Training[/bold]")
        
        train_logs = logs[:6]
        test_logs = logs[6:]
        
        self.ml.train(train_logs)
        console.print("\n[bold]STEP 2: Anomaly Detection[/bold]")
        anomalies, scores = self.ml.detect(test_logs)
        console.print("\n[bold]STEP 3: Threat Analysis [/bold]")
        if self.has_llm:
            console.print("[green]Using Ollama LLM for intelligent analysis...[/green]")
        
        table = Table(show_lines=True)
        table.add_column("#", style="dim")
        table.add_column("Log", style="cyan", width=40)
        table.add_column("ML Score", justify="right")
        table.add_column("Status", width=10)
        table.add_column("AI Threat Level", width=12)
        table.add_column("Attack Type", width=18)
        table.add_column("Confidence", justify="right")
    
        ai_analyses = []
        
        for i, (log, is_anomaly, score) in enumerate(zip(test_logs, anomalies, scores), 1):
            if is_anomaly:
                status = "[red]Anomaly!!![/red]"
                if self.has_llm: #Ollama analysis
                    analysis = self.llm.analyze_with_llm(log, score)
                else:
                    analysis = self.llm._rule_based_fallback(log, score) if OLLAMA else {
                        "threat_level": "MEDIUM",
                        "attack_type": "UNKNOWN",
                        "confidence": 50,
                        "analysis": "Rule-based detection",
                        "recommendation": "Investigate",
                        "impact": "Unknown"
                    }
                
                ai_analyses.append(analysis)
                if analysis["threat_level"] == "CRITICAL":
                    threat_color = "[bold red]"
                elif analysis["threat_level"] == "HIGH":
                    threat_color = "[red]"
                elif analysis["threat_level"] == "MEDIUM":
                    threat_color = "[yellow]"
                elif analysis["threat_level"] == "LOW":
                    threat_color = "[blue]"
                else:
                    threat_color = "[green]"
                
                table.add_row(
                    str(i), log[:37] + "..." if len(log) > 40 else log, f"{score:.3f}", status,
                    f"{threat_color}{analysis['threat_level']}[/{threat_color.split('[')[1].split(']')[0]}]",
                    analysis["attack_type"].replace("_", " "), f"{analysis['confidence']}%"
                )
            else:
                table.add_row(
                    str(i), log[:37] + "..." if len(log) > 40 else log, f"{score:.3f}", "[green]NORMAL[/green]", "[green]SAFE[/green]",
                    "Normal", "95%"
                )
        console.print(table)
        if ai_analyses:
            console.print("\n" + "="*100)
            console.print("[bold]STEP 4: Detailed Analysis by AI [/bold]")
            
            for i, analysis in enumerate(ai_analyses, 1):
                console.print(Panel(
                    f"[bold]Analysis #{i}[/bold]\n"
                    f"[cyan]Threat Level:[/] {analysis['threat_level']}\n"
                    f"[cyan]Attack Type:[/] {analysis['attack_type'].replace('_', ' ')}\n"
                    f"[cyan]Confidence:[/] {analysis['confidence']}%\n"
                    f"[cyan]Analysis:[/] {analysis['analysis']}\n"
                    f"[cyan]Recommendation:[/] {analysis['recommendation']}\n"
                    f"[cyan]Potential Impact:[/] {analysis['impact']}",
                    title=f"AI Analysis",
                    border_style="yellow" if analysis['threat_level'] in ['MEDIUM', 'HIGH'] else "red" if analysis['threat_level'] == 'CRITICAL' else "green"
                ))
        console.print("\n" + "="*100)
        console.print("[bold]STEP 5: Security Dashboard[/bold]")
        
        anomaly_count = sum(anomalies)
        if ai_analyses:
            threat_levels = [a['threat_level'] for a in ai_analyses]
            critical_count = threat_levels.count('CRITICAL')
            high_count = threat_levels.count('HIGH')
            medium_count = threat_levels.count('MEDIUM')
        else:
            critical_count = high_count = medium_count = 0
        
        dashboard = Panel(
            f"[bold]Security Posture Overview[/bold]\n\n"
            f"[cyan]Total Logs:[/] {len(logs)}\n"
            f"[yellow]ML Anomalies:[/] {anomaly_count}\n"
            f"[red]Critical Threats:[/] {critical_count}\n"
            f"[yellow]High Threats:[/] {high_count}\n"
            f"[blue]Medium Threats:[/] {medium_count}\n"
            f"[green]AI System:[/] {'Ollama LLM' if self.has_llm else 'Rule-Based'}\n"
            f"[cyan]ML Model:[/] Isolation Forest (trained on {len(train_logs)} samples)",
            title="Dashboard",
            border_style="cyan"
        )
        
        recommendations = Panel(
            "[bold]Recommended Actions[/bold]\n\n"
            f"{'Immediate Action is needed!!!' if critical_count > 0 else 'No immediate threats'}\n"
            f"{'Review all of the analyses above' if ai_analyses else 'All clear'}\n"
            f"{'Block suspicious IPs' if anomaly_count > 2 else 'Normal activity'}\n"
            f"{'Monitor for pattern repetition' if medium_count > 0 else ''}",
            title="Action Items",
            border_style="green" if critical_count == 0 else "red"
        )
        
        console.print(Columns([dashboard, recommendations]))
        
        console.print("\n" + "="*100)
        console.print(Panel.fit(
            f"[bold green] DEMO COMPLETE![/]\n\n"
            f"[cyan]Model Training:[/] ✓ Learned from {len(train_logs)} samples\n"
            f"[cyan]AI Analysis:[/] {'✓ Using Ollama LLM' if self.has_llm else 'Rule-based (install Ollama for LLM)'}\n"
            f"[cyan]Threats Found:[/] {anomaly_count} anomalies, {critical_count} critical\n"
            f"[cyan]System Status:[/] {'Operational' if critical_count == 0 else 'Review Needed'}",
            border_style="green" if critical_count == 0 else "yellow"
        ))
if __name__ == "__main__":
    console.print("[bold]AI Log Analysis System with Ollama Integration[/bold]\n")
    
    try:
        import sklearn
        console.print(f"[green]scikit-learn {sklearn.__version__}[/green]")
        
        console.print("\n[cyan]AI Configuration:[/cyan]")
        use_ollama = False
        
        if OLLAMA:
            try:
                import requests
                test = requests.get("http://localhost:11434/api/tags", timeout=2)
                if test.status_code == 200:
                    console.print("[green]Ollama detected and running[/green]")
                    use_ollama = True
                else:
                    console.print("[yellow]Ollama installed but not running[/yellow]")
            except:
                console.print("[yellow]Ollama not running (will use rule-based)[/yellow]")
        siem = System(use_ollama=use_ollama)
        input("\nPress Enter to start analysis!")
        siem.run_full_demo()
        if not OLLAMA or not use_ollama:
            console.print("\n" + "="*100)
            console.print(Panel(
                "[bold]To Enable Real AI (LLM) Analysis:[/bold]\n\n"
                "1. Install Ollama from https://ollama.com\n"
                "2. Pull models: ollama pull llama3.2\n"
                "3. Start server: ollama serve\n"
                "4. Re-run this program\n\n",
                title="AI Enhancement Available",
                border_style="yellow"
            ))
    except ImportError as err:
        console.print(f"[red]Missing dependency: {err}[/red]")
        console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")
    except Exception as err:
        console.print(f"[red]Error: {err}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")