# Security Log Intelligence System

This project is an example of a security system that uses machine learning to detect and analyze threats in log files. The system features a real-time anomaly detection, attack classification and report.

## How It's Made:
Tech used: Python, scikit-learn, Ollama, Rich, NumPy

... write something


## How It Works:
* Leverages both statistical ML and generative AI for hybrid threat detection.
* Analyzes web server logs with customizable confidence thresholds.
* Identifies and classifies specific attack patterns like SQLi, XSS, and path traversal.
* Generates detailed security reports with actionable recommendations and impact assessments.

## Example


## Installation
1. Clone the repository:
```bash
git clone https://github.com/iamoidn/ai-log-analyzer.git
cd ai-log-analyzer
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage
To run the project, use the following command:

```bash
ollama pull llama3.2
```
Then, in another terminal use these commands:
```bash
ollama serve
python main.py
```
