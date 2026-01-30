# Security Log Intelligence System

This project is an example of a security system that uses machine learning to detect and analyze threats in log files. The system features a real-time anomaly detection, attack classification and report.

## How It's Made:
Tech used: Python, scikit-learn, Ollama, Rich, NumPy

## How It Works:
* Uses both Machine Learning algorithms and generative AI for hybrid threat detection.
* Analyzes web server logs with customizable confidence levels.
* Identifies and classifies specific attack patterns like SQLi, XSS, and path traversal.
* Generates detailed security reports with recommendations and impact assessments.

## Example
<img width="901" height="276" alt="image" src="https://github.com/user-attachments/assets/4b50fbef-49f9-4084-8ed3-8837d1c68bbd" />
<img width="932" height="700" alt="image" src="https://github.com/user-attachments/assets/175d47bf-f203-4d0f-931e-024ca18461ef" />

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
