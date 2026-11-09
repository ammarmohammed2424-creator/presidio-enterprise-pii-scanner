# presidio-enterprise-pii-scanner
Automated PII and credit card data discovery engine for enterprise logs using Microsoft Presidio and spaCy NLP.
# 🛡️ Enterprise PII & Credit Card Data Discovery Engine

An automated data discovery and classification pipeline built with **Python**, **Microsoft Presidio**, and **spaCy** natural language processing (NLP). This tool parses complex, unstructured enterprise support logs to isolate, classify, and validate sensitive Personally Identifiable Information (PII) and financial card assets while filtering out false positives using cryptographic and checksum algorithms.

---

## 📊 Real-World Project Evaluation & Scoring

| Category | Score (Out of 100) | Real-World Value & Industry Relevance |
| :--- | :---: | :--- |
| **Security Knowledge** | **92/100** | Demonstrates mastery of data privacy frameworks (GDPR, PCI-DSS), entity recognition, and strict checksum validation. |
| **Cybersecurity & SOC** | **88/100** | Highly applicable to Security Operations Center (SOC) data loss prevention (DLP), log monitoring, and triage workflows. |
| **Cloud & Architecture** | **85/100** | Directly maps to Cloud Security Posture Management (CSPM) and Data Security Platforms (DSPM) scanning object stores and logs. |
| **IT Administration** | **90/100** | Reflects sysadmin competence in managing local environments, troubleshooting path/permission policies, and parsing complex logs. |
| **Hands-On Execution** | **95/100** | Built from scratch—handling directory synchronization, wheel package installations, and custom scanning logic. |

* **Overall Project Impact Score:** **90 / 100**

---

## ⚙️ Step-by-Step Implementation Guide

<img width="914" height="106" alt="presido 1 install and upgrade " src="https://github.com/user-attachments/assets/9d53d4a5-61fb-4d6b-92c5-c7150f3bce0c" />


### Step 1: Upgrade Packaging Toolchains
Ensure your local Python package management tools are fully updated to support secure wheel installations[cite: 8].
```cmd
python -m pip install --upgrade pip setuptools wheel



<img width="815" height="217" alt="presidio 2 install spacy and yaml" src="https://github.com/user-attachments/assets/9afa4107-3cc5-4210-8f20-3428d5c66905" />



Step 2: Install Presidio Analyzer & Dependencies
Install the core Microsoft Presidio Analyzer engine, anonymization library, and configuration components.



<img width="959" height="79" alt="presisio 3 installing collected packages" src="https://github.com/user-attachments/assets/7cb1ccc0-7889-4595-9998-799c9c6908e8" />



Step 3: Install the spaCy NLP Model
To bypass potential network gateway timeouts, install the spaCy English language core model directly via its pre-compiled wheel release.



<img width="454" height="203" alt="presidio 4 running the python script on the test text" src="https://github.com/user-attachments/assets/ca4318a7-1468-4dd7-af0c-7c3e7c119803" />


Step 4: Execute the Log Scanning Engine
Run the automated discovery script to parse multi-incident logs, ignore conversational noise, and output classified entities.




Core Architecture & Technical Concepts
1. Named Entity Recognition (NER)
The pipeline leverages spaCy's NLP models combined with Presidio's custom recognizers to detect semantic entities like human names (PERSON) amidst large blocks of unstructured conversational text and system headers.

2. False-Positive Reduction via the Luhn Algorithm
When scanning financial logs, dummy 16-digit sequences (such as test numbers) are frequently encountered. Presidio integrates a strict Luhn algorithm checksum check on candidate strings:

True Cards: Card numbers that satisfy mathematical bank checksum requirements are flagged with high confidence (1.0).

Random Serials: Invalid mock numbers fail the algorithm and are automatically discarded as false positives, ensuring cleaner security reports.




enterprise_audit_log.txt (Target Log Sample)
Plaintext
================================================================================
GLOBAL ENTERPRISE SUPPORT & TRANSACTION AUDIT LOG - REGION: EMEA
Date: November 9, 2026
================================================================================
[INCIDENT #8841 - SUPPORT CHAT LOG]
Customer Support Representative: Sarah Jenkins
Client Name: Michael Vance
Notes: Payment processed via corporate card ending in digital reference 4532-7182-9384-5012.

[INCIDENT #8843 - REFUND REQUEST FORM]
Agent Handling: Marcus Vance
Client Name: Robert Taylor
Summary: Reference invoice #9921 associated with physical card swipe 3782-8224-6310-005.

scan_enterprise_log.py (Analysis Script)



import os
from presidio_analyzer import AnalyzerEngine

# Initialize the Microsoft Presidio Analyzer engine
analyzer = AnalyzerEngine()

target_file = "enterprise_audit_log.txt"

if os.path.exists(target_file):
    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    print(f"[*] Scanning audit log ({target_file}) for sensitive entities...")
    
    results = analyzer.analyze(
        text=content,
        language="en",
        entities=["CREDIT_CARD", "PERSON"]
    )
    
    print("\n==================================================")
    print(f" SECURITY DISCOVERY SCAN REPORT: {target_file}")
    print("==================================================")
    
    if results:
        results = sorted(results, key=lambda x: x.start)
        for i, res in enumerate(results, 1):
            detected_text = content[res.start:res.end]
            print(f"[{i:02d}] Entity Type: {res.entity_type:<12} | Confidence: {res.score} | Extracted Value: '{detected_text}'")
    else:
        print("No sensitive entities found.")
    print("==================================================")
