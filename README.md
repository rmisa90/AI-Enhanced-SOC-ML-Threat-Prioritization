# AI-Enhanced SOC with ML-Based Threat Prioritization

**An AI-enhanced Security Operations Center for machine learning-based security alert prioritization, contextual analysis, and controlled response.**

Final Year Project

---

## Project Overview

This project designs and implements an AI-enhanced Security Operations Center for an SME environment using Wazuh and machine learning.

The system collects and monitors security alerts from multiple sources, extracts contextual security features, and uses a trained Random Forest classifier to prioritize eligible alerts as **High** or **Low priority**.

Additional components provide MITRE ATT&CK context, campaign correlation, Slack notifications, dashboard visualization, and controlled IP-based response.

---

## System Architecture

![Physical Architecture](diagrams/physical_architecture.png)

The system combines:

- **Wazuh** for centralized security monitoring
- **Suricata** for network intrusion detection
- **Auditd** for host-level monitoring
- **VirusTotal** for threat intelligence enrichment
- **Cowrie** as an SSH/Telnet honeypot
- **Random Forest** for ML-based alert prioritization
- **OpenSearch / Wazuh Dashboards** for visualization
- **Slack** for selected security notifications
- **iptables** for controlled automated response

---

## Repository Structure

```text
AI-Enhanced-SOC-ML-Threat-Prioritization/
│
├── soc_ml/
│   ├── custom_ml_priority.py
│   └── campaign_correlation.py
│
├── models/
│   ├── alert_priority_model_tuned.pkl
│   ├── feature_columns.pkl
│   └── model_threshold.pkl
│
├── notebooks/
│   └── model_training_and_evaluation.ipynb
│
├── dataset/
│   └── README.md
│
├── honeypot/
│   └── cowrie_notes.md
│
├── response/
│   ├── block_ip.sh
│   └── slack_notification.py
│
├── diagrams/
│   ├── physical_architecture.png
│   ├── logical_architecture.png
│   └── ml_pipeline_diagram.png
│
├── outputs/
│   ├── confusion_matrix.png
│   ├── roc_auc.png
│   ├── pr_auc.png
│   └── feature_importance.png
│
├── testing_evaluation/
│   ├── README.md
│   ├── wazuh_raw_alerts.png
│   └── ml_prioritized_alerts.png
│
├── figures/
│   ├── wazuh_dashboard.png
│   ├── ml_dashboard.png
│   ├── alert_prioritization.png
│   └── slack_notification.png
│
├── requirements.txt
└── README.md
```

---

## Machine Learning Pipeline

- **Model:** Random Forest Classifier
- **Input:** 21 contextual security features
- **Training:** Grouped stratified train/test workflow with GridSearchCV
- **Output:** High / Low alert priority
- **Threshold:** Probability-based operational threshold
- **Additional Context:** Model confidence and MITRE ATT&CK mapping

The model considers contextual information such as Wazuh severity, alert repetition, authentication activity, payload patterns, Suricata detections, VirusTotal enrichment, file-integrity context, service type, and other security indicators.

---

## Dashboard

The custom dashboard provides visibility into:

- High and Low priority alerts
- Model confidence
- Source IP information
- MITRE ATT&CK context
- Alert details
- Response information

---

## Campaign Correlation

A separate correlation component groups related High-priority alerts from the same source within a defined time window.

This provides additional analyst context for patterns such as:

- repeated High-priority alerts
- web attack chains
- brute-force activity
- multi-stage attack behavior

Implementation:

`soc_ml/campaign_correlation.py`

---

## Automated Response

### Temporary IP Blocking

The project includes controlled temporary IP blocking using `iptables` for selected high-risk attack scenarios.

The response logic validates the source IP, checks predefined attack conditions, applies temporary blocking where appropriate, and supports automatic unblocking after the configured response period.

Implementation:

`response/block_ip.sh`

### Slack Notification

Selected important security alerts can generate Slack notifications to support faster analyst awareness and investigation.

Notifications may include information such as attack type, final priority, model confidence, source IP, affected agent, MITRE ATT&CK context, and response information.

The Slack webhook credential is intentionally excluded from the repository.

Implementation:

`response/slack_notification.py`

---

## How to Run

### Prerequisites

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

The implementation also requires a configured Wazuh environment with the relevant monitoring and integration components enabled.

### Model Training and Evaluation

Open and run:

```text
notebooks/model_training_and_evaluation.ipynb
```

This notebook contains the model training, tuning, threshold selection, and evaluation workflow.

### ML Alert Prioritization

The deployed ML integration is designed to run within the Wazuh integration environment.

Core implementation:

```text
soc_ml/custom_ml_priority.py
```

The script loads the trained model artifacts from the configured model directory and processes eligible Wazuh alert files passed by the Wazuh integration.

### Campaign Correlation

Campaign correlation is handled by:

```text
soc_ml/campaign_correlation.py
```

It processes selected High-priority ML alerts and groups related activity occurring within the configured correlation window.

### Automated Response

Controlled IP blocking and Slack notification are implemented through:

```text
response/block_ip.sh
response/slack_notification.py
```

These components require the relevant Wazuh response/integration configuration before use.

---

## Tools & Technologies

| Category | Technology |
|---|---|
| SIEM | Wazuh |
| Machine Learning | Python, Scikit-learn, Random Forest |
| Data Processing | Pandas |
| Model Serialization | Joblib |
| Network IDS | Suricata |
| Host Monitoring | Auditd |
| Threat Intelligence | VirusTotal |
| Honeypot | Cowrie |
| Search / Visualization | OpenSearch / Wazuh Dashboards |
| Notification | Slack |
| Automated Response | iptables |
| Model Development | Jupyter Notebook |

---

## Limitations

- The system was developed and tested within a controlled virtual lab environment.
- The deployed Random Forest model is currently static and trained offline.
- Dataset size and diversity are limited compared with a production SOC.
- Automated response is intentionally restricted to selected attack scenarios.
- Live alert prioritization is performed on individual alerts rather than full temporal attack sequences.

---

## Future Improvements

- Scheduled or incremental model retraining
- Analyst-feedback integration
- Broader attack scenarios
- Stronger automated-response approval and rollback controls
- More advanced campaign investigation views
- Improved long-term log and storage management
- Additional operational datasets
