# Testing and System Evaluation

This directory contains screenshots and evidence from controlled testing of the implemented AI-enhanced SOC workflow.

A mixed test scenario containing both benign and suspicious activity was used to compare the standard Wazuh alert view with the ML-prioritized dashboard.

During one representative test run:

- **166 alerts** were visible on the standard Wazuh dashboard.
- **94 alerts** were displayed through the ML-prioritized workflow.

The purpose of this comparison is to demonstrate the reduction of lower-value and repetitive alert activity presented to the analyst while preserving alerts selected for further investigation.

These values are not fixed system outputs. Alert counts can vary between executions depending on the attack scenarios performed, benign background activity, timing, event repetition, and Wazuh rule behavior.

## Included Screenshots

- `wazuh_raw_alerts.png` — standard Wazuh dashboard showing the raw alert volume from the test scenario.
- `ml_prioritized_alerts.png` — custom ML-enhanced dashboard showing the alerts presented after prioritization and processing.

The screenshots represent one controlled evaluation scenario and are included as implementation evidence rather than as a universal performance benchmark.
