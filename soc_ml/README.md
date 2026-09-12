# SOC ML Integration

This directory contains the core machine learning integration components developed for the AI-enhanced Security Operations Center.

The workflow processes eligible Wazuh security alerts, extracts the feature set required by the trained Random Forest model, calculates alert priority, and enriches the resulting alerts with additional security context.

The directory also contains a campaign-correlation component that groups related high-priority alerts within a defined time window to provide additional context for analysts.
