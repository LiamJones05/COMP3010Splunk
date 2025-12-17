Boss of the SOC v3 – Security Operations Investigation Report

Course: COMP3010 Security Operations & Incident Management
Dataset: BOTSv3 (Boss of the SOC v3 – Splunk)
Author: Liam Jones
Tools: Splunk Enterprise, SPL (Search Processing Language)

1. Introduction
1.1 Context

Security Operations Centres (SOCs) are responsible for continuous monitoring, detection, analysis, and response to security incidents across enterprise environments. Modern SOCs rely heavily on Security Information and Event Management (SIEM) platforms such as Splunk to correlate large volumes of telemetry from cloud, endpoint, network, and application sources.

The Boss of the SOC version 3 (BOTSv3) dataset is a publicly available, pre-indexed security dataset developed by Splunk. It simulates a realistic multi-stage security incident affecting a fictional brewing company named Frothly. The dataset includes logs from Amazon Web Services (AWS), Windows endpoints, network devices, and application services.

1.2 Objective and Scope

The objective of this investigation is to analyse the BOTSv3 dataset using Splunk to identify, investigate, and evidence security-relevant events aligned with the cyber kill chain. The scope of this report focuses on the AWS-related and endpoint-related 200-level BOTSv3 questions, using Splunk Search Processing Language (SPL) to extract relevant evidence.

Assumptions:

All logs within BOTSv3 are trusted and correctly timestamped.

The investigation is conducted retrospectively (post-incident analysis).

The SOC analyst has read-only access to log data.

2. SOC Roles & Incident Handling Reflection

In a real-world SOC, incident handling is typically distributed across multiple tiers:

Tier 1 (Alert Triage): Initial alert review and basic validation.

Tier 2 (Incident Analysis): Deep investigation, log correlation, and root cause analysis.

Tier 3 (Threat Hunting & Engineering): Advanced analysis, detection engineering, and long-term remediation.

The BOTSv3 exercise primarily simulates the responsibilities of a Tier 2 SOC Analyst, requiring detailed log analysis, contextual reasoning, and evidence-based conclusions.

This investigation aligns with the NIST incident response lifecycle:

Preparation: Splunk installation and dataset ingestion.

Detection & Analysis: SPL-based log analysis and event correlation.

Containment & Eradication: Identification of misconfigurations and insecure actions.

Recovery & Lessons Learned: Reflection on detection gaps and SOC improvements.

3. Installation & Data Preparation
3.1 Splunk Environment Setup

Splunk Enterprise was installed locally and configured to support analysis of the BOTSv3 dataset. The BOTSv3 pre-indexed Splunk dataset was used to ensure data integrity and consistency with the official challenge environment.

3.2 Dataset Ingestion

The BOTSv3 dataset was ingested by placing the pre-indexed data into Splunk’s apps directory and restarting the Splunk service. Successful ingestion was validated using the following SPL query:

| eventcount summarize=false index=*


This confirmed the presence of the botsv3 index containing over two million events.

3.3 Validation of Data Sources

Key sourcetypes were validated to ensure investigative coverage:

index=botsv3
| stats count by sourcetype


Confirmed sourcetypes included:

aws:cloudtrail

aws:s3:accesslogs

winhostmon

hardware

Screenshots of ingestion validation are provided in the /evidence directory.

4. Guided Questions & Investigation Findings

Note: Each question is answered using SPL queries, supported by screenshots and SOC-relevant interpretation.

Question 1 – AWS IAM Users Observed

Objective: Identify IAM users observed in the environment.

SPL Query:

index=botsv3 sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) as IAM_Users


Findings:
The query returns a list of IAM users performing API actions within the AWS environment. This activity represents authenticated identity usage and forms the baseline for detecting anomalous or malicious behaviour.

SOC Relevance:
Understanding which identities are active is critical for:

Baseline behaviour modelling

Privileged access monitoring

Attribution during incident response

📸 Evidence: evidence/q1_iam_users.png

Question 4 – Public S3 Bucket Misconfiguration

Objective: Identify the API call that enabled public access to an S3 bucket.

SPL Query:

index=botsv3 sourcetype="aws:cloudtrail"
eventName="PutBucketAcl"
| table _time eventID userIdentity.userName requestParameters


Findings:
The event with ID:

ab45689d-69cd-41e7-8705-5350402cf7ac


contains an Access Control List (ACL) entry granting READ permissions to the AllUsers group:

Grantee: {
  URI: http://acs.amazonaws.com/groups/global/AllUsers
}
Permission: READ


SOC Relevance:
This represents a cloud misconfiguration, exposing the bucket to public access. Such misconfigurations are a leading cause of cloud data breaches and should trigger immediate containment actions.

📸 Evidence: evidence/q4_s3_acl_public.png

📸 Evidence: evidence/q4_search_public_bucket.png
            

Question 8 – Endpoint OS Deviation

Objective: Identify the endpoint running a different Windows edition.

SPL Query:

index=botsv3 sourcetype=winhostmon
| stats count by OS host


Findings:
Most endpoints run Windows 10 Pro, while one host (BSTOLL-L) runs Windows 10 Enterprise.

To resolve the full FQDN:

index=botsv3 host="BSTOLL-L"
| stats values(host)


Correlating with domain context across the dataset confirms the FQDN:

bstoll-l.froth.ly


SOC Relevance:
OS deviations may indicate:

Privileged workstations

Administrative endpoints

Increased attack surface

📸 Evidence: evidence/q8_os_deviation.png

📸 Evidence: evidence/q8_BSTOLL_host.png

5. Conclusion & Lessons Learned

This investigation demonstrates how SIEM platforms such as Splunk enable SOC analysts to reconstruct security incidents using log correlation and structured analysis. Key lessons include:

Cloud misconfigurations remain a high-impact threat vector.

Identity and access monitoring is critical for AWS environments.

Endpoint inconsistencies can reveal high-value assets.

From a SOC perspective, improvements could include:

Automated detection for public S3 ACLs

MFA enforcement alerts

Baseline deviation monitoring for endpoints

6. Video Presentation

🎥 YouTube Walkthrough (Unlisted):
Link here

The video demonstrates:

Key SPL queries

Evidence interpretation

SOC incident response reflections

7. References

[1] Splunk Inc., Boss of the SOC v3 Dataset, 2018.
[2] NIST, Computer Security Incident Handling Guide (SP 800-61r2).
[3] AWS, CloudTrail User Guide.
