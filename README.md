# Boss of the SOC v3 (BOTSv3)
## Security Operations Investigation Report

**Course:** COMP3010 Security Operations & Incident Management
**Dataset:** BOTSv3 (Boss of the SOC v3 – Splunk)
**Author:** Liam Jones
**Tools**: Splunk Enterprise, SPL (Search Processing Language)

------------------------------------------------------------------------

## Table of Contents
1. [Introduction](#introduction)
2. [SOC Roles Incident Handling Reflection](#soc-roles-incident-handling-reflection)
3. [Installation Data Preparation](#installation-data-preparation)
4. [Guided Questions Investigation Findings](#guided-questions-investigation-findings)
5. [Conclusion Lessons Learned](#conclusion-lessons-learned)
6. [Video Presentation](#video-presentation)
7. [References](#references)


------------------------------------------------------------------------

## Introduction

### Context

Security Operations Centres (SOCs) are responsible for continuous monitoring, detection, analysis, and response to security incidents across enterprise environments. Modern SOCs rely heavily on Security Information and Event Management (SIEM) platforms such as Splunk to correlate large volumes of telemetry from cloud, endpoint, network, and application sources.

The Boss of the SOC version 3 (BOTSv3) dataset is a publicly available, pre-indexed security dataset developed by Splunk. It simulates a realistic multi-stage security incident affecting a fictional brewing company named Frothly. The dataset includes logs from Amazon Web Services (AWS), Windows endpoints, network devices, and application services.

### Objective and Scope

The objective of this investigation is to analyse the BOTSv3 dataset using Splunk to identify, investigate, and evidence security-relevant events aligned with the cyber kill chain. The scope of this report focuses on the AWS-related and endpoint-related 200-level BOTSv3 questions, using Splunk Search Processing Language (SPL) to extract relevant evidence.

**Assumptions**:

All logs within BOTSv3 are trusted and correctly timestamped.

The investigation is conducted retrospectively (post-incident analysis).

The SOC analyst has read-only access to log data.

------------------------------------------------------------------------

## SOC Roles Incident Handling Reflection

In a real-world SOC, incident handling is typically distributed across multiple tiers:

**Tier 1 (Alert Triage):** Initial alert review and basic validation.

**Tier 2 (Incident Analysis):** Deep investigation, log correlation, and root cause analysis.

**Tier 3 (Threat Hunting & Engineering):** Advanced analysis, detection engineering, and long-term remediation.

The BOTSv3 exercise primarily simulates the responsibilities of a Tier 2 SOC Analyst, requiring detailed log analysis, contextual reasoning, and evidence-based conclusions.

This investigation aligns with the NIST incident response lifecycle:

- Preparation: Splunk installation and dataset ingestion.

- Detection & Analysis: SPL-based log analysis and event correlation.

- Containment & Eradication: Identification of misconfigurations and insecure actions.

- Recovery & Lessons Learned: Reflection on detection gaps and SOC improvements.

## Installation Data Preparation

### Splunk Environment Setup

Splunk Enterprise was installed locally and configured to support analysis of the BOTSv3 dataset. The BOTSv3 pre-indexed Splunk dataset was used to ensure data integrity and consistency with the official challenge environment.

------------------------------------------------------------------------

### Dataset Ingestion

The BOTSv3 dataset was ingested by placing the pre-indexed data into Splunk’s apps directory and restarting the Splunk service. Successful ingestion was validated using the following SPL query:

  | eventcount summarize=false index=*


This confirmed the presence of the botsv3 index containing over two million events.

### Validation of Data Sources

Key sourcetypes were validated to ensure investigative coverage:

  index=botsv3
  | stats count by sourcetype


**Confirmed sourcetypes included:**

aws:cloudtrail

aws:s3:accesslogs

winhostmon

hardware

**Screenshots of ingestion validation are provided in:**

📸 /evidence/dataset_ingestion.png

📸 /evidence/validation_of_data_sources.png

------------------------------------------------------------------------

## Guided Questions Investigation Findings


Note: Each question is answered using SPL queries, supported by screenshots and SOC-relevant interpretation.

###  Question 1 – AWS IAM Users Observed

**Objective:** Identify IAM users observed in the environment.

**SPL Query:**

  index=botsv3 sourcetype="aws:cloudtrail"
  | stats values(userIdentity.userName) as IAM_Users


**Findings:**
The query returns a list of IAM users performing API actions within the AWS environment. This activity represents authenticated identity usage and forms the baseline for detecting anomalous or malicious behaviour.

**SOC Relevance:**
Understanding which identities are active is critical for:

- Baseline behaviour modelling

- Privileged access monitoring

- Attribution during incident response

**📸 Evidence:** evidence/q1_iam_users.png  


### Question 2 - AWS API Activity Without MFA

**Objective:** Identify the field used to alert that AWS API activity has occurred without MFA

**SOC Relevance:** Monitoring for AWS API activity without MFA is critical because it indicates increased risk of credential compromise. SOC teams commonly alert on CloudTrail events where privileged actions are performed without MFA, excluding interactive console logins, to detect policy violations or attacker persistence.

**SPL Query:**

  index=botsv3 sourcetype="aws:cloudtrail"
  | search NOT eventName="ConsoleLogin" userIdentity.sessionContext.attributes.mfaAuthenticated=false

**Findings:**

Analysis of AWS CloudTrail logs identified API activity executed without multi-factor authentication. The field userIdentity.sessionContext.attributes.mfaAuthenticated explicitly indicates whether MFA was used during the session. Events where this value is set to false, excluding ConsoleLogin, represent elevated risk and would typically trigger SOC alerts under AWS security best practice guidelines.

**📸 Evidence:** evidence/q2_mfa_false.png  


### Question 3 - Processor Number on Web Servers

**Objective:** Identify the processor number used on the web servers

**SOC Relevance:**

- Hardware telemetry helps SOC teams:

- Validate asset baselines

- Identify anomalies or rogue systems

Support forensic investigations

**SPL Query Used:**

**Identify host processors:**

  index=botsv3 sourcetype="hardware" | table host processor

**Identify Processor Number:**

  index=botsv3 sourcetype="hardware" host="gacrux.i-09cbc261e84259b52"

**Findings:**

Hardware inventory logs revealed that Frothly’s web servers are running Intel processors identified as Intel(R) Core(TM) i7-7920HQ CPU @ 3.10GHz. This confirms consistency across web infrastructure and supports asset baseline validation, which is a key SOC responsibility during incident triage and threat hunting.

**📸 Evidence:** evidence/q3_search_host_processor.png

**📸 Evidence:** evidene/q3_processor_name.png  


### Question 4 – Public S3 Bucket Misconfiguration

**Objective:** Identify the API call that enabled public access to an S3 bucket.

**SPL Query:**

  index=botsv3 sourcetype="aws:cloudtrail"
  eventName="PutBucketAcl"
  | table _time eventID userIdentity.userName requestParameters


**Findings:**
The event with ID:

ab45689d-69cd-41e7-8705-5350402cf7ac


contains an Access Control List (ACL) entry granting READ permissions to the AllUsers group:

  Grantee: {
    URI: http://acs.amazonaws.com/groups/global/AllUsers
  }
  Permission: READ


**SOC Relevance:**
This represents a cloud misconfiguration, exposing the bucket to public access. Such misconfigurations are a leading cause of cloud data breaches and should trigger immediate containment actions.

**📸 Evidence:** evidence/q4_s3_acl_public.png

**📸 Evidence:** evidence/q4_search_public_bucket.png  

### Question 5 - Identify Bud's Username
Objective: Identify Bud's Username 

**SOC Relevance:**

Attribution is a core SOC function. Identifying the IAM user responsible for a misconfiguration allows:

- Accurate incident scoping
- Correct escalation
- Remediation and access review

**SPL Query Used:**

  index=botsv3 sourcetype="aws:cloudtrail" eventID="ab45689d-69cd-41e7-8705-5350402cf7ac"

**Justification:**

As seen in question 4, the misconfiguration was caused by Bud. Using the misconfiguration event, we can identify the username by the field:

userName: bstoll

Findings:

CloudTrail logs confirm that the IAM user bstoll executed the PutBucketAcl API call responsible for modifying S3 access controls. This attribution is essential for SOC incident handling, enabling targeted remediation and IAM policy review.

📸 Evidence: evidence/q5_buds_username.png

### Question 6 - Name of Public S3 Bucket
Objective: Identify the name of the S3 Bucket that Bud made publicly available

**SOC Relevance:**

Public S3 buckets are a common cloud misconfiguration leading to data exposure. Identifying the affected resource is critical for containment and recovery.

**SPL Query:**

  index=botsv3 sourcetype="aws:cloudtrail" eventID="ab45689d-69cd-41e7-8705-5350402cf7ac"

**Justification:**

As seen in previous questions, the misconfiguration API call has been identified, therefore the name of the S3 bucket can be identified within the JSON package under:

**requestParamaters > BucketName: frothlywebcode**

**Findings:**

Analysis of CloudTrail PutBucketAcl events identified the S3 bucket frothlywebcode as having its access controls modified, resulting in public accessibility. This represents a critical cloud security misconfiguration requiring immediate SOC intervention.

**📸 Evidence:** evidence/q6_bucket_name.png

### Question 7 - File Uploaded to Public S3 Bucket

**Objective:** Identify the name of the file uploaded to the S3 bucket whilst it was publicly accessible.

**SOC Relevance:**

Detecting object uploads to public buckets helps SOC teams:

- Identify data exposure
- Detect attacker validation or probing
- Assess impact

**SPL Query Used:**

  index=botsv3 sourcetype=aws:s3:accesslogs 
  "frothlywebcode"
  "REST.PUT.OBJECT"
  " 200 "

**Findings:**

S3 access logs show a successful PUT operation uploading the file OPEN_BUCKET_PLEASE_FIX.txt to the publicly accessible bucket. This confirms that the misconfiguration was externally exploitable and that unauthorized data interaction occurred during the exposure window.

**📸 Evidence:** evidence/q7_text_file_name.png
            
### Question 8 – Endpoint OS Deviation

**Objective:** Identify the endpoint running a different Windows edition.

**SOC Relevance:**
OS deviations may indicate:

Privileged workstations

Administrative endpoints

Increased attack surface


**SPL Query:**

  index=botsv3 sourcetype=winhostmon
  | stats count by OS host


**Findings:**
Most endpoints run Windows 10 Pro, while one host (BSTOLL-L) runs Windows 10 Enterprise.

**To resolve the full FQDN:**

  index=botsv3 host="BSTOLL-L"
  | stats values(host)


Correlating with domain context across the dataset confirms the FQDN:

bstoll-l.froth.ly


**📸 Evidence:** evidence/q8_os_deviation.png

**📸 Evidence:** evidence/q8_BSTOLL_host.png

## Conclusion Lessons Learned


This investigation demonstrates how SIEM platforms such as Splunk enable SOC analysts to reconstruct security incidents using log correlation and structured analysis. Key lessons include:

Cloud misconfigurations remain a high-impact threat vector.

Identity and access monitoring is critical for AWS environments.

Endpoint inconsistencies can reveal high-value assets.

From a SOC perspective, improvements could include:

Automated detection for public S3 ACLs

MFA enforcement alerts

Baseline deviation monitoring for endpoints

## Video Presentation


🎥 YouTube Walkthrough (Unlisted):
Link here

The video demonstrates:

Key SPL queries

Evidence interpretation

SOC incident response reflections

## References


[1] Splunk Inc., Boss of the SOC v3 Dataset, 2018.

[2] NIST, Computer Security Incident Handling Guide (SP 800-61r2).

[3] AWS, CloudTrail User Guide.
