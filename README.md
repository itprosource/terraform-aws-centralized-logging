<div id="top"></div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/itprosource/terraform-aws-centralized-logging">
  </a>

<h3 align="center">Terraform - Centralized Logging Solution</h3>

  <p align="center">
    Template which deploys an Opensearch/Elasticsearch cluster with Kinesis-based ingest pipeline. Based on AWS-curated <a href="https://aws.amazon.com/solutions/implementations/centralized-logging/">Centralized Logging Solution</a>.
    <br />
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project
This module deploys a VPC-hosted Opensearch or Elasticsearch cluster as depicted in AWS' Centralized Logging Solution - using Cloudwatch Destinations/Kinesis Data stream to ingest data, pass through a Lambda function which transforms data into Opensearch-readable format, then pipes formatted data through Kinesis Firehose before depositing logs in the Opensearch cluster. Access to Opensearch dashboard is faciliated through an ec2 Bastion host and Cognito user authentication. Includes option for ultrawarm storage. 

### User Management
User accounts are managed in Cognito. Simply go to the user pool to add or remove users. 

### VPC Security
The cluster is configured to allow external access only through 443 on a bastion host. It is not recommended to leave the dashboard login screen open to the public. Use the bastion host to access the dashboard. Bastion host access rules are controlled in the template. 

# Future Updates
As time permits, I plan to work on the following updates:
1. Key Cloudwatch alarms. AWS curates a list of <a href="[url](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cloudwatch-alarms.html)">best-practice Cloudwatch alarms</a> for monitoring the Opensearch service itself. I would like to add an option for deploying these in the template. 
2. Build out more Opensearch options - Custom Endpoints, Fine-Grained Access Control, etc. 

### Built With

* [Terraform](https://www.terraform.io/)


