# AWS Three-Tier Secure Architecture

## Project Overview
This project demonstrates a production-ready, highly secure AWS network infrastructure deployed using **Terraform**. The architecture follows the principle of least privilege, ensuring that sensitive data is isolated from the public internet.

The project includes an automated security audit. Current status: 98 tests passed, identified vulnerabilities are being addressed according to security priorities.

## Security Features
* **VPC Isolation:** A dedicated Virtual Private Cloud with custom CIDR block.
* **Tiered Subnets:** Logical separation between Public (Web) and Private (Database) layers.
* **Zero Trust Access:** Security Groups are configured to allow traffic ONLY from the Web layer to the Database, blocking all direct external access.
* **Infrastructure as Code (IaC):** Fully automated deployment for consistency and security auditing.

## Architecture Diagram (Logical)
1. **Public Layer:** Internet Gateway -> Load Balancer/Web Server (Port 80).
2. **Private Layer:** No Direct Internet Access -> Database (Port 3306) -> Only accessible from Web SG.

## Technologies Used
* **Terraform** (HCL)
* **AWS** (VPC, EC2, Security Groups, IAM)

## License
This project is licensed under the MIT License.
