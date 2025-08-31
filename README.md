Threat-IOC-Analysis-Tool

A web-based tool designed to analyze Indicators of Compromise (IOCs) such as URLs, domains, IP addresses, and file hashes. It integrates multiple threat intelligence APIs to assess the risk level of each IOC, providing cybersecurity professionals with actionable insights.

⚙️ Features

Multi-IOC Input: Analyze URLs, domains, IPs, and file hashes.

API Integrations:

VirusTotal

AbuseIPDB

URLhaus

Open Threat Exchange (OTX)

Risk Assessment: Categorizes IOCs as Malicious, Suspicious, or Benign.

Confidence Scoring: Displays risk ratings with sources for transparency.

User Interface: Built with React and Tailwind CSS for a responsive experience.


🚀 Installation

Clone the repository:
git clone https://github.com/MoamenHamdan/Threat-IOC-Analysis-Tool.git
cd Threat-IOC-Analysis-Tool

Install dependencies:
npm install


Set up your .env file with the required API keys.

Run the development server:
npm run dev


Access the application at http://localhost:3000.

🛠️ Technologies Used

Frontend: React, Tailwind CSS

Backend: Vite (for development server)

APIs: VirusTotal, AbuseIPDB, URLhaus, OTX

📄 License

This project is licensed under the MIT License - see the LICENSE