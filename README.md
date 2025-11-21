# 🛡️ OpenVAS Vulnerability Scanner with AI Integration

A powerful, automated vulnerability assessment tool that integrates **OpenVAS (Greenbone Vulnerability Management)** with **Artificial Intelligence**. This project creates a user-friendly interface to manage scans, analyze reports, and utilize Machine Learning to predict vulnerability severity and suggest remediations.

⚠️ Disclaimer
This tool is intended for educational and authorized security assessment purposes only. You must have explicit permission to scan any network or system. The authors are not responsible for any misuse or damage caused by this tool.

## 📖 Overview

This project automates the vulnerability scanning process by connecting directly to the OpenVAS Greenbone Management Protocol (GMP). It goes beyond traditional scanning by incorporating AI models to analyze finding descriptions.
- **Backend**: Python script interfacing with the GVM daemon via Unix sockets.
- **Frontend**: A **Streamlit** dashboard for starting scans, viewing real-time logs, and visualizing results.
- **AI Engine**: Uses **SentenceTransformers**, **PyTorch**, and **Scikit-learn** to classify severity and recommend remediation steps based on vulnerability patterns.

## ✨ Key Features

* **🚀 Automated Scanning**: Start OpenVAS scans directly from a web UI without navigating the complex GVM interface.
* **🧠 AI-Powered Analysis**:
    * Uses Deep Learning (`Model2.pt`) and Logistic Regression (`Model1.pkl`) to analyze vulnerability descriptions.
    * Predicts **Severity Levels** (Critical, High, Medium, Low) contextually.
    * Generates/Retrieves **Smart Remediations** based on historical data.
* **📊 Interactive Dashboard**: Built with Streamlit to display finding details, CVE IDs, Attack Vectors, and CVSS scores in an organized manner.
* **📝 Real-time Logging**: Sidebar logs tracking the progress of authentication, target creation, and scan status.
* **📄 PDF/XML Report Parsing**: Automatically parses the generated OpenVAS reports for immediate display.

## 🛠️ Tech Stack

* **Language**: Python 3.8+
* **Framework**: [Streamlit](https://streamlit.io/)
* **Vulnerability Scanner**: [OpenVAS / Greenbone Vulnerability Management (GVM)](https://www.greenbone.net/)
* **Machine Learning**:
    * `PyTorch` (Deep Learning model)
    * `Sentence-Transformers` (Text Embeddings)
    * `Scikit-learn` (Logistic Regression & Metrics)
    * `Joblib` (Model serialization)
* **Data Handling**: `Pandas`, `NumPy`, `lxml` (XML parsing)

## ⚙️ Prerequisites

Before running the tool, ensure you have the following installed:

1.  **Linux Environment** (Kali Linux or Ubuntu recommended).
2.  **OpenVAS / GVM** installed and running.
    * The `gvmd` service must be active.
    * You must have the Unix socket path available (usually `/run/gvmd/gvmd.sock`).
3.  **Python 3.x** installed.

## 📦 Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/AbubakarSharif-47/openvas-ai-scanner.git]
    cd openvas-ai-scanner
    ```

2.  **Install Python Dependencies**
    ```bash
    pip install streamlit python-gvm lxml torch sentence-transformers scikit-learn pandas numpy joblib
    ```

3.  **Ensure Model Files are Present**
    Make sure the following files are in the root directory:
    * `Code.py` (Main application)
    * `Model1.pkl` (Scikit-learn model)
    * `Model2.pt` (PyTorch model)
    * `metadata.csv` (Training/Reference data)

## 🔧 Configuration

Open `Code.py` and update the **GVM Configuration** section to match your local OpenVAS setup:

```python
# GVM Configuration
GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"  # Path to your GVM socket
USERNAME = "admin"                       # Your OpenVAS Username
PASSWORD = "your_password"               # Your OpenVAS Password

# These IDs are specific to your OpenVAS installation. 
# You can retrieve them using `gvm-cli` or from the GVM web interface.
PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # Default "All IANA assigned TCP"
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea" # Default "Full and fast"
REPORT_FORMAT_ID = "c1645568-627a-11e3-a660-406186ea4fc5" # XML Format ID


⚠️ Disclaimer
This tool is intended for educational and authorized security assessment purposes only. You must have explicit permission to scan any network or system. The authors are not responsible for any misuse or damage caused by this tool.
