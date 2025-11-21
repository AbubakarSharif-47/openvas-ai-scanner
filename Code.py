import streamlit as st
import time
import os
import base64
import numpy as np
import pandas as pd
import torch
import re
import joblib
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree
from datetime import datetime

# GVM Configuration
GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"
USERNAME = "admin"
PASSWORD = "42c6a1ff-72fe-4b28-b675-64801c8bc800"
PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
REPORT_FORMAT_ID = "c1645568-627a-11e3-a660-406186ea4fc5"

st.set_page_config(page_title="OpenVAS AI Scanner", layout="wide")
st.title("🛡️ OpenVAS Vulnerability Scanner with AI")
st.sidebar.header("🔍 System Logs")
st.sidebar.info("This panel shows real-time progress and backend activity logs.")

# ======== Caching AI Model Loading ========
@st.cache_resource(show_spinner=False)
def load_severity_model():
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Model1.pkl")
    model, label_encoder = joblib.load(model_path)
    sbert = SentenceTransformer('all-MiniLM-L6-v2')
    return model, label_encoder, sbert

@st.cache_resource(show_spinner=False)
def load_remediation_model():
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    remediation_model = SentenceTransformer('all-MiniLM-L6-v2')
    embeddings = torch.load(os.path.join(CURRENT_DIR, "Model2.pt"), map_location=torch.device('cpu'))
    metadata = pd.read_csv(os.path.join(CURRENT_DIR, "metadata.csv"))
    problems = metadata['combined_problem'].tolist()
    solutions = metadata['remediation'].tolist()
    return remediation_model, embeddings, metadata, problems, solutions

# Load Models with UI Feedback
with st.spinner("🔄 Loading Severity Prediction Model..."):
    try:
        model, label_encoder, model_sbert = load_severity_model()
        st.sidebar.success("✅ Severity model integrated")
    except Exception as e:
        st.sidebar.error(f"❌ Error loading severity model: {str(e)}")
        model = label_encoder = model_sbert = None

with st.spinner("🔄 Loading Remediation Model..."):
    try:
        remediation_model, remediation_embeddings, remediation_metadata, remediation_problems, remediation_solutions = load_remediation_model()
        st.sidebar.success("✅ Remediation model and data loaded")
    except Exception as e:
        st.sidebar.error(f"❌ Error loading remediation model: {str(e)}")
        remediation_model = remediation_embeddings = remediation_metadata = None

def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def predict_severity(description, cvss):
    try:
        cleaned_text = clean_text(description)
        embedding = model_sbert.encode([cleaned_text])
        cvss_val = float(cvss) if cvss else 0.0
        embedding_with_cvss = np.hstack((embedding, [[cvss_val]]))
        prediction = model.predict(embedding_with_cvss)
        return label_encoder.inverse_transform(prediction)[0]
    except:
        return "Error"

def get_remediation(description, cvss):
    try:
        query = f"vulnerability: {description} cvss: {cvss}"
        query_embedding = remediation_model.encode(query, convert_to_tensor=True)
        similarities = cosine_similarity([
            query_embedding.cpu().numpy()], remediation_embeddings.cpu().numpy())[0]
        top_result = np.argmax(similarities)
        return f"{remediation_solutions[top_result]} (Similarity: {round(similarities[top_result], 3)})"
    except:
        return "Error retrieving remediation."

def run_scan(target_ip, scan_name, progress_bar, status_text):
    logs = []
    vulnerabilities = []
    start_time = datetime.now()

    logs.append("🔌 Connecting to OpenVAS...")
    status_text.text("🔌 Connecting to OpenVAS...")
    connection = UnixSocketConnection(path=GVM_SOCKET_PATH)
    with Gmp(connection) as gmp:
        logs.append("🔑 Authenticating with OpenVAS...")
        status_text.text("🔑 Authenticating with OpenVAS...")
        gmp.authenticate(USERNAME, PASSWORD)

        logs.append("🎯 Creating scan target...")
        status_text.text("🎯 Creating scan target...")
        target_response = gmp.create_target(name=scan_name, hosts=[target_ip], port_list_id=PORT_LIST_ID)
        target_id = etree.fromstring(target_response).get("id")

        logs.append("📡 Fetching scanner info...")
        status_text.text("📡 Fetching scanner info...")
        scanners_xml = etree.fromstring(gmp.get_scanners())
        scanner_id = next(
            (s.get("id") for s in scanners_xml.findall("scanner") if s.findtext("name") == "OpenVAS Default"), None)

        logs.append("📝 Creating scan task...")
        status_text.text("📝 Creating scan task...")
        task_id = etree.fromstring(gmp.create_task(
            name=scan_name, config_id=SCAN_CONFIG_ID, target_id=target_id, scanner_id=scanner_id)).get("id")

        logs.append("🚀 Starting scan task...")
        status_text.text("🚀 Starting scan task...")
        gmp.start_task(task_id)

        while True:
            task_status_xml = etree.fromstring(gmp.get_task(task_id=task_id))
            status = task_status_xml.findtext(".//status")
            progress = task_status_xml.findtext(".//progress", "0")
            logs.append(f"⏳ Scan progress: {progress}%")
            status_text.text(f"⏳ Scan progress: {progress}% completed...")
            try:
                progress_bar.progress(int(progress))
            except:
                pass
            if status == "Done":
                report_id = task_status_xml.find(".//report").get("id")
                logs.append("✅ Scan completed")
                status_text.text("✅ Scan completed")
                break
            elif status in ["Stopped", "Failed"]:
                raise Exception(f"Scan failed with status: {status}")
            time.sleep(10)

        # ====== Fetch and Save XML Report ======
        logs.append("📄 Fetching XML report...")
        status_text.text("📄 Fetching XML report...")
        xml_response = gmp.send_command(f'<get_reports report_id="{report_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" details="1"/>')  # format_id for XML
        xml_report = etree.fromstring(xml_response)
        xml_string = etree.tostring(xml_report, pretty_print=True, encoding='utf-8').decode('utf-8')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        xml_filename = f"openvas_scan_{scan_name}_{timestamp}.xml"
        xml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), xml_filename)
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(xml_string)
        logs.append(f"💾 XML report saved as {xml_filename}")

        # ====== Convert XML to CSV ======
        csv_filename = f"openvas_scan_{scan_name}_{timestamp}.csv"
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), csv_filename)
        results = xml_report.findall(".//result")
        csv_rows = []
        for r in results:
            name = r.findtext("name", "Unknown")
            cvss = r.findtext(".//cvss_base", "0.0")
            desc = r.findtext("description", "No description.")
            # Extract CVE IDs
            cve_ids = []
            nvt = r.find("nvt")
            if nvt is not None:
                refs = nvt.find("refs")
                if refs is not None:
                    for ref in refs.findall("ref"):
                        if ref.get("type") == "cve":
                            cve_ids.append(ref.get("id"))
                # Extract attack vector from tags
                tags = nvt.findtext("tags", "")
                attack_vector = "N/A"
                for tag in tags.split("|"):
                    if tag.startswith("cvss_base_vector="):
                        attack_vector = tag.split("=", 1)[1]
                        break
            else:
                attack_vector = "N/A"
            cve_ids_str = ";".join(cve_ids) if cve_ids else "N/A"
            csv_rows.append({
                'name': name,
                'cvss': cvss,
                'description': desc,
                'cve_ids': cve_ids_str,
                'attack_vector': attack_vector
            })
        df = pd.DataFrame(csv_rows)
        df.to_csv(csv_path, index=False)
        logs.append(f"💾 CSV report saved as {csv_filename}")

        # ====== Feed CSV Data to Models ======
        vulnerabilities = []
        for _, row in df.iterrows():
            severity = predict_severity(row['description'], row['cvss'])
            remediation = get_remediation(row['description'], row['cvss'])
            vulnerabilities.append((row['name'], row['cvss'], severity, row['description'], remediation, row['cve_ids'], row['attack_vector']))

    end_time = datetime.now()
    duration = str(end_time - start_time).split('.')[0]
    logs.append(f"🕒 Scan Duration: {duration}")
    return logs, vulnerabilities, None, duration

# ===== Streamlit Main UI =====
ip = st.text_input("Target IP Address")
name = st.text_input("Scan Name")

if st.button("🚀 Start Scan"):
    if not ip or not name:
        st.warning("Please provide both IP and scan name")
    else:
        with st.spinner("🔄 Initializing scan process..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            try:
                logs, results, _, duration = run_scan(ip, name, progress_bar, status_text)
                st.success("✅ Scan completed successfully!")
                st.write(f"🕒 **Scan Duration:** {duration}")
                st.subheader("📜 Scan Logs")
                for log in logs:
                    st.sidebar.text(log)
                if results:
                    st.subheader("🛡️ Vulnerability Findings")
                    for i, (n, c, s, d, r, cve, av) in enumerate(results, 1):
                        with st.expander(f"Finding {i}: {n}"):
                            st.write(f"**CVE IDs:** {cve}")
                            st.write(f"**Attack Vector:** {av}")
                            st.write(f"**CVSS Score:** {c}")
                            # Color severity
                            severity_color = {
                                'critical': 'red',
                                'high': 'orange',
                                'medium': 'yellow',
                                'low': 'green'
                            }.get(s.lower(), 'gray')
                            st.markdown(f"**AI-Predicted Severity:** <span style='color:{severity_color};font-weight:bold'>{s}</span>", unsafe_allow_html=True)
                            st.write(f"**Description:** {d}")
                            st.write(f"**Suggested Remediation:** {r}")
                else:
                    st.info("🎉 No vulnerabilities found.")
            except Exception as e:
                st.error(f"❌ Error during scan: {str(e)}")

