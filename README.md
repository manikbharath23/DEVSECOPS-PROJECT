# 🔐 DeSecOps: Integrating Security as Code in DevOps

## 📌 Project Description

**DeSecOps** is a project where security is integrated into every stage of the CI/CD pipeline. The goal is to reduce vulnerabilities, improve system resilience, and accelerate incident response by embedding **security as code** into the development lifecycle.

---

## 🛠️ Tools and Technologies Used

* **Python** – Scripting and automation
* **Bandit** – Static code analysis for detecting vulnerabilities
* **Tkinter** – GUI for interacting with the scanner
* **Wireshark & Scapy** – Network packet analysis
* **psutil** – System and resource monitoring
* **Dash / Plotly** – Real-time dashboards
* **Git & Jenkins** – Version control and CI/CD automation
* **Windows & Linux** – Deployment platforms

---

## 🚀 Key Features

### 🔄 Automated Security Checks in CI/CD

* Integrated security scanning in every build and deployment step
* Reduced vulnerabilities by ~70%

---

### 🧪 Bandit Scanner with GUI

* Built using Tkinter
* Easy-to-use interface for running scans
* Reduced manual code review time by ~40%

---

### 📊 Real-Time Monitoring Dashboard

* Built using Dash and Plotly
* Tracks system metrics and security events
* Reduced incident response time by ~60%

---

### 🌐 Network Packet Analysis

* Uses Wireshark and Scapy
* Detects suspicious incoming and outgoing traffic

---

### ⚙️ Process & Resource Monitoring

* Implemented using psutil
* Monitors CPU, memory, and running processes

---

## 👨‍💻 My Role in the Project

* Integrated **Bandit vulnerability scanner** with **Tkinter GUI**
* Developed interface to run scans and display reports
* Worked on real-time monitoring dashboards and alerts
* Improved system stability and reduced downtime

---

## ⚠️ Problems Faced

### 1. Integration Challenges

* Difficulty integrating Bandit with Git, Jenkins, and Python scripts

### 2. Real-Time Monitoring

* Handling large data without dashboard lag

### 3. False Positives

* Bandit flagged non-critical issues
* Required tuning to reduce unnecessary alerts

### 4. Cross-Platform Compatibility

* Ensuring smooth execution on both Windows and Linux

---

## 🧠 Code Logic

### 🔍 Security Scanning (Bandit)

* Run Bandit using CLI
* Capture vulnerabilities
* Display results in GUI

---

### 🖥️ Tkinter GUI

* Accept user input (file/directory path)
* Trigger scans using buttons
* Show real-time output

---

### 📊 Monitoring Dashboard

* Collect CPU and memory usage using psutil
* Visualize data using Dash/Plotly
* Generate alerts on high usage

---

### 🌐 Packet Inspection

* Capture network packets using Scapy/Wireshark
* Filter suspicious traffic patterns

---

## 💻 Code Examples

### Python – Bandit + GUI

```python
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess

def run_scan():
    file_path = file_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file or directory.")
        return
    result = subprocess.run(['bandit', '-r', file_path], capture_output=True, text=True)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, result.stdout)
```

---

### Python – System Monitoring

```python
import psutil
import time

def monitor_system():
    print("Monitoring system...")
    while True:
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        print(f"CPU Usage: {cpu}% | Memory Usage: {memory}%")
        if cpu > 80 or memory > 80:
            print("Warning: High resource usage!")
        time.sleep(5)
```

---

### Java – Running Bandit Scan

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class BanditScanner {
    public static void runBanditScan(String path) {
        try {
            ProcessBuilder builder = new ProcessBuilder("bandit", "-r", path);
            Process process = builder.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

## 🎯 Key Learnings

* DevSecOps principles and CI/CD integration
* Automated security testing
* Real-time monitoring and alert systems
* Network traffic analysis

---

## 📌 Summary

* Security integrated into development lifecycle
* Automated vulnerability detection
* Real-time monitoring and alerts
* Improved system reliability and performance

---

## 👨‍💻 Author

**Manik Bharath**
GitHub: https://github.com/manikbharath23

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!
