import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import os
import re

selected_file = None

# -----------------------------
# 1) Check file type
# -----------------------------
def is_code_file(file_path: str) -> bool:
    code_extensions = [
        ".py", ".java", ".c", ".cpp", ".js", ".rb", ".go", ".php",
        ".html", ".css", ".ts", ".json", ".yml", ".yaml", ".sh"
    ]
    ext = os.path.splitext(file_path)[1]
    return ext.lower() in code_extensions


# -----------------------------
# 2) SDLC Phase detection logic
# -----------------------------
def get_sdlc_phase(description: str) -> str:
    d = description.lower()

    if "hardcoded" in d or "credential" in d or "password" in d or "secret" in d:
        return "Requirement Phase (Secrets)"
    elif any(kw in d for kw in ["eval", "exec", "pickle", "yaml.load", "os.system", "subprocess"]):
        return "Implementation Phase"
    elif any(kw in d for kw in ["input", "validation", "sanitize"]):
        return "Design/Implementation Phase"
    elif any(kw in d for kw in ["assert", "try", "exception", "error"]):
        return "Testing Phase"
    elif any(kw in d for kw in ["debug", "print", "logging"]):
        return "Deployment/Maintenance Phase"
    else:
        return "Implementation Phase"


# -----------------------------
# 3) Parse Bandit output
# -----------------------------
def parse_bandit_output(output: str):
    issues = []
    lines = output.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        if line.startswith(">> Issue:"):
            issue = {
                "description": line.replace(">> Issue:", "").strip(),
                "severity": "",
                "confidence": "",
                "file": "",
                "line": "",
                "code": "",
                "phase": ""
            }

            j = i + 1
            while j < len(lines) and j <= i + 12:
                l = lines[j].strip()

                if l.startswith("Severity:"):
                    sev_match = re.search(r"Severity:\s*(\w+)", l)
                    conf_match = re.search(r"Confidence:\s*(\w+)", l)
                    if sev_match:
                        issue["severity"] = sev_match.group(1)
                    if conf_match:
                        issue["confidence"] = conf_match.group(1)

                elif l.startswith("Location:"):
                    loc = l.replace("Location:", "").strip()
                    if ":" in loc:
                        file_part, line_part = loc.rsplit(":", 1)
                        issue["file"] = file_part.strip()
                        issue["line"] = line_part.strip()
                    else:
                        issue["file"] = loc

                elif l.startswith("Code:"):
                    issue["code"] = l.replace("Code:", "").strip()

                j += 1

            issue["phase"] = get_sdlc_phase(issue["description"])
            issues.append(issue)
            i = j
            continue

        i += 1

    return issues


# -----------------------------
# 4) Upload file
# -----------------------------
def upload_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    if selected_file:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"File selected: {selected_file}\n")


# -----------------------------
# 5) Scan file using bandit
# -----------------------------
def process_scan():
    output_text.delete(1.0, tk.END)

    if not selected_file:
        messagebox.showerror("No File", "Please upload a file first.")
        return

    file_path = selected_file
    output_text.insert(tk.END, f"Scanning file: {file_path}\n\n")

    if not is_code_file(file_path):
        output_text.insert(tk.END, "This is NOT a code file/application. No scan needed.\n")
        messagebox.showinfo("Non-Code File", "This file is not a code/executable file. No scan needed.")
        return

    try:
        result = subprocess.run(
            ["bandit", "-r", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = result.stdout
        issues = parse_bandit_output(output)

        if issues:
            output_text.insert(tk.END, "Vulnerabilities found ✅\n\n")
            for idx, issue in enumerate(issues, start=1):
                output_text.insert(tk.END, f"{idx}) {issue['description']}\n")
                output_text.insert(tk.END, f"   Severity: {issue['severity']} | Confidence: {issue['confidence']}\n")
                output_text.insert(tk.END, f"   Location: {issue['file']}  Line: {issue['line']}\n")
                if issue["code"]:
                    output_text.insert(tk.END, f"   Code: {issue['code']}\n")
                output_text.insert(tk.END, f"   SDLC Phase: {issue['phase']}\n\n")

            messagebox.showwarning("Scan Complete", "Vulnerabilities detected! See output.")
        else:
            output_text.insert(tk.END, "This is a secure code/application ✅\nNo vulnerabilities found.\n")
            messagebox.showinfo("Safe", "No vulnerabilities found. File is secure.")

    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")
        messagebox.showerror("Error", "An error occurred during scanning.")


# -----------------------------
# 6) GUI setup
# -----------------------------
root = tk.Tk()
root.title("Vulnerability Scanner Tool")
root.geometry("900x550")
root.config(bg="black")

title = tk.Label(
    root,
    text="Advanced Vulnerability Scanner",
    font=("Arial", 16, "bold"),
    fg="lime",
    bg="black"
)
title.pack(pady=10)

upload_btn = tk.Button(
    root,
    text="Upload File",
    command=upload_file,
    width=20,
    bg="darkorange",
    fg="white",
    font=("Arial", 12, "bold")
)
upload_btn.pack(pady=5)

scan_btn = tk.Button(
    root,
    text="Start Scan",
    command=process_scan,
    width=20,
    bg="green",
    fg="white",
    font=("Arial", 12, "bold")
)
scan_btn.pack(pady=5)

output_text = scrolledtext.ScrolledText(
    root,
    wrap=tk.WORD,
    width=110,
    height=22,
    bg="black",
    fg="white",
    font=("Courier", 10)
)
output_text.pack(padx=10, pady=10)

root.mainloop()