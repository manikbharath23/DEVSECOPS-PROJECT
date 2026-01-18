import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import os
import threading
import shutil

selected_file = None
scan_process = None
stop_scan_flag = False


# ✅ SDLC phase detection logic
def get_sdlc_phase(description: str) -> str:
    description = description.lower()

    if "hardcoded" in description or "credential" in description or "password" in description:
        return "Requirement Phase"
    elif any(kw in description for kw in ["eval", "exec", "pickle", "yaml.load", "os.system", "subprocess"]):
        return "Implementation Phase"
    elif "input" in description or "validation" in description:
        return "Requirement Phase"
    elif "debug" in description or "print" in description:
        return "Deployment/Maintenance Phase"
    elif any(kw in description for kw in ["assert", "try", "exception"]):
        return "Testing Phase"
    elif any(kw in description for kw in ["blacklist", "cipher", "ciphers"]):
        return "Design Phase"
    else:
        return "Implementation Phase"


# ✅ Parse Bandit output for issues and SDLC phase
def parse_bandit_output(output: str):
    issues = []
    lines = output.splitlines()

    for i in range(len(lines)):
        if ">> Issue:" in lines[i]:
            issue = {
                "description": lines[i].strip(),
                "severity": "",
                "confidence": "",
                "file": "",
                "line": "",
                "code": "",
                "phase": get_sdlc_phase(lines[i]),
            }

            for j in range(i + 1, min(i + 12, len(lines))):
                if "Severity:" in lines[j]:
                    parts = lines[j].split()
                    # Example: Severity: Low   Confidence: High
                    if len(parts) >= 4:
                        issue["severity"] = parts[1]
                        issue["confidence"] = parts[3]

                elif "Location:" in lines[j]:
                    loc = lines[j].replace("Location:", "").strip()
                    # Example: .\scanner.py:118:23
                    if ":" in loc:
                        p = loc.split(":")
                        issue["file"] = p[0].strip()
                        issue["line"] = p[1].strip() if len(p) > 1 else ""

                elif lines[j].strip() and not lines[j].strip().startswith("---"):
                    # code line
                    issue["code"] = lines[j].strip()
                    break

            issues.append(issue)

    return issues


# ✅ File type checker
def is_code_file(file_path: str) -> bool:
    code_extensions = [
        ".py", ".java", ".c", ".cpp", ".js", ".rb", ".go",
        ".php", ".html", ".css", ".ts"
    ]
    ext = os.path.splitext(file_path)[1]
    return ext.lower() in code_extensions


# ✅ File upload
def upload_file():
    global selected_file
    selected_file = filedialog.askopenfilename()

    if selected_file:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"✅ File selected: {selected_file}\n")


# ✅ Start scan (runs in thread)
def process_scan():
    global stop_scan_flag

    stop_scan_flag = False
    output_text.delete(1.0, tk.END)

    if not selected_file:
        messagebox.showerror("No File", "Please upload a file first.")
        return

    file_path = selected_file
    output_text.insert(tk.END, f"🔍 Scanning file: {file_path}\n\n")

    if not is_code_file(file_path):
        output_text.insert(tk.END, "❌ This is NOT a code file or application.\n")
        messagebox.showinfo("Non-Code File", "This is not a code file. No scan needed.")
        return

    # ✅ Disable Start while scanning
    scan_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    # ✅ Scan in separate thread to avoid GUI freeze
    thread = threading.Thread(target=run_bandit_scan, args=(file_path,))
    thread.start()


# ✅ Stop scan
def stop_scan():
    global scan_process, stop_scan_flag

    stop_scan_flag = True

    try:
        if scan_process and scan_process.poll() is None:
            output_text.insert(tk.END, "\n🛑 Stopping scan...\n")
            scan_process.terminate()
    except Exception as e:
        output_text.insert(tk.END, f"\n❌ Unable to stop scan: {e}\n")

    reset_buttons()


# ✅ Reset UI buttons
def reset_buttons():
    scan_btn.config(state=tk.NORMAL)
    stop_btn.config(state=tk.DISABLED)


# ✅ Bandit scan actual logic
def run_bandit_scan(file_path: str):
    global scan_process, stop_scan_flag

    try:
        bandit_path = shutil.which("bandit")
        if not bandit_path:
            output_text.insert(tk.END, "❌ Bandit not found.\n")
            output_text.insert(tk.END, "👉 Install: pip install bandit\n")
            messagebox.showerror("Bandit Missing", "Bandit tool not installed. Run: pip install bandit")
            reset_buttons()
            return

        # ✅ Full path used -> fixes B607 partial path warning
        # ✅ shell=False already safer
        scan_process = subprocess.Popen(  # nosec B603
            [bandit_path, "-r", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False
        )

        stdout, stderr = scan_process.communicate()

        if stop_scan_flag:
            output_text.insert(tk.END, "\n🛑 Scan stopped by user.\n")
            reset_buttons()
            return

        if stderr:
            output_text.insert(tk.END, f"⚠️ Bandit Error:\n{stderr}\n")

        issues = parse_bandit_output(stdout)

        if issues:
            output_text.insert(tk.END, "🚨 Vulnerabilities found:\n\n")
            for issue in issues:
                output_text.insert(tk.END, f"{issue['description']}\n")
                output_text.insert(tk.END, f"   Severity: {issue['severity']} | Confidence: {issue['confidence']}\n")
                output_text.insert(tk.END, f"   Location: {issue['file']}  Line: {issue['line']}\n")
                output_text.insert(tk.END, f"   Code: {issue['code']}\n")
                output_text.insert(tk.END, f"   SDLC Phase: {issue['phase']}\n")
                output_text.insert(tk.END, "-" * 75 + "\n")

            messagebox.showwarning("Scan Complete", "Vulnerabilities detected! See the output.")
        else:
            output_text.insert(tk.END, "✅ This is secure code/application. No vulnerabilities found.\n")
            messagebox.showinfo("Safe", "No vulnerabilities found. The file is secure.")

    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {str(e)}\n")
        messagebox.showerror("Error", f"An error occurred during scanning.\n{e}")

    reset_buttons()


# ✅ GUI Setup
root = tk.Tk()
root.title("Vulnerability Scanner Tool")
root.geometry("800x500")
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
    fg="white"
)
upload_btn.pack(pady=5)

scan_btn = tk.Button(
    root,
    text="Start Scan",
    command=process_scan,
    width=20,
    bg="green",
    fg="white"
)
scan_btn.pack(pady=5)

stop_btn = tk.Button(
    root,
    text="Stop Scan",
    command=stop_scan,
    width=20,
    bg="red",
    fg="white",
    state=tk.DISABLED
)
stop_btn.pack(pady=5)

output_text = scrolledtext.ScrolledText(
    root,
    wrap=tk.WORD,
    width=100,
    height=18,
    bg="black",
    fg="white",
    font=("Courier", 10)
)
output_text.pack(padx=10, pady=10)

root.mainloop()
