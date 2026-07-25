import re
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse


def analyze_url():
    url = entry_url.get().strip()

    if not url:
        messagebox.showwarning("Warning", "Please enter a URL first!")
        return

    score = 0
    reasons = []

    # 1. HTTPS Check
    if not url.startswith("https://"):
        score += 2
        reasons.append("- Missing HTTPS protocol.")

    # 2. IP Address Check
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    if re.search(ip_pattern, url):
        score += 3
        reasons.append("- Uses direct IP address instead of domain.")

    # 3. @ Symbol Check
    if "@" in url:
        score += 3
        reasons.append("- Contains '@' symbol (misleading URL).")

    # 4. URL Length Check
    if len(url) > 75:
        score += 1
        reasons.append("- URL length is too long (> 75 chars).")

    # 5. Domain Hyphens Check
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.count("-") > 2:
        score += 2
        reasons.append("- Domain contains too many hyphens (-).")

    # 6. URL Shorteners Check
    shorteners = ["bit.ly", "tinyurl.com", "is.gd", "buff.ly", "ow.ly"]
    if any(shortener in domain for shortener in shorteners):
        score += 2
        reasons.append("- Uses URL shortening service.")

    # Result & Color setup
    if score == 0:
        status_text = "SAFE: URL appears to be safe."
        status_color = "#2ecc71"
    elif score < 3:
        status_text = "SUSPICIOUS: Moderate risk detected."
        status_color = "#f39c12"
    else:
        status_text = "DANGER: High risk Phishing URL!"
        status_color = "#e74c3c"

    # Display Result
    lbl_result.config(text=status_text, fg=status_color)

    # Display Reasons
    text_reasons.config(state="normal")
    text_reasons.delete("1.0", tk.END)
    if reasons:
        text_reasons.insert(
            tk.END, "Detection Reasons:\n\n" + "\n".join(reasons)
        )
    else:
        text_reasons.insert(tk.END, "No risk factors found.")
    text_reasons.config(state="disabled")


# Main Window Setup
root = tk.Tk()
root.title("Phishing Detection System")
root.geometry("380x520")
root.configure(bg="#1e1e1e")

# Title
lbl_title = tk.Label(
    root,
    text="Phishing Detection System",
    font=("Arial", 14, "bold"),
    fg="white",
    bg="#1e1e1e",
)
lbl_title.pack(pady=12)

# Input Prompt
lbl_prompt = tk.Label(
    root,
    text="Enter URL to analyze:",
    font=("Arial", 10),
    fg="#ccc",
    bg="#1e1e1e",
)
lbl_prompt.pack(pady=5)

entry_url = tk.Entry(
    root, font=("Arial", 11), width=32, justify="center", bd=2
)
entry_url.pack(pady=5)

# Check Button
btn_check = tk.Button(
    root,
    text="Analyze URL",
    font=("Arial", 10, "bold"),
    bg="#3498db",
    fg="white",
    command=analyze_url,
    padx=10,
    pady=5,
)
btn_check.pack(pady=12)

# Result Label
lbl_result = tk.Label(
    root, text="", font=("Arial", 11, "bold"), bg="#1e1e1e", wraplength=340
)
lbl_result.pack(pady=8)

# Reasons Text Area
text_reasons = tk.Text(
    root,
    height=8,
    width=38,
    font=("Arial", 9),
    bg="#2d2d2d",
    fg="white",
    bd=0,
)
text_reasons.pack(pady=10)
text_reasons.config(state="disabled")

# Footer / Info
lbl_footer = tk.Label(
    root,
    text="Student: Akram Hussein | ID: 3230606118",
    font=("Arial", 8),
    fg="#888",
    bg="#1e1e1e",
)
lbl_footer.pack(side="bottom", pady=10)

root.mainloop()
