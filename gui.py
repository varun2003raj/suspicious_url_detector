import subprocess
import tkinter as tk
import re

window = tk.Tk()
window.title("Suspicious URL Detector")
window.geometry("500x300")

label = tk.Label(window, text="Enter URL:")
label.pack(pady=10)

url_entry = tk.Entry(window, width=50)
url_entry.pack(pady=10)

def show_url():
    url = url_entry.get()

    if not url:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "Please enter a URL")
        return

    import subprocess

    try:
        result = subprocess.check_output(
            ["python3", "url_detector.py", url]
        ).decode()

        result = re.sub(r'\x1b\[[0-9;]*m', '', result)

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    except:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "Error running URL detector")

button = tk.Button(window, text="Analyze", command=show_url)
button.pack(pady=10)

output_text = tk.Text(window, height=20, width=60)
output_text.pack(pady=20)

window.mainloop()
