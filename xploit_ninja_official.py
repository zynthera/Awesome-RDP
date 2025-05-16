import tkinter as tk
from tkinter import messagebox
import logging
import re
import sys
from typing import Optional
import random
import time
import hashlib

# Configure logging with anonymized data
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='xploit_ninja_official.log'
)

class XploitNinjaOfficial:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("XploitNinjaOfficial - Anonymized RDP & Proxy Simulation")
        self.root.configure(bg="#1a1a1a")  # Dark theme inspired by the hooded figure
        self.proxy_ip = self.generate_random_ip()  # Simulated proxy IP
        self.flag = "XploitNinja{rdp_4n0n_2025}"  # Flag for the challenge
        self.request_count = 0  # Track number of requests for rate limiting
        self.rate_limit = 5  # Max requests before cooldown
        self.cooldown_until = 0  # Timestamp for cooldown
        self.setup_gui()

    def generate_random_ip(self) -> str:
        """Generate a random IP address for simulation, avoiding reserved ranges"""
        while True:
            ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            if not ip.startswith("127.") and not ip.startswith("0."):
                return ip

    def validate_url(self, url: str) -> bool:
        """Validate URL format and check for malicious input"""
        url_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$'
        if not re.match(url_pattern, url):
            return False
        malicious_chars = ['<', '>', "'", '"', ';']
        if any(char in url for char in malicious_chars):
            messagebox.showerror("Input Error", "URL contains invalid characters", parent=self.root)
            return False
        return True

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip))

    def check_rate_limit(self) -> bool:
        """Check if the user has exceeded the request rate limit"""
        current_time = time.time()
        if current_time < self.cooldown_until:
            messagebox.showerror(
                "Rate Limit", 
                f"Too many requests! Wait {int(self.cooldown_until - current_time)} seconds or reset with code.", 
                parent=self.root
            )
            return False

        self.request_count += 1
        self.update_status_label()
        if self.request_count > self.rate_limit:
            self.cooldown_until = current_time + 30  # 30-second cooldown
            self.request_count = 0
            self.update_status_label()
            messagebox.showerror(
                "Rate Limit", 
                "Rate limit exceeded! Wait 30 seconds or reset with code (hint: ninja_reset_2025).", 
                parent=self.root
            )
            return False
        return True

    def reset_rate_limit(self):
        """Reset rate limit if the correct code is provided"""
        code = self.reset_code_entry.get().strip()
        if code == "ninja_reset_2025":
            self.request_count = 0
            self.cooldown_until = 0
            self.update_status_label()
            messagebox.showinfo("Success", "Rate limit reset successfully!", parent=self.root)
        else:
            messagebox.showerror("Error", "Invalid reset code. Hint: ninja_reset_2025", parent=self.root)

    def update_status_label(self):
        """Update the status label with rate limit info"""
        requests_left = max(0, self.rate_limit - self.request_count)
        for widget in self.root.winfo_children():
            if widget.winfo_name() == "status_label":
                if time.time() < self.cooldown_until:
                    remaining = int(self.cooldown_until - time.time())
                    widget.config(text=f"Status: On Cooldown ({remaining}s remaining)")
                else:
                    widget.config(text=f"Status: Requests Left: {requests_left}")
                break

    def simulate_proxy_request(self, url: str) -> Optional[str]:
        """Simulate a proxy request while hiding the user's IP"""
        if not self.validate_url(url):
            return None
        # Hash the URL for anonymized logging
        hashed_url = hashlib.sha256(url.encode()).hexdigest()
        logging.info(f"Proxy request to [hashed URL: {hashed_url}] routed through {self.proxy_ip}")
        result = (
            f"[SIMULATION] Proxy Request\n"
            f"Target URL: [HIDDEN]\n"
            f"Original IP: [HIDDEN]\n"
            f"Proxy IP: {self.proxy_ip}\n"
            f"Status: Request routed anonymously\n"
        )
        return result

    def check_encryption_key(self) -> bool:
        """Simulate checking an encryption key for RDP connection"""
        key = self.encryption_key_entry.get().strip()
        expected_key = "xploit_key_2025"
        if key != expected_key:
            messagebox.showerror("Error", "Invalid encryption key. Hint: xploit_key_2025", parent=self.root)
            return False
        return True

    def check_firewall(self, port: str) -> bool:
        """Simulate a firewall check for RDP connection"""
        expected_port = "3389"  # Default RDP port
        if port != expected_port:
            messagebox.showerror("Firewall", f"Firewall blocked connection on port {port}. Use port 3389.", parent=self.root)
            return False
        return True

    def simulate_rdp_connection(self):
        """Simulate a modern RDP connection over a secure tunnel, routed through the proxy"""
        try:
            if not self.check_rate_limit():
                return

            # Validate inputs
            target_ip = self.rdp_ip_entry.get().strip()
            port = self.port_entry.get().strip()
            if not self.validate_ip(target_ip):
                messagebox.showerror("Input Error", "Invalid target IP", parent=self.root)
                return
            if not port:
                messagebox.showerror("Input Error", "Port number required", parent=self.root)
                return

            # Check encryption key
            if not self.check_encryption_key():
                return

            # Check firewall
            if not self.check_firewall(port):
                return

            # Simulate proxy routing
            proxy_url = f"https://proxy.rdp/{target_ip}"
            proxy_result = self.simulate_proxy_request(proxy_url)
            if not proxy_result:
                return

            # Simulate RDP over a secure tunnel (e.g., SSH tunneling)
            hashed_ip = hashlib.sha256(target_ip.encode()).hexdigest()
            logging.info(f"Simulating RDP connection to [hashed IP: {hashed_ip}] via proxy {self.proxy_ip}")
            result = (
                f"[SIMULATION] Modern RDP Connection\n"
                f"Target IP: [HIDDEN]\n"
                f"Proxy IP: {self.proxy_ip}\n"
                f"Port: {port}\n"
                f"Secure Tunnel: Simulated SSH tunnel established\n"
                f"Status: Connected anonymously\n"
                f"Educational Note: Modern RDP uses encryption and secure tunnels.\n"
            )

            # Challenge: Flag appears if connecting to a specific IP
            if target_ip == "192.168.1.100":
                result += f"\n[Desktop File] flag.txt: {self.flag}"
            else:
                result += "\n[Desktop File] note.txt: Try connecting to the admin server at 192.168.1.100"

            messagebox.showinfo("RDP Connection", result, parent=self.root)
        except Exception as e:
            logging.error(f"RDP simulation failed: {str(e)}")
            messagebox.showerror("Error", f"Simulation failed: {str(e)}", parent=self.root)

    def copy_to_clipboard(self, text: str):
        """Simulate copying text to clipboard"""
        messagebox.showinfo("Clipboard", f"Simulated copy to clipboard:\n{text}", parent=self.root)

    def copy_flag(self):
        """Simulate copying the flag or hint to clipboard"""
        target_ip = self.rdp_ip_entry.get().strip()
        if target_ip == "192.168.1.100":
            self.copy_to_clipboard(self.flag)
        else:
            self.copy_to_clipboard("Hint: Try connecting to the admin server at 192.168.1.100")

    def reset_proxy(self):
        """Reset the proxy IP to simulate changing servers"""
        self.proxy_ip = self.generate_random_ip()
        for widget in self.root.winfo_children():
            if widget.winfo_name() == "proxy_ip_label":
                widget.config(text=f"Proxy IP: {self.proxy_ip}")
                break
        messagebox.showinfo("Proxy Reset", f"Proxy IP changed to {self.proxy_ip}", parent=self.root)

    def setup_gui(self):
        """Set up the GUI with a hacker-themed aesthetic"""
        # Title Label
        tk.Label(
            self.root, 
            text="XploitNinjaOfficial", 
            font=("Courier", 16, "bold"), 
            fg="#00ff00",  # Neon green for hacker vibe
            bg="#1a1a1a"
        ).pack(pady=10)

        # RDP Target IP Input
        tk.Label(
            self.root, 
            text="RDP Target IP:", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a"
        ).pack()
        self.rdp_ip_entry = tk.Entry(
            self.root, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            insertbackground="#00ff00",
            width=40
        )
        self.rdp_ip_entry.pack()

        # Port Input
        tk.Label(
            self.root, 
            text="Port Number:", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a"
        ).pack()
        self.port_entry = tk.Entry(
            self.root, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            insertbackground="#00ff00",
            width=40
        )
        self.port_entry.pack()

        # Encryption Key Input
        tk.Label(
            self.root, 
            text="Encryption Key:", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a"
        ).pack()
        self.encryption_key_entry = tk.Entry(
            self.root, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            insertbackground="#00ff00",
            width=40
        )
        self.encryption_key_entry.pack()

        # Proxy IP Display
        tk.Label(
            self.root, 
            text=f"Proxy IP: {self.proxy_ip}", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a",
            name="proxy_ip_label"
        ).pack(pady=5)

        # Status Label
        tk.Label(
            self.root, 
            text="Status: Requests Left: 5", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a",
            name="status_label"
        ).pack(pady=5)

        # Reset Code Input
        tk.Label(
            self.root, 
            text="Rate Limit Reset Code:", 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#1a1a1a"
        ).pack()
        self.reset_code_entry = tk.Entry(
            self.root, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            insertbackground="#00ff00",
            width=40
        )
        self.reset_code_entry.pack()

        # Buttons
        tk.Button(
            self.root, 
            text="Connect via RDP (Modern)", 
            command=self.simulate_rdp_connection, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            activebackground="#555555"
        ).pack(pady=5)

        tk.Button(
            self.root, 
            text="Reset Proxy IP", 
            command=self.reset_proxy, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            activebackground="#555555"
        ).pack(pady=5)

        tk.Button(
            self.root, 
            text="Reset Rate Limit", 
            command=self.reset_rate_limit, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            activebackground="#555555"
        ).pack(pady=5)

        tk.Button(
            self.root, 
            text="Copy Flag/Hint", 
            command=self.copy_flag, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            activebackground="#555555"
        ).pack(pady=5)

        tk.Button(
            self.root, 
            text="Learn About Secure RDP", 
            command=self.show_edu_info, 
            font=("Courier", 12), 
            fg="#00ff00", 
            bg="#333333", 
            activebackground="#555555"
        ).pack(pady=10)

    def show_edu_info(self):
        """Display educational information about secure RDP"""
        info = """
        XploitNinjaOfficial - Secure RDP Simulation
        ==========================================
        This tool simulates an anonymized RDP connection with proxy routing.

        Key Features:
        1. Secure Tunneling: Uses SSH tunnels for encryption
        2. Proxy Routing: Enhances anonymity
        3. Encryption Keys: Ensures secure access
        4. Firewall: Simulates network security checks
        5. Anonymized Logging: Protects user privacy

        Challenge Tip:
        - Find the correct IP to connect to (hint: 192.168.1.100)
        - Use the correct encryption key (hint: xploit_key_2025)
        - Use the correct port (hint: 3389)

        Security Notes:
        - Always use secure protocols for remote access
        - Protect your encryption keys
        - This is a simulation for educational purposes only

        Can you uncover the hidden flag?
        """
        messagebox.showinfo("Educational Information", info, parent=self.root)

    def run(self):
        """Run the application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logging.info("Application terminated by user")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Application error: {str(e)}")
            messagebox.showerror("Error", "Application encountered an error", parent=self.root)

if __name__ == '__main__':
    app = XploitNinjaOfficial()
    app.run()