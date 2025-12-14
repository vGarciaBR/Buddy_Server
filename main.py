import asyncio
import logging
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from buddy_server.server import BuddyServer
from buddy_server.config import Config

class TextHandler(logging.Handler):
    """Log Handler that writes to a Tkinter ScrolledText widget"""
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GunBound Buddy Server - P2P HYBRID EDITION")
        self.root.geometry("1000x700")
        
        # Internal State
        self.server_instance = None
        self.server_thread = None
        self.loop = None
        self.stop_event = threading.Event()
        
        # Create all widgets
        self.create_widgets()
        
        # Setup logging AFTER widgets are created
        self.setup_logging()
        
        # Start Monitor Loop
        self.root.after(1000, self.update_status_loop)

    def create_widgets(self):
        # Styles
        style = ttk.Style()
        style.configure("Bold.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"))
        
        # =====================================================================
        # 1. CONFIGURATION FRAME
        # =====================================================================
        config_frame = ttk.LabelFrame(self.root, text="⚙️ Configuration", padding="10")
        config_frame.pack(fill="x", padx=10, pady=5)
        
        # Network Settings
        ttk.Label(config_frame, text="Server IP:", style="Bold.TLabel").grid(
            row=0, column=0, sticky="w", padx=5
        )
        self.entry_ip = ttk.Entry(config_frame, width=15)
        self.entry_ip.insert(0, Config.HOST)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Port:", style="Bold.TLabel").grid(
            row=0, column=2, sticky="w", padx=5
        )
        self.entry_port = ttk.Entry(config_frame, width=8)
        self.entry_port.insert(0, str(Config.PORT))
        self.entry_port.grid(row=0, column=3, padx=5, pady=2)

        # Database Settings
        ttk.Label(config_frame, text="DB Host:", style="Bold.TLabel").grid(
            row=1, column=0, sticky="w", padx=5
        )
        self.entry_db_host = ttk.Entry(config_frame, width=15)
        self.entry_db_host.insert(0, Config.DB_HOST)
        self.entry_db_host.grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(config_frame, text="DB Name:", style="Bold.TLabel").grid(
            row=1, column=2, sticky="w", padx=5
        )
        self.entry_db_name = ttk.Entry(config_frame, width=15)
        self.entry_db_name.insert(0, Config.DB_NAME)
        self.entry_db_name.grid(row=1, column=3, padx=5, pady=2)

        ttk.Label(config_frame, text="DB User:", style="Bold.TLabel").grid(
            row=1, column=4, sticky="w", padx=5
        )
        self.entry_db_user = ttk.Entry(config_frame, width=15)
        self.entry_db_user.insert(0, Config.DB_USER)
        self.entry_db_user.grid(row=1, column=5, padx=5, pady=2)

        ttk.Label(config_frame, text="DB Pass:", style="Bold.TLabel").grid(
            row=1, column=6, sticky="w", padx=5
        )
        self.entry_db_pass = ttk.Entry(config_frame, width=15, show="*")
        self.entry_db_pass.insert(0, Config.DB_PASS)
        self.entry_db_pass.grid(row=1, column=7, padx=5, pady=2)

        # =====================================================================
        # 2. CONTROL BUTTONS
        # =====================================================================
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill="x", padx=10)

        # Buttons
        self.btn_start = ttk.Button(
            control_frame, 
            text="🚀 START SERVER (P2P)", 
            command=self.start_server
        )
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(
            control_frame, 
            text="🛑 STOP SERVER", 
            command=self.stop_server, 
            state="disabled"
        )
        self.btn_stop.pack(side="left", padx=5)
        
        self.btn_stats = ttk.Button(
            control_frame,
            text="📊 SHOW STATS",
            command=self.show_stats
        )
        self.btn_stats.pack(side="left", padx=5)

        self.btn_clear = ttk.Button(
            control_frame, 
            text="🗑️ Clear Logs", 
            command=self.clear_logs
        )
        self.btn_clear.pack(side="right", padx=5)

        # =====================================================================
        # 3. LIVE MONITOR FRAME (ATUALIZADO COM P2P)
        # =====================================================================
        monitor_frame = ttk.LabelFrame(self.root, text="📡 Live Monitor (P2P Enabled)", padding=10)
        monitor_frame.pack(fill="x", padx=10, pady=5)
        
        # Status Grid - Initialize StringVars
        self.status_vars = {
            "Server State": tk.StringVar(value="OFFLINE"),
            "DB Connection": tk.StringVar(value="Disconnected"),
            "Center Link": tk.StringVar(value="Disconnected"),
            "Active Sockets": tk.StringVar(value="0"),
            "Logged Users": tk.StringVar(value="0"),
            "P2P Connections": tk.StringVar(value="0"),  # NOVO
            "P2P Success Rate": tk.StringVar(value="0%")  # NOVO
        }
        
        # Dictionary to store label references for color changes
        self.status_labels = {}
        
        row = 0
        col = 0
        for key, var in self.status_vars.items():
            # Label name
            ttk.Label(
                monitor_frame, 
                text=f"{key}:", 
                font=('Segoe UI', 9, 'bold')
            ).grid(row=row, column=col, sticky=tk.W, padx=5, pady=2)
            
            # Value label
            lbl = ttk.Label(monitor_frame, textvariable=var, foreground="gray")
            lbl.grid(row=row, column=col+1, sticky=tk.W, padx=5, pady=2)
            
            # Store reference
            self.status_labels[key] = lbl
            
            col += 2
            if col > 5:  # Aumentado de 3 para 5 (mais espaço para P2P)
                col = 0
                row += 1

        # =====================================================================
        # 4. LOGS FRAME
        # =====================================================================
        log_frame = ttk.LabelFrame(self.root, text="📋 Packet Logs & Debug", padding="5")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_area = scrolledtext.ScrolledText(
            log_frame, 
            state='disabled', 
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white"
        )
        self.log_area.pack(fill="both", expand=True)

    def setup_logging(self):
        """Setup logging to GUI"""
        text_handler = TextHandler(self.log_area)
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s', 
            datefmt='%H:%M:%S'
        )
        text_handler.setFormatter(formatter)
        
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.handlers = []  # Clear existing handlers
        logger.addHandler(text_handler)

    def clear_logs(self):
        """Clear log area"""
        self.log_area.configure(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.configure(state='disabled')

    def toggle_inputs(self, enable):
        """Enable/disable input fields"""
        state = "normal" if enable else "disabled"
        self.entry_ip.configure(state=state)
        self.entry_port.configure(state=state)
        self.entry_db_host.configure(state=state)
        self.entry_db_name.configure(state=state)
        self.entry_db_user.configure(state=state)
        self.entry_db_pass.configure(state=state)

    def start_server(self):
        """Start the server"""
        # Update Config from GUI
        try:
            Config.HOST = self.entry_ip.get()
            Config.PORT = int(self.entry_port.get())
            Config.DB_HOST = self.entry_db_host.get()
            Config.DB_NAME = self.entry_db_name.get()
            Config.DB_USER = self.entry_db_user.get()
            Config.DB_PASS = self.entry_db_pass.get()
            
            # Update DB_CONFIG dict
            Config.DB_CONFIG = {
                'user': Config.DB_USER,
                'password': Config.DB_PASS,
                'host': Config.DB_HOST,
                'database': Config.DB_NAME,
                'port': Config.DB_PORT
            }
        except ValueError:
            messagebox.showerror("Error", "Port must be an integer.")
            return

        # Update UI
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.toggle_inputs(False)
        self.status_vars["Server State"].set("STARTING...")
        self.status_labels["Server State"].configure(foreground="orange")
        
        # Start server in background thread
        self.server_thread = threading.Thread(target=self.run_async_server, daemon=True)
        self.server_thread.start()

    def stop_server(self):
        """Stop the server"""
        if self.loop and self.server_instance:
            # Schedule shutdown on the event loop
            self.loop.call_soon_threadsafe(self.shutdown_loop)
        self.btn_stop.configure(state="disabled")

    def run_async_server(self):
        """Run server in async event loop"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        # Fix: Pass Config explicitly because default args are evaluated at import time
        self.server_instance = BuddyServer(host=Config.HOST, port=Config.PORT)
        
        try:
            self.loop.run_until_complete(self.server_instance.start())
        except Exception as e:
            logging.error(f"Server Critical Failure: {e}")
            import traceback
            logging.error(traceback.format_exc())
        finally:
            self.loop.close()
            # Reset UI on stop
            self.root.after(0, self.on_server_stop)

    def shutdown_loop(self):
        """Shutdown the server gracefully"""
        if self.server_instance:
            asyncio.create_task(self.server_instance.stop())

    def on_server_stop(self):
        """Called when server stops - updates UI"""
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.toggle_inputs(True)
        
        self.status_vars["Server State"].set("OFFLINE")
        self.status_labels["Server State"].configure(foreground="red")
        
        self.status_vars["DB Connection"].set("Disconnected")
        self.status_labels["DB Connection"].configure(foreground="gray")
        
        self.status_vars["Center Link"].set("Disconnected")
        self.status_labels["Center Link"].configure(foreground="gray")
        
        self.status_vars["Active Sockets"].set("0")
        self.status_vars["Logged Users"].set("0")
        self.status_vars["P2P Connections"].set("0")
        self.status_vars["P2P Success Rate"].set("0%")
        
        self.server_instance = None

    def update_status_loop(self):
        """Update status indicators periodically"""
        if self.server_instance:
            # Server State
            if hasattr(self.server_instance, 'server') and self.server_instance.server:
                if self.server_instance.server.is_serving():
                    self.status_vars["Server State"].set("✅ RUNNING (P2P)")
                    self.status_labels["Server State"].configure(foreground="green")
                else:
                    self.status_vars["Server State"].set("⏳ STARTING...")
                    self.status_labels["Server State"].configure(foreground="orange")
            else:
                self.status_vars["Server State"].set("🔴 OFFLINE")
                self.status_labels["Server State"].configure(foreground="red")
            
            # Database State
            if hasattr(self.server_instance, 'db') and self.server_instance.db:
                if hasattr(self.server_instance.db, 'connection') and \
                   self.server_instance.db.connection and \
                   self.server_instance.db.connection.is_connected():
                    db_name = self.server_instance.db.db_config.get('database', 'Unknown')
                    self.status_vars["DB Connection"].set(f"✅ {db_name}")
                    self.status_labels["DB Connection"].configure(foreground="green")
                else:
                    self.status_vars["DB Connection"].set("❌ Disconnected")
                    self.status_labels["DB Connection"].configure(foreground="red")
            else:
                self.status_vars["DB Connection"].set("❌ Not Initialized")
                self.status_labels["DB Connection"].configure(foreground="red")
            
            # Center Link State
            if hasattr(self.server_instance, 'center_client') and self.server_instance.center_client:
                if self.server_instance.center_client.connected:
                    self.status_vars["Center Link"].set("✅ Linked")
                    self.status_labels["Center Link"].configure(foreground="green")
                else:
                    self.status_vars["Center Link"].set("⚠️ Standalone")
                    self.status_labels["Center Link"].configure(foreground="orange")
            else:
                self.status_vars["Center Link"].set("❌ Disabled")
                self.status_labels["Center Link"].configure(foreground="gray")

            # Metrics
            client_count = len(self.server_instance.clients) if hasattr(self.server_instance, 'clients') else 0
            user_count = len(self.server_instance.user_sessions) if hasattr(self.server_instance, 'user_sessions') else 0
            
            self.status_vars["Active Sockets"].set(f"🔌 {client_count}")
            self.status_vars["Logged Users"].set(f"👥 {user_count}")
            
            # ========== NOVO: P2P STATS ==========
            if hasattr(self.server_instance, 'p2p_manager'):
                p2p_stats = self.server_instance.p2p_manager.get_stats()
                active_p2p = p2p_stats.get('active_p2p_connections', 0)
                success_rate = p2p_stats.get('success_rate', '0%')
                
                self.status_vars["P2P Connections"].set(f"🔗 {active_p2p}")
                self.status_vars["P2P Success Rate"].set(f"📊 {success_rate}")
                
                # Cor baseada na taxa de sucesso
                try:
                    rate_num = float(success_rate.rstrip('%'))
                    if rate_num >= 70:
                        color = "green"
                    elif rate_num >= 40:
                        color = "orange"
                    else:
                        color = "red"
                    self.status_labels["P2P Success Rate"].configure(foreground=color)
                except:
                    self.status_labels["P2P Success Rate"].configure(foreground="gray")

        else:
            # Server is not running
            self.status_vars["Server State"].set("🔴 OFFLINE")
            self.status_labels["Server State"].configure(foreground="red")
            
            self.status_vars["DB Connection"].set("Disconnected")
            self.status_labels["DB Connection"].configure(foreground="gray")
            
            self.status_vars["Center Link"].set("Disconnected")
            self.status_labels["Center Link"].configure(foreground="gray")
            
            self.status_vars["Active Sockets"].set("0")
            self.status_vars["Logged Users"].set("0")
            self.status_vars["P2P Connections"].set("0")
            self.status_vars["P2P Success Rate"].set("0%")

        # Schedule next update
        self.root.after(1000, self.update_status_loop)

    def show_stats(self):
        """Show detailed statistics in popup"""
        if not self.server_instance:
            messagebox.showinfo("Stats", "Server is not running.")
            return
        
        try:
            stats = self.server_instance.get_server_stats()
            
            stats_text = "=" * 50 + "\n"
            stats_text += "📊 SERVER STATISTICS (P2P ENABLED)\n"
            stats_text += "=" * 50 + "\n\n"
            
            # Server Stats
            stats_text += "🖥️  SERVER\n"
            stats_text += f"  Online Users: {stats['server']['online_users']}\n"
            stats_text += f"  Connections: {stats['server']['total_connections']}\n\n"
            
            # ========== NOVO: P2P STATS ==========
            if 'p2p' in stats:
                stats_text += "🔗 P2P SYSTEM\n"
                stats_text += f"  Attempts: {stats['p2p']['p2p_attempts']}\n"
                stats_text += f"  Successful: {stats['p2p']['p2p_successful']}\n"
                stats_text += f"  Failed: {stats['p2p']['p2p_failed']}\n"
                stats_text += f"  Success Rate: {stats['p2p']['success_rate']}\n"
                stats_text += f"  Active P2P: {stats['p2p']['active_p2p_connections']}\n"
                stats_text += f"  Relay Mode: {stats['p2p']['relay_mode_connections']}\n\n"
            
            # Tunneling Stats
            if 'tunneling' in stats:
                stats_text += "📦 TUNNELING\n"
                stats_text += f"  Total: {stats['tunneling']['total_tunneled']}\n"
                stats_text += f"  Success: {stats['tunneling']['successful']}\n"
                stats_text += f"  Failed: {stats['tunneling']['failed']}\n"
                stats_text += f"  Offline: {stats['tunneling']['offline_saved']}\n"
                stats_text += f"  Rate: {stats['tunneling']['success_rate']}\n\n"
            
            # Invite Stats
            if 'invites' in stats:
                stats_text += "💌 INVITES\n"
                stats_text += f"  Sent: {stats['invites']['total_sent']}\n"
                stats_text += f"  Accepted: {stats['invites']['total_accepted']}\n"
                stats_text += f"  Rejected: {stats['invites']['total_rejected']}\n"
                stats_text += f"  Active: {stats['invites']['active_invites']}\n\n"
            
            # Status Stats
            if 'status' in stats:
                stats_text += "👤 USER STATUS\n"
                stats_text += f"  Online: {stats['status']['online_users']}\n"
                dist = stats['status'].get('status_distribution', {})
                for status_name, count in dist.items():
                    if count > 0:
                        stats_text += f"  {status_name}: {count}\n"
                stats_text += "\n"
            
            # Center Stats
            if 'center' in stats and stats['center']:
                stats_text += "🌐 CENTER\n"
                stats_text += f"  Connected: {stats['center'].get('connected', False)}\n"
                stats_text += f"  Registered: {stats['center'].get('registered', False)}\n"
                stats_text += f"  Messages Sent: {stats['center'].get('messages_sent', 0)}\n"
                stats_text += f"  Messages Recv: {stats['center'].get('messages_received', 0)}\n"
            
            # Create popup window
            popup = tk.Toplevel(self.root)
            popup.title("Server Statistics - P2P Edition")
            popup.geometry("500x650")
            
            text_widget = scrolledtext.ScrolledText(
                popup, 
                font=("Consolas", 10),
                bg="#1e1e1e",
                fg="#d4d4d4"
            )
            text_widget.pack(fill="both", expand=True, padx=10, pady=10)
            text_widget.insert(tk.END, stats_text)
            text_widget.configure(state='disabled')
            
            close_btn = ttk.Button(popup, text="Close", command=popup.destroy)
            close_btn.pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get stats: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()