
import threading
import queue
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options, http
import asyncio
import sys

class InterceptLogger:
    def __init__(self, log_queue):
        self.log_queue = log_queue

    def request(self, flow: http.HTTPFlow):
        msg = f"[Request] {flow.request.method} {flow.request.pretty_url}\nHeaders: {dict(flow.request.headers)}\n"
        if flow.request.content:
            msg += f"Body: {flow.request.get_text()}\n"
        msg += "-" * 40 + "\n"
        self.log_queue.put(msg)

    def response(self, flow: http.HTTPFlow):
        msg = f"[Response] {flow.request.method} {flow.request.pretty_url}\nStatus: {flow.response.status_code}\nHeaders: {dict(flow.response.headers)}\n"
        if flow.response.content:
            msg += f"Body: {flow.response.get_text()}\n"
        msg += "=" * 40 + "\n"
        self.log_queue.put(msg)


# Run mitmproxy in a background thread with its own event loop
import time
from tkinter import ttk, Canvas, messagebox, filedialog
from scapy.all import sniff, ARP, Ether, IP, ICMP
from collections import defaultdict
class ProxyThread(threading.Thread):
    def __init__(self, log_queue, port=8888):
        super().__init__()
        self.log_queue = log_queue
        self.port = port
        self.master = None
        self._should_stop = threading.Event()

    def run(self):
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.run_proxy())
        except Exception as e:
            self.log_queue.put(f"[Error] {e}\n")
        finally:
            self.log_queue.put("[Debug] Proxy thread exited.\n")

    async def run_proxy(self):
        opts = options.Options(listen_host="0.0.0.0", listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        addon = InterceptLogger(self.log_queue)
        self.master.addons.add(addon)
        try:
            self.log_queue.put(f"[Debug] mitmproxy listening on 0.0.0.0:{self.port}\n")
            await self.master.run()
        except Exception as e:
            self.log_queue.put(f"[Error] {e}\n")
        finally:
            await self.master.shutdown()

    def stop(self):
        if self.master:
            try:
                asyncio.run_coroutine_threadsafe(self.master.shutdown(), asyncio.get_event_loop())
            except Exception as e:
                self.log_queue.put(f"[Error] during shutdown: {e}\n")
        self._should_stop.set()



class SnifferThread(threading.Thread):
    def __init__(self, log_queue, device_queue):
        super().__init__()
        self.log_queue = log_queue
        self.device_queue = device_queue
        self.seen_devices = defaultdict(lambda: {'mac': None, 'last_seen': 0, 'ip': 'Unknown'})
        self.running = threading.Event()
        self.running.set()

    def packet_callback(self, pkt):
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        updated = False
        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            src_ip = pkt[IP].src if IP in pkt else None
            dst_ip = pkt[IP].dst if IP in pkt else None
            self.seen_devices[src_mac]['mac'] = src_mac
            self.seen_devices[src_mac]['last_seen'] = time.time()
            if src_ip:
                self.seen_devices[src_mac]['ip'] = src_ip
            msg = f"[{now}] MAC {src_mac} -> {dst_mac} | IP {src_ip} -> {dst_ip}\n"
            self.log_queue.put(msg)
            updated = True
        if ARP in pkt and pkt[ARP].op in (1, 2):
            src_mac = pkt[ARP].hwsrc
            src_ip = pkt[ARP].psrc
            dst_mac = pkt[ARP].hwdst
            dst_ip = pkt[ARP].pdst
            self.seen_devices[src_mac]['mac'] = src_mac
            self.seen_devices[src_mac]['ip'] = src_ip
            self.seen_devices[src_mac]['last_seen'] = time.time()
            msg = f"[{now}] ARP: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})\n"
            self.log_queue.put(msg)
            updated = True
        if ICMP in pkt:
            msg = f"[{now}] ICMP: {pkt[IP].src} -> {pkt[IP].dst}\n"
            self.log_queue.put(msg)
            updated = True
        if updated:
            self.device_queue.put(dict(self.seen_devices))

    def run(self):
        self.log_queue.put("[Info] Network sniffer started.\n")
        try:
            sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.running.is_set())
        except Exception as e:
            self.log_queue.put(f"[Error] {e}\n")
        self.log_queue.put("[Info] Network sniffer stopped.\n")

    def stop(self):
        self.running.clear()


# Restore MITMProxyGUI class header
class MITMProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MITM Proxy & Network Sniffer GUI (Educational)")
        self.log_queue = queue.Queue()
        self.proxy_thread = None
        self.sniffer_thread = None
        self.sniffer_log_queue = queue.Queue()
        self.device_queue = queue.Queue()
        self.devices = {}  # MAC -> info
        self.selected_devices = set()

        self.tab_control = ttk.Notebook(root)
        self.proxy_tab = tk.Frame(self.tab_control)
        self.sniffer_tab = tk.Frame(self.tab_control)
        self.tab_control.add(self.proxy_tab, text='MITM Proxy')
        self.tab_control.add(self.sniffer_tab, text='Network Sniffer')
        self.tab_control.pack(expand=1, fill='both')


        # Proxy tab
        self.device_filter_label = tk.Label(self.proxy_tab, text="Intercept traffic for:")
        self.device_filter_label.pack(anchor='w', padx=10, pady=(10,0))
        self.device_filter_var = tk.StringVar(value='All')
        self.device_filter_menu = ttk.Combobox(self.proxy_tab, textvariable=self.device_filter_var, state='readonly')
        self.device_filter_menu['values'] = ['All']
        self.device_filter_menu.current(0)
        self.device_filter_menu.pack(anchor='w', padx=10, pady=(0,10))

        self.text = ScrolledText(self.proxy_tab, state='disabled', width=100, height=30)
        self.text.pack(padx=10, pady=10)
        self.start_btn = tk.Button(self.proxy_tab, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=5)
        self.stop_btn = tk.Button(self.proxy_tab, text="Stop Proxy", command=self.stop_proxy, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=10, pady=5)

        # Sniffer tab
        self.sniffer_text = ScrolledText(self.sniffer_tab, state='disabled', width=100, height=10)
        self.sniffer_text.pack(padx=10, pady=5)
        self.sniffer_start_btn = tk.Button(self.sniffer_tab, text="Start Sniffer", command=self.start_sniffer)
        self.sniffer_start_btn.pack(side=tk.LEFT, padx=10, pady=5)
        self.sniffer_stop_btn = tk.Button(self.sniffer_tab, text="Stop Sniffer", command=self.stop_sniffer, state='disabled')
        self.sniffer_stop_btn.pack(side=tk.LEFT, padx=10, pady=5)


        # Device map canvas
        self.device_canvas = Canvas(self.sniffer_tab, width=800, height=300, bg='white')
        self.device_canvas.pack(padx=10, pady=10)
        self.device_canvas.bind('<Button-1>', self.on_device_click)
        self.device_canvas.create_text(400, 150, text="Devices will appear here as they are discovered", fill="gray", font=("Arial", 14), tags="empty")

        # Device action buttons
        self.device_action_frame = tk.Frame(self.sniffer_tab)
        self.device_action_frame.pack(padx=10, pady=5, fill='x')
        self.action_label = tk.Label(self.device_action_frame, text="Select a device to interact:")
        self.action_label.pack(side=tk.LEFT)
        self.msg_btn = tk.Button(self.device_action_frame, text="Send Message", command=self.send_message, state='disabled')
        self.msg_btn.pack(side=tk.LEFT, padx=5)
        self.file_btn = tk.Button(self.device_action_frame, text="Share File", command=self.share_file, state='disabled')
        self.file_btn.pack(side=tk.LEFT, padx=5)
        self.screen_btn = tk.Button(self.device_action_frame, text="Request Screen", command=self.request_screen, state='disabled')
        self.screen_btn.pack(side=tk.LEFT, padx=5)
        self.ping_btn = tk.Button(self.device_action_frame, text="Ping Device", command=self.ping_device, state='disabled')
        self.ping_btn.pack(side=tk.LEFT, padx=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.update_log()
        self.update_sniffer_log()
        self.update_device_map()

    def on_device_click(self, event):
        for mac, info in self.devices.items():
            x, y = info.get('pos', (0, 0))
            if abs(event.x - x) < 30 and abs(event.y - y) < 30:
                if mac in self.selected_devices:
                    self.selected_devices.remove(mac)
                else:
                    if len(self.selected_devices) < 2:
                        self.selected_devices.add(mac)
                    else:
                        messagebox.showinfo("Device Selection", "You can select up to 2 devices at a time.")
                        return
                self.update_device_map(redraw=True)
                self.update_device_actions()
                self.show_device_actions(mac)
                break

    def update_device_actions(self):
        if self.selected_devices:
            if len(self.selected_devices) == 1:
                self.msg_btn.config(state='normal')
                self.file_btn.config(state='normal')
                self.screen_btn.config(state='normal')
                self.ping_btn.config(state='normal')
            elif len(self.selected_devices) == 2:
                # Enable only MITM or relay actions for 2 devices
                self.msg_btn.config(state='disabled')
                self.file_btn.config(state='disabled')
                self.screen_btn.config(state='disabled')
                self.ping_btn.config(state='disabled')
                # You can add a button here for MITM/relay between two devices
        else:
            self.msg_btn.config(state='disabled')
            self.file_btn.config(state='disabled')
            self.screen_btn.config(state='disabled')
            self.ping_btn.config(state='disabled')

    def show_device_actions(self, mac):
        info = self.devices.get(mac, {})
        ip = info.get('ip', 'Unknown')
        msg = f"Selected device:\nMAC: {mac}\nIP: {ip}\n\nYou can now use the action buttons below."
        self.update_device_actions()
        messagebox.showinfo("Device Selected", msg)

    def send_message(self):
        if not self.selected_devices:
            return
        mac = next(iter(self.selected_devices))
        info = self.devices.get(mac, {})
        ip = info.get('ip', 'Unknown')
        # Custom dialog for message input
        msg = self.custom_message_dialog(f"Enter message to send to {ip} ({mac}):")
        if msg:
            try:
                import socket
                with socket.create_connection((ip, 5001), timeout=5) as s:
                    s.sendall(f"MSG:{msg}".encode())
                messagebox.showinfo("Send Message", f"Message sent to {ip} ({mac})!")
            except Exception as e:
                messagebox.showerror("Send Message", f"Failed to send message: {e}")

    def custom_message_dialog(self, prompt):
        dialog = tk.Toplevel(self.root)
        dialog.title("Send Message")
        tk.Label(dialog, text=prompt).pack(padx=10, pady=10)
        entry = tk.Entry(dialog, width=60)
        entry.pack(padx=10, pady=5)
        entry.focus_set()
        result = {'msg': None}
        def on_ok():
            result['msg'] = entry.get()
            dialog.destroy()
        tk.Button(dialog, text="Send", command=on_ok).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return result['msg']

    def share_file(self):
        if not self.selected_devices:
            return
        mac = next(iter(self.selected_devices))
        info = self.devices.get(mac, {})
        ip = info.get('ip', 'Unknown')
        file_path = filedialog.askopenfilename(title="Select file to send")
        if file_path:
            try:
                import socket, os
                with open(file_path, 'rb') as f:
                    data = f.read()
                filename = os.path.basename(file_path)
                with socket.create_connection((ip, 5001), timeout=5) as s:
                    s.sendall(f"FILE:{filename}:{len(data)}".encode() + b'\n')
                    s.sendall(data)
                messagebox.showinfo("Share File", f"File sent to {ip} ({mac})!")
            except Exception as e:
                messagebox.showerror("Share File", f"Failed to send file: {e}")

    def request_screen(self):
        if not self.selected_devices:
            return
        mac = next(iter(self.selected_devices))
        info = self.devices.get(mac, {})
        ip = info.get('ip', 'Unknown')
        try:
            import socket
            with socket.create_connection((ip, 5001), timeout=5) as s:
                s.sendall(b"SCREEN_REQUEST")
            messagebox.showinfo("Request Screen", f"Screen request sent to {ip} ({mac})!")
        except Exception as e:
            messagebox.showerror("Request Screen", f"Failed to request screen: {e}")

    def ping_device(self):
        if not self.selected_devices:
            return
        import subprocess
        mac = next(iter(self.selected_devices))
        info = self.devices.get(mac, {})
        ip = info.get('ip', None)
        if not ip or ip == 'Unknown':
            messagebox.showerror("Ping Device", "No IP address for selected device.")
            return
        try:
            output = subprocess.check_output(["ping", "-n", "2", ip], universal_newlines=True)
            messagebox.showinfo("Ping Result", output)
        except Exception as e:
            messagebox.showerror("Ping Device", f"Ping failed: {e}")

    def start_proxy(self):
        if not self.proxy_thread or not self.proxy_thread.is_alive():
            self.proxy_thread = ProxyThread(self.log_queue, port=8888)
            self.proxy_thread.start()
            time.sleep(1)
            if self.proxy_thread.is_alive():
                self.start_btn.config(state='disabled')
                self.stop_btn.config(state='normal')
                self.log_queue.put("[Info] Proxy started on port 8888. Configure your browser to use localhost:8888.\n")
            else:
                self.log_queue.put("[Error] Proxy thread failed to start. Check logs for details.\n")

    def start_sniffer(self):
        if not self.sniffer_thread or not self.sniffer_thread.is_alive():
            self.sniffer_thread = SnifferThread(self.sniffer_log_queue, self.device_queue)
            self.sniffer_thread.start()
            time.sleep(1)
            if self.sniffer_thread.is_alive():
                self.sniffer_start_btn.config(state='disabled')
                self.sniffer_stop_btn.config(state='normal')
                self.sniffer_log_queue.put("[Info] Sniffer started.\n")
            else:
                self.sniffer_log_queue.put("[Error] Sniffer thread failed to start.\n")

    def stop_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.stop()
            self.sniffer_thread.join()
            self.sniffer_start_btn.config(state='normal')
            self.sniffer_stop_btn.config(state='disabled')
            self.sniffer_log_queue.put("[Info] Sniffer stopped.\n")

    def stop_proxy(self):
        if self.proxy_thread and self.proxy_thread.is_alive():
            self.proxy_thread.stop()
            self.proxy_thread.join()
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.log_queue.put("[Info] Proxy stopped.\n")

    def update_log(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.text.config(state='normal')
            self.text.insert(tk.END, msg)
            self.text.see(tk.END)
            self.text.config(state='disabled')
        self.root.after(500, self.update_log)

    def update_sniffer_log(self):
        while not self.sniffer_log_queue.empty():
            msg = self.sniffer_log_queue.get()
            self.sniffer_text.config(state='normal')
            self.sniffer_text.insert(tk.END, msg)
            self.sniffer_text.see(tk.END)
            self.sniffer_text.config(state='disabled')
        self.root.after(500, self.update_sniffer_log)

    def update_device_map(self, redraw=False):
        updated = False
        while not self.device_queue.empty():
            devices = self.device_queue.get()
            self.devices = devices
            updated = True
        # Update device filter menu in proxy tab
        device_list = ['All'] + [f"{info.get('ip','Unknown')} ({mac[-5:]})" for mac, info in self.devices.items()]
        self.device_filter_menu['values'] = device_list
        if self.device_filter_var.get() not in device_list:
            self.device_filter_var.set('All')
        if updated or redraw:
            self.device_canvas.delete("all")
            if not self.devices:
                self.device_canvas.create_text(400, 150, text="Devices will appear here as they are discovered", fill="gray", font=("Arial", 14), tags="empty")
            else:
                # Arrange devices in a grid
                n = len(self.devices)
                cols = min(n, 8)
                rows = (n + cols - 1) // cols
                i = 0
                for mac, info in self.devices.items():
                    row = i // cols
                    col = i % cols
                    x = 80 + col * 90
                    y = 60 + row * 90
                    self.devices[mac]['pos'] = (x, y)
                    color = "#4caf50" if mac in self.selected_devices else "#2196f3"
                    self.device_canvas.create_oval(x-30, y-30, x+30, y+30, fill=color, outline="black", width=2)
                    self.device_canvas.create_text(x, y-35, text=f"{info.get('ip', 'Unknown')}", font=("Arial", 9))
                    self.device_canvas.create_text(x, y, text=mac[-5:], font=("Arial", 10, "bold"), fill="white")
                    self.device_canvas.create_text(x, y+35, text=time.strftime('%H:%M:%S', time.localtime(info['last_seen'])), font=("Arial", 8))
                    i += 1
        self.root.after(1000, self.update_device_map)

    def on_close(self):
        self.stop_proxy()
        self.stop_sniffer()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MITMProxyGUI(root)
    root.mainloop()
