
import os
import threading
import queue
from datetime import datetime
from collections import Counter

import tkinter as tk
from tkinter import ttk, messagebox

from scapy.all import (
    sniff, get_if_list, IP, IPv6,
    TCP, UDP, ICMP, PcapWriter
)


class NetworkSnifferDashboard:

    def __init__(self, root):
        self.root = root
        self.root.title("CodeAlpha | Network Sniffer")
        self.root.geometry("1150x720")
        self.root.minsize(900, 550)
        self.root.configure(bg="#101827")

        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.capture_thread = None

        self.capturing = False
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.pcap_path = None

        os.makedirs("captures", exist_ok=True)

        self.setup_style()
        self.build_interface()
        self.refresh_interfaces()

        self.root.after(100, self.process_events)
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#172337",
            foreground="#e5e7eb",
            fieldbackground="#172337",
            rowheight=29,
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            background="#26364d",
            foreground="white",
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[("selected", "#2563eb")]
        )

    def build_interface(self):

        header = tk.Frame(self.root, bg="#101827")
        header.pack(fill="x", padx=22, pady=18)

        tk.Label(
            header,
            text="NETWORK SNIFFER",
            font=("Segoe UI", 24, "bold"),
            fg="#60a5fa",
            bg="#101827"
        ).pack(side="left")

        self.status = tk.Label(
            header,
            text="● IDLE",
            font=("Segoe UI", 11, "bold"),
            fg="#fbbf24",
            bg="#101827"
        )
        self.status.pack(side="right")

        controls = tk.LabelFrame(
            self.root,
            text=" CAPTURE CONTROLS ",
            bg="#172337",
            fg="white",
            padx=12,
            pady=12
        )
        controls.pack(fill="x", padx=22, pady=8)

        tk.Label(
            controls,
            text="Network Interface:",
            bg="#172337",
            fg="white"
        ).grid(row=0, column=0, padx=5, pady=8)

        self.interface_box = ttk.Combobox(
            controls,
            width=55,
            state="readonly"
        )
        self.interface_box.grid(
            row=0, column=1, padx=5, pady=8
        )

        tk.Button(
            controls,
            text="Refresh",
            command=self.refresh_interfaces
        ).grid(row=0, column=2, padx=5)

        tk.Label(
            controls,
            text="Packet Filter:",
            bg="#172337",
            fg="white"
        ).grid(row=1, column=0, padx=5, pady=8)

        self.filter_box = ttk.Combobox(
            controls,
            values=["ip or ip6", "tcp", "udp", "icmp"],
            width=20
        )
        self.filter_box.set("ip or ip6")
        self.filter_box.grid(
            row=1, column=1, sticky="w", padx=5
        )

        tk.Label(
            controls,
            text="Packet Limit (0 = unlimited):",
            bg="#172337",
            fg="white"
        ).grid(row=1, column=2, padx=5)

        self.limit_entry = tk.Entry(controls, width=10)
        self.limit_entry.insert(0, "50")
        self.limit_entry.grid(row=1, column=3, padx=5)

        buttons = tk.Frame(controls, bg="#172337")
        buttons.grid(
            row=2, column=0, columnspan=4, pady=12
        )

        self.start_button = tk.Button(
            buttons,
            text="▶ START CAPTURE",
            bg="#15803d",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            command=self.start_capture,
            padx=18,
            pady=8
        )
        self.start_button.pack(side="left", padx=7)

        self.stop_button = tk.Button(
            buttons,
            text="■ STOP CAPTURE",
            bg="#b91c1c",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            command=self.stop_capture,
            padx=18,
            pady=8,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=7)

        self.folder_button = tk.Button(
            buttons,
            text="OPEN CAPTURES FOLDER",
            command=self.open_captures,
            padx=14,
            pady=8
        )
        self.folder_button.pack(side="left", padx=7)

        stats = tk.Frame(self.root, bg="#101827")
        stats.pack(fill="x", padx=22, pady=12)

        self.packet_label = self.make_stat(
            stats, "PACKETS CAPTURED", "0"
        )

        self.bytes_label = self.make_stat(
            stats, "DATA CAPTURED", "0 B"
        )

        self.protocol_label = self.make_stat(
            stats, "TOP PROTOCOL", "-"
        )

        self.file_label = self.make_stat(
            stats, "PCAP STATUS", "Ready"
        )

        table_frame = tk.Frame(self.root, bg="#101827")
        table_frame.pack(
            fill="both",
            expand=True,
            padx=22,
            pady=10
        )

        tk.Label(
            table_frame,
            text="LIVE PACKET MONITOR",
            bg="#101827",
            fg="#60a5fa",
            font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=8)

        columns = (
            "number", "time", "source", "destination",
            "protocol", "source_port",
            "destination_port", "size"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "number": "No.",
            "time": "Time",
            "source": "Source IP",
            "destination": "Destination IP",
            "protocol": "Protocol",
            "source_port": "Source Port",
            "destination_port": "Destination Port",
            "size": "Size"
        }

        widths = {
            "number": 45,
            "time": 85,
            "source": 190,
            "destination": 190,
            "protocol": 80,
            "source_port": 90,
            "destination_port": 110,
            "size": 75
        }

        for column in columns:
            self.table.heading(
                column, text=headings[column]
            )
            self.table.column(
                column,
                width=widths[column],
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side="left", fill="both", expand=True
        )

        scrollbar.pack(side="right", fill="y")

        self.footer = tk.Label(
            self.root,
            text="Ready | Authorized network monitoring only",
            bg="#101827",
            fg="#94a3b8",
            anchor="w"
        )
        self.footer.pack(
            fill="x", padx=22, pady=10
        )

    def make_stat(self, parent, title, value):

        card = tk.Frame(
            parent,
            bg="#172337",
            padx=14,
            pady=12
        )
        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=title,
            bg="#172337",
            fg="#94a3b8",
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")

        label = tk.Label(
            card,
            text=value,
            bg="#172337",
            fg="#60a5fa",
            font=("Segoe UI", 17, "bold")
        )
        label.pack(anchor="w")

        return label

    def refresh_interfaces(self):

        interfaces = get_if_list()
        self.interface_box["values"] = interfaces

        if not interfaces:
            return

        self.interface_box.current(0)

        wifi = next(
            (
                interface for interface in interfaces
                if "CF8C18C9" in interface
            ),
            None
        )

        if wifi:
            self.interface_box.set(wifi)

    def start_capture(self):

        if self.capturing:
            return

        interface = self.interface_box.get()

        if not interface:
            messagebox.showerror(
                "Error",
                "Please select a network interface."
            )
            return

        try:
            limit = int(self.limit_entry.get())

            if limit < 0:
                raise ValueError

        except ValueError:
            messagebox.showerror(
                "Invalid input",
                "Enter a valid non-negative packet limit."
            )
            return

        packet_filter = (
            self.filter_box.get().strip() or "ip or ip6"
        )

        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_counts.clear()

        self.stop_event.clear()
        self.capturing = True

        for item in self.table.get_children():
            self.table.delete(item)

        filename = datetime.now().strftime(
            "capture_%Y%m%d_%H%M%S.pcap"
        )

        self.pcap_path = os.path.join(
            "captures", filename
        )

        self.packet_label.config(text="0")
        self.bytes_label.config(text="0 B")
        self.protocol_label.config(text="-")
        self.file_label.config(text="Writing...")

        self.status.config(
            text="● CAPTURING",
            fg="#4ade80"
        )

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.footer.config(
            text="Live packet capture in progress..."
        )

        self.capture_thread = threading.Thread(
            target=self.capture_worker,
            args=(
                interface,
                packet_filter,
                limit
            ),
            daemon=True
        )

        self.capture_thread.start()

    def capture_worker(
        self, interface, packet_filter, limit
    ):

        writer = None
        seen = 0

        try:
            writer = PcapWriter(
                self.pcap_path,
                append=False,
                sync=True
            )

            def handle_packet(packet):
                nonlocal seen

                seen += 1
                writer.write(packet)

                self.events.put(
                    ("packet", packet)
                )

            while not self.stop_event.is_set():

                remaining = (
                    limit - seen if limit else 0
                )

                if limit and remaining <= 0:
                    break

                sniff(
                    iface=interface,
                    filter=packet_filter,
                    prn=handle_packet,
                    count=remaining,
                    store=False,
                    timeout=1
                )

            self.events.put(
                ("finished", self.pcap_path)
            )

        except Exception as error:
            self.events.put(
                ("error", str(error))
            )

        finally:
            if writer is not None:
                writer.close()

    def stop_capture(self):

        if self.capturing:
            self.stop_event.set()

            self.status.config(
                text="● STOPPING",
                fg="#fbbf24"
            )

            self.footer.config(
                text="Stopping packet capture..."
            )

    def process_events(self):

        try:
            while True:

                event = self.events.get_nowait()
                kind = event[0]

                if kind == "packet":
                    self.display_packet(event[1])

                elif kind == "finished":
                    self.capture_finished(event[1])

                elif kind == "error":
                    self.capture_finished(None)

                    messagebox.showerror(
                        "Capture error",
                        event[1]
                    )

        except queue.Empty:
            pass

        self.root.after(
            100, self.process_events
        )

    def display_packet(self, packet):

        self.packet_count += 1
        self.total_bytes += len(packet)

        source = "Unknown"
        destination = "Unknown"

        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst

        elif IPv6 in packet:
            source = packet[IPv6].src
            destination = packet[IPv6].dst

        sport = "-"
        dport = "-"

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        elif IP in packet or IPv6 in packet:
            protocol = "OTHER IP"

        else:
            protocol = "OTHER"

        self.protocol_counts[protocol] += 1

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%H:%M:%S")

        self.table.insert(
            "",
            "end",
            values=(
                self.packet_count,
                timestamp,
                source,
                destination,
                protocol,
                sport,
                dport,
                f"{len(packet)} B"
            )
        )

        children = self.table.get_children()

        if children:
            self.table.see(children[-1])

        self.packet_label.config(
            text=str(self.packet_count)
        )

        self.bytes_label.config(
            text=f"{self.total_bytes:,} B"
        )

        self.protocol_label.config(
            text=self.protocol_counts.most_common(1)[0][0]
        )

    def capture_finished(self, path):

        self.capturing = False

        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

        self.status.config(
            text="● IDLE",
            fg="#fbbf24"
        )

        if path and os.path.exists(path):

            self.file_label.config(text="Saved")

            self.footer.config(
                text="PCAP saved: " +
                os.path.abspath(path)
            )

        else:
            self.file_label.config(text="Not saved")

            self.footer.config(
                text="Capture stopped or failed."
            )

    def open_captures(self):

        folder = os.path.abspath("captures")

        os.makedirs(folder, exist_ok=True)

        os.startfile(folder)

    def close_app(self):

        if self.capturing:
            self.stop_event.set()

            self.root.after(
                200, self.close_app
            )
            return

        self.root.destroy()


if __name__ == "__main__":

    root = tk.Tk()

    app = NetworkSnifferDashboard(root)

    root.mainloop()
