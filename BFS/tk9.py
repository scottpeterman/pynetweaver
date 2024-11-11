import csv
import math
import tkinter as tk
import traceback
from tkinter import ttk, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import networkx as nx
from collections import deque


class NetworkCrawlerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Crawler")

        # Configure root grid to expand
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Set scale factor
        self.scale = 1

        # Initialize network data
        self.graph = {}
        self.queue = deque()
        self.visited = set()
        self.current_node = None

        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.grid(row=0, column=0, sticky="nsew")

        # Configure main container grid
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=2)  # Graph gets more space
        self.main_container.grid_columnconfigure(1, weight=1)  # Right side gets less space

        # Create left side for graph
        self.create_graph_frame()

        # Create right side container
        self.right_container = ttk.Frame(self.main_container)
        self.right_container.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Configure right container grid
        self.right_container.grid_rowconfigure(0, weight=0)  # Topology table
        self.right_container.grid_rowconfigure(1, weight=0)  # Lists
        self.right_container.grid_rowconfigure(2, weight=0)  # Buttons
        self.right_container.grid_columnconfigure(0, weight=1)

        # Create the frames on right side
        self.create_input_frame()
        self.create_lists_frame()
        self.create_control_frame()

        # Initialize the network graph
        self.G = nx.Graph()
        self.pos = None
        self.fig = Figure(figsize=(8, 8))  # Larger figure size
        self.ax = self.fig.add_subplot(111)

        # Create canvas for matplotlib
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_scroll_frame)
        self.canvas.draw()
        canvas_widget = self.canvas.get_tk_widget()
        canvas_widget.grid(row=0, column=0, sticky="nsew")

        # Initialize with sample topology
        self.initialize_spine_leaf()

    def create_graph_frame(self):
        # Create main graph container
        self.graph_frame = ttk.LabelFrame(self.main_container, text="Network Diagram", padding="5")
        self.graph_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Configure graph frame grid
        self.graph_frame.grid_rowconfigure(0, weight=1)
        self.graph_frame.grid_columnconfigure(0, weight=1)

        # Create canvas with scrollbars for the graph
        self.graph_canvas = tk.Canvas(self.graph_frame)
        self.graph_canvas.grid(row=0, column=0, sticky="nsew")

        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(self.graph_frame, orient="vertical", command=self.graph_canvas.yview)
        x_scrollbar = ttk.Scrollbar(self.graph_frame, orient="horizontal", command=self.graph_canvas.xview)

        # Configure scrollbars
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure canvas
        self.graph_canvas.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        # Create frame inside canvas
        self.graph_scroll_frame = ttk.Frame(self.graph_canvas)
        self.graph_canvas.create_window((0, 0), window=self.graph_scroll_frame, anchor="nw")

        # Bind resize event
        self.graph_frame.bind("<Configure>", self.on_frame_configure)

    def on_frame_configure(self, event=None):
        # Update figure size based on frame size
        width = self.graph_frame.winfo_width() / 100  # Convert to inches (assuming 100 DPI)
        height = self.graph_frame.winfo_height() / 100

        # Maintain aspect ratio
        if width > height:
            width = height
        else:
            height = width

        # Update figure size
        self.fig.set_size_inches(width, height)
        self.draw_graph()

    def create_input_frame(self):
        # Create frame for network topology input
        input_container = ttk.LabelFrame(self.right_container, text="Network Topology", padding="5")
        input_container.grid(row=0, column=0, sticky="nsew", pady=(0, 5))

        # Create table frame with scrollbars
        table_frame = ttk.Frame(input_container)
        table_frame.grid(row=0, column=0, sticky="nsew")

        # Create table for connections
        columns = ('Node', 'Interface', 'Connected To', 'Remote Interface')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=6)

        # Set column headings and widths
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)

        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)

        # Configure tree view
        self.tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        # Grid all elements
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

    def create_lists_frame(self):
        # Create container for both lists
        lists_frame = ttk.Frame(self.right_container)
        lists_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 5))

        # Configure grid for side-by-side lists
        lists_frame.grid_columnconfigure(0, weight=1)
        lists_frame.grid_columnconfigure(1, weight=1)

        # Create queue list
        queue_frame = ttk.LabelFrame(lists_frame, text="Queue", padding="5")
        queue_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        self.queue_listbox = tk.Listbox(queue_frame, height=10, width=15)
        self.queue_listbox.grid(row=0, column=0, sticky="nsew")
        queue_scrollbar = ttk.Scrollbar(queue_frame, orient="vertical", command=self.queue_listbox.yview)
        queue_scrollbar.grid(row=0, column=1, sticky="ns")
        self.queue_listbox.configure(yscrollcommand=queue_scrollbar.set)

        # Create visited list
        visited_frame = ttk.LabelFrame(lists_frame, text="Visited", padding="5")
        visited_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 0))
        self.visited_listbox = tk.Listbox(visited_frame, height=10, width=15)
        self.visited_listbox.grid(row=0, column=0, sticky="nsew")
        visited_scrollbar = ttk.Scrollbar(visited_frame, orient="vertical", command=self.visited_listbox.yview)
        visited_scrollbar.grid(row=0, column=1, sticky="ns")
        self.visited_listbox.configure(yscrollcommand=visited_scrollbar.set)

    def create_control_frame(self):
        # Create frame for buttons and selectors
        self.control_frame = ttk.Frame(self.right_container, padding="5")
        self.control_frame.grid(row=2, column=0, sticky="nsew")

        # Create selectors frame
        selectors_frame = ttk.Frame(self.control_frame)
        selectors_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))

        # Add layout selector
        ttk.Label(selectors_frame, text="Layout:").pack(side=tk.LEFT, padx=5)
        self.layout_var = tk.StringVar(value="Hierarchical")
        self.layout_combo = ttk.Combobox(selectors_frame,
                                         textvariable=self.layout_var,
                                         values=["Hierarchical", "Spring", "Circular", "Shell", "Kamada-Kawai"],
                                         state="readonly",
                                         width=15)
        self.layout_combo.pack(side=tk.LEFT, padx=5)
        self.layout_combo.bind('<<ComboboxSelected>>', self.on_layout_change)

        # Add start node selector
        ttk.Label(selectors_frame, text="Start Node:").pack(side=tk.LEFT, padx=5)
        self.start_node_var = tk.StringVar()
        self.start_node_combo = ttk.Combobox(selectors_frame,
                                             textvariable=self.start_node_var,
                                             state="readonly",
                                             width=15)
        self.start_node_combo.pack(side=tk.LEFT, padx=5)

        # Button frame
        button_frame = ttk.Frame(self.control_frame)
        button_frame.pack(side=tk.TOP, fill=tk.X)

        # Add buttons
        ttk.Button(button_frame, text="Import CSV", command=self.import_csv).pack(side=tk.LEFT, padx=5, expand=True)
        ttk.Button(button_frame, text="Generate Graph", command=self.generate_graph).pack(side=tk.LEFT, padx=5,
                                                                                          expand=True)
        ttk.Button(button_frame, text="Next Step", command=self.next_step).pack(side=tk.LEFT, padx=5, expand=True)
        ttk.Button(button_frame, text="Reset", command=self.reset).pack(side=tk.LEFT, padx=5, expand=True)

    def update_start_node_options(self):
        # Get all available nodes
        nodes = sorted(list(self.G.nodes()))
        self.start_node_combo['values'] = nodes

        # Set default to first node if not already set
        if not self.start_node_var.get() or self.start_node_var.get() not in nodes:
            self.start_node_var.set(nodes[0] if nodes else '')

    def on_layout_change(self, event=None):
        if hasattr(self, 'G') and self.G:
            self.generate_graph()

    def get_layout_positions(self):
        layout_name = self.layout_var.get()

        if layout_name == "Hierarchical":
            # Our custom hierarchical layout
            edge_nodes = [n for n in self.G.nodes() if 'edge' in n.lower()]
            spine_nodes = [n for n in self.G.nodes() if 'spine' in n.lower() and 'edge' not in n.lower()]
            leaf_nodes = [n for n in self.G.nodes() if 'leaf' in n.lower()]
            host_nodes = [n for n in self.G.nodes() if 'host' in n.lower()]
            other_nodes = [n for n in self.G.nodes() if n not in edge_nodes + spine_nodes + leaf_nodes + host_nodes]

            max_width = max(len(edge_nodes), len(spine_nodes), len(leaf_nodes), len(host_nodes), len(other_nodes))
            scale = 2.0 / max_width if max_width > 0 else 1.0
            pos = {}

            def position_nodes(nodes, level):
                width = len(nodes)
                if width == 0:
                    return
                spacing = 2.0 / (width + 1)
                for i, node in enumerate(sorted(nodes)):
                    x = (i + 1) * spacing - 1.0
                    pos[node] = (x * scale, level * scale)

            position_nodes(edge_nodes, 3.0)
            position_nodes(spine_nodes, 2.0)
            position_nodes(leaf_nodes, 1.0)
            position_nodes(host_nodes, 0.0)
            if other_nodes:
                position_nodes(other_nodes, -1.0)

            return pos

        elif layout_name == "Spring":
            return nx.spring_layout(self.G, k=2 / math.sqrt(self.G.number_of_nodes()))
        elif layout_name == "Circular":
            return nx.circular_layout(self.G)
        elif layout_name == "Shell":
            # Group nodes by type for shell layout
            shells = []
            for prefix in ['edge', 'spine', 'leaf', 'host']:
                shell = [n for n in self.G.nodes() if prefix in n.lower()]
                if shell:
                    shells.append(shell)
            return nx.shell_layout(self.G, shells) if shells else nx.shell_layout(self.G)
        elif layout_name == "Kamada-Kawai":
            return nx.kamada_kawai_layout(self.G)

        # Default to spring layout if something goes wrong
        return nx.spring_layout(self.G)

    def import_csv(self):
        # Open file dialog for CSV selection
        filename = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv")]
        )

        if not filename:
            return

        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Read CSV file
            with open(filename, 'r') as file:
                csv_reader = csv.reader(file)
                next(csv_reader)  # Skip header row if present
                for row in csv_reader:
                    if len(row) == 4:  # Ensure row has all required fields
                        self.tree.insert('', 'end', values=row)

            # Generate new graph
            self.generate_graph()

        except Exception as e:
            print(traceback.print_exc())
            tk.messagebox.showerror("Error", f"Failed to import CSV: {str(e)}")

    def add_row(self):
        self.tree.insert('', 'end', values=('', '', '', ''))

    def generate_graph(self):
        # Clear existing graph
        self.G.clear()
        self.graph = {}
        self.queue.clear()
        self.visited.clear()
        self.current_node = None

        # Parse connections from tree
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            node, interface, connected_to, remote_interface = values

            if node and connected_to:
                # Add forward connection
                if node not in self.graph:
                    self.graph[node] = []
                self.graph[node].append({
                    'interface': interface,
                    'connected_node': connected_to,
                    'remote_interface': remote_interface
                })

                # Add reverse connection
                if connected_to not in self.graph:
                    self.graph[connected_to] = []
                self.graph[connected_to].append({
                    'interface': remote_interface,
                    'connected_node': node,
                    'remote_interface': interface
                })

                self.G.add_edge(node, connected_to)

        # Get positions based on selected layout
        if not self.G.nodes():
            return  # Exit if graph is empty

        layout_name = self.layout_var.get()

        if layout_name == "Hierarchical":
            # Identify node types
            edge_nodes = [n for n in self.G.nodes() if 'edge' in n.lower()]
            spine_nodes = [n for n in self.G.nodes() if 'spine' in n.lower() and 'edge' not in n.lower()]
            leaf_nodes = [n for n in self.G.nodes() if 'leaf' in n.lower()]
            host_nodes = [n for n in self.G.nodes() if 'host' in n.lower()]
            other_nodes = [n for n in self.G.nodes() if n not in edge_nodes + spine_nodes + leaf_nodes + host_nodes]

            # Calculate scaling based on maximum layer width
            max_width = max(len(edge_nodes), len(spine_nodes), len(leaf_nodes), len(host_nodes), len(other_nodes))
            scale = 2.0 / max_width if max_width > 0 else 1.0

            self.pos = {}

            def position_nodes(nodes, level):
                width = len(nodes)
                if width == 0:
                    return
                spacing = 2.0 / (width + 1)
                for i, node in enumerate(sorted(nodes)):
                    x = (i + 1) * spacing - 1.0
                    self.pos[node] = (x * scale, level * scale)

            # Position each layer
            position_nodes(edge_nodes, 3.0)  # Top layer (edge)
            position_nodes(spine_nodes, 2.0)  # Second layer (spine)
            position_nodes(leaf_nodes, 1.0)  # Third layer (leaf)
            position_nodes(host_nodes, 0.0)  # Bottom layer (host)
            if other_nodes:
                position_nodes(other_nodes, -1.0)  # Extra layer for unclassified nodes

        elif layout_name == "Spring":
            self.pos = nx.spring_layout(self.G, k=2 / math.sqrt(self.G.number_of_nodes()))
        elif layout_name == "Circular":
            self.pos = nx.circular_layout(self.G)
        elif layout_name == "Shell":
            # Group nodes by type for shell layout
            shells = []
            for prefix in ['edge', 'spine', 'leaf', 'host']:
                shell = [n for n in self.G.nodes() if prefix in n.lower()]
                if shell:
                    shells.append(shell)
            self.pos = nx.shell_layout(self.G, shells) if shells else nx.shell_layout(self.G)
        elif layout_name == "Kamada-Kawai":
            self.pos = nx.kamada_kawai_layout(self.G)
        else:
            # Default to spring layout if something goes wrong
            self.pos = nx.spring_layout(self.G)

        # Update start node options
        self.update_start_node_options()

        # Draw the graph
        self.draw_graph()
        # Don't automatically start traversal - let user pick start node
        self.update_lists()

    def draw_graph(self):
        self.ax.clear()

        # Set axis to be equal and remove borders
        self.ax.set_aspect('equal')
        self.ax.axis('off')

        # Draw edges
        edges = self.G.edges()
        edge_colors = []
        edge_widths = []
        for edge in edges:
            if edge[0] in self.visited and edge[1] in self.visited:
                edge_colors.append('#22c55e')  # Green for traversed edges
                edge_widths.append(3)
            else:
                edge_colors.append('gray')  # Gray for untraversed edges
                edge_widths.append(2)

        nx.draw_networkx_edges(self.G, self.pos, ax=self.ax,
                               edge_color=edge_colors,
                               width=edge_widths)

        # Draw nodes
        node_colors = []
        for node in self.G.nodes():
            if node in self.visited:
                color = '#22c55e'  # Visited nodes are green
            elif node in self.queue:
                color = 'yellow'  # Queued nodes are yellow
            else:
                color = '#e5e7eb'  # Undiscovered nodes are light gray
            node_colors.append(color)

        # Calculate node size based on figure size
        fig_width = self.fig.get_size_inches()[0]
        base_node_size = 1000 * (fig_width / 8)

        nx.draw_networkx_nodes(self.G, self.pos,
                               ax=self.ax,
                               node_color=node_colors,
                               node_size=base_node_size,
                               node_shape='s')  # Changed to square shape

        # Add labels with adjusted font size
        base_font_size = 10 * (fig_width / 8)
        nx.draw_networkx_labels(self.G, self.pos,
                                ax=self.ax,
                                font_size=base_font_size)

        # Add interface labels
        edge_labels = {}
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            node, interface, connected_to, _ = values
            if node and connected_to:
                edge_labels[(node, connected_to)] = interface

        nx.draw_networkx_edge_labels(self.G, self.pos,
                                     edge_labels=edge_labels,
                                     ax=self.ax,
                                     font_size=base_font_size * 0.8)

        self.canvas.draw()
        self.update_scroll_region()
    def update_lists(self):
        # Update queue list
        self.queue_listbox.delete(0, tk.END)
        for node in self.queue:
            self.queue_listbox.insert(tk.END, node)

        # Update visited list
        self.visited_listbox.delete(0, tk.END)
        for node in self.visited:
            self.visited_listbox.insert(tk.END, node)

    def start_traversal(self):
        if not self.G.nodes:
            return

        # Get selected start node or use first node as fallback
        start_node = self.start_node_var.get()
        if not start_node or start_node not in self.G.nodes():
            start_node = list(self.G.nodes())[0]
            self.start_node_var.set(start_node)

        # Clear previous state
        self.queue.clear()
        self.visited.clear()
        self.current_node = None

        # Initialize with start node
        self.queue.append(start_node)

        # Update UI
        self.update_lists()
        self.draw_graph()
    def next_step(self):
        # Check if we need to start the traversal
        if not self.queue and not self.visited:
            self.start_traversal()
            return

        # If we've completed traversal, do nothing
        if not self.queue:
            return

        # Get next node from queue
        node = self.queue.popleft()
        self.current_node = node

        # Mark the node as visited
        self.visited.add(node)

        # Add unvisited neighbors to queue
        neighbors = self.graph.get(node, [])
        for neighbor_data in neighbors:
            neighbor = neighbor_data['connected_node']
            if neighbor not in self.visited and neighbor not in self.queue:
                self.queue.append(neighbor)

        # Draw updated state
        self.draw_graph()
        self.update_lists()

    def reset(self):
        self.queue.clear()
        self.visited.clear()
        self.current_node = None
        self.start_traversal()  # This will use the currently selected start node
        self.draw_graph()
        self.update_lists()
    def update_scroll_region(self, event=None):
        # Update the scroll region to encompass the inner frame
        self.graph_canvas.configure(scrollregion=self.graph_canvas.bbox("all"))

    def initialize_spine_leaf(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Define spine-leaf topology
        connections = [
            ('spine1', 'eth1/1', 'leaf1', 'eth1/1'),
            ('spine1', 'eth1/2', 'leaf2', 'eth1/1'),
            ('spine1', 'eth1/3', 'leaf3', 'eth1/1'),
            ('spine2', 'eth1/1', 'leaf1', 'eth1/2'),
            ('spine2', 'eth1/2', 'leaf2', 'eth1/2'),
            ('spine2', 'eth1/3', 'leaf3', 'eth1/2'),
            ('leaf1', 'eth1/3', 'host1', 'eth1'),
            ('leaf1', 'eth1/4', 'host2', 'eth1'),
            ('leaf2', 'eth1/3', 'host3', 'eth1'),
            ('leaf2', 'eth1/4', 'host4', 'eth1'),
            ('leaf3', 'eth1/3', 'host5', 'eth1'),
            ('leaf3', 'eth1/4', 'host6', 'eth1')
        ]

        for conn in connections:
            self.tree.insert('', 'end', values=conn)

        # Generate the graph immediately
        self.generate_graph()


def main():
    root = tk.Tk()
    root.geometry("1200x800")  # Increased default window size
    app = NetworkCrawlerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()