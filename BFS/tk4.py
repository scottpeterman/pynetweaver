import tkinter as tk
from tkinter import ttk
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
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Set scale factor
        self.scale = 0.5  # scale

        # Initialize network data
        self.graph = {}
        self.queue = deque()
        self.visited = set()
        self.current_node = None

        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights to control relative sizes
        self.main_container.grid_rowconfigure(0, weight=1)  # Input frame
        self.main_container.grid_rowconfigure(1, weight=2)  # Graph frame
        self.main_container.grid_rowconfigure(2, weight=0)  # Control frame
        self.main_container.grid_columnconfigure(0, weight=1)

        # Create the frames
        self.create_input_frame()
        self.create_graph_frame()
        self.create_control_frame()

        # Initialize the network graph
        self.G = nx.Graph()
        self.pos = None
        self.fig = Figure(figsize=(6, 6))  # Smaller figure size
        self.ax = self.fig.add_subplot(111)

        # Create canvas for matplotlib with scrolling container
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_scroll_frame)
        self.canvas.draw()
        canvas_widget = self.canvas.get_tk_widget()

        # Configure canvas scrolling
        canvas_widget.grid(row=0, column=0, sticky="nsew")

        # Bind scroll region after graph updates
        self.graph_scroll_frame.bind('<Configure>', self.update_scroll_region)

        # Initialize with sample topology
        self.initialize_spine_leaf()

    def create_input_frame(self):
        # Create frame for network topology input
        input_container = ttk.LabelFrame(self.main_container, text="Network Topology", padding="5")
        input_container.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        input_container.grid_columnconfigure(0, weight=1)
        input_container.grid_rowconfigure(0, weight=1)

        # Create table frame with scrollbars
        table_frame = ttk.Frame(input_container)
        table_frame.grid(row=0, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

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

    def create_graph_frame(self):
        # Create main graph container with fixed height
        self.graph_frame = ttk.LabelFrame(self.main_container, text="Network Diagram", padding="5")
        self.graph_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Create horizontal container for graph and lists
        self.horizontal_container = ttk.Frame(self.graph_frame)
        self.horizontal_container.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights for horizontal layout
        self.horizontal_container.grid_columnconfigure(0, weight=3)  # Graph gets more space
        self.horizontal_container.grid_columnconfigure(1, weight=1)  # Lists container gets less space

        # Create left side for graph
        self.graph_container = ttk.Frame(self.horizontal_container)
        self.graph_container.grid(row=0, column=0, sticky="nsew")

        # Create canvas with scrollbars for the graph
        self.graph_canvas = tk.Canvas(self.graph_container)
        self.graph_canvas.grid(row=0, column=0, sticky="nsew")

        # Add scrollbars for graph
        y_scrollbar = ttk.Scrollbar(self.graph_container, orient="vertical", command=self.graph_canvas.yview)
        x_scrollbar = ttk.Scrollbar(self.graph_container, orient="horizontal", command=self.graph_canvas.xview)

        # Configure scrollbars
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure canvas
        self.graph_canvas.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        # Create frame inside canvas
        self.graph_scroll_frame = ttk.Frame(self.graph_canvas)
        self.graph_canvas.create_window((0, 0), window=self.graph_scroll_frame, anchor="nw")

        # Create right side container for lists
        self.lists_container = ttk.Frame(self.horizontal_container)
        self.lists_container.grid(row=0, column=1, sticky="n", padx=5)  # Changed to sticky="n"

        # Configure lists container for horizontal layout
        self.lists_container.grid_columnconfigure(0, weight=1)
        self.lists_container.grid_columnconfigure(1, weight=1)

        # Create queue list (left side)
        queue_frame = ttk.LabelFrame(self.lists_container, text="Queue", padding="5")
        queue_frame.grid(row=0, column=0, sticky="n", padx=(0, 2))
        self.queue_listbox = tk.Listbox(queue_frame, height=10, width=15)
        self.queue_listbox.grid(row=0, column=0, sticky="nsew")
        queue_scrollbar = ttk.Scrollbar(queue_frame, orient="vertical", command=self.queue_listbox.yview)
        queue_scrollbar.grid(row=0, column=1, sticky="ns")
        self.queue_listbox.configure(yscrollcommand=queue_scrollbar.set)

        # Create visited list (right side)
        visited_frame = ttk.LabelFrame(self.lists_container, text="Visited", padding="5")
        visited_frame.grid(row=0, column=1, sticky="n", padx=(2, 0))
        self.visited_listbox = tk.Listbox(visited_frame, height=10, width=15)
        self.visited_listbox.grid(row=0, column=0, sticky="nsew")
        visited_scrollbar = ttk.Scrollbar(visited_frame, orient="vertical", command=self.visited_listbox.yview)
        visited_scrollbar.grid(row=0, column=1, sticky="ns")
        self.visited_listbox.configure(yscrollcommand=visited_scrollbar.set)

        # Configure graph frame grid
        self.graph_frame.grid_rowconfigure(0, weight=1)
        self.graph_frame.grid_columnconfigure(0, weight=1)
    def update_scroll_region(self, event=None):
        # Update the scroll region to encompass the inner frame
        self.graph_canvas.configure(scrollregion=self.graph_canvas.bbox("all"))

    def create_control_frame(self):
        self.control_frame = ttk.Frame(self.main_container, padding="5")
        self.control_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        ttk.Button(self.control_frame, text="Add Row", command=self.add_row).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Generate Graph", command=self.generate_graph).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Next Step", command=self.next_step).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Reset", command=self.reset).pack(side=tk.LEFT, padx=5)

    def add_row(self):
        self.tree.insert('', 'end', values=('', '', '', ''))

    def generate_graph(self):
        # Clear existing graph
        self.G.clear()
        self.graph = {}
        self.queue.clear()
        self.visited.clear()
        self.current_node = None

        # Parse connections from tree - create bidirectional connections
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

        spine_nodes = [n for n in self.G.nodes() if n.startswith('spine')]
        leaf_nodes = [n for n in self.G.nodes() if n.startswith('leaf')]
        host_nodes = [n for n in self.G.nodes() if n.startswith('host')]

        self.pos = {}

        # Position spine nodes at top
        for i, node in enumerate(spine_nodes):
            self.pos[node] = (i * 2 * self.scale, 2 * self.scale)

        # Position leaf nodes in middle
        for i, node in enumerate(leaf_nodes):
            self.pos[node] = (i * 2 * self.scale, 1 * self.scale)

        # Position host nodes at bottom
        for i, node in enumerate(host_nodes):
            leaf_idx = i // 2
            offset = -0.5 if i % 2 == 0 else 0.5
            self.pos[node] = ((leaf_idx * 2 + offset) * self.scale, 0 * self.scale)

        self.draw_graph()
        self.start_traversal()

    def draw_graph(self):
        self.ax.clear()

        # Draw edges with color based on traversal progress
        edges = self.G.edges()
        edge_colors = []
        edge_widths = []
        for edge in edges:
            # Edge is traversed if both endpoints are visited
            if edge[0] in self.visited and edge[1] in self.visited:
                edge_colors.append('#22c55e')  # Green for traversed edges
                edge_widths.append(3)
            else:
                edge_colors.append('gray')  # Gray for untraversed edges
                edge_widths.append(2)

        nx.draw_networkx_edges(self.G, self.pos, ax=self.ax,
                             edge_color=edge_colors,
                             width=edge_widths)

        # Draw nodes with appropriate colors
        node_colors = []
        for node in self.G.nodes():
            if node == self.current_node:
                color = 'yellow'  # Current node being processed
            elif node in self.visited:
                color = '#22c55e'  # Green for visited nodes
            elif node in self.queue:
                color = 'yellow'  # Yellow for nodes in queue
            else:
                color = '#e5e7eb'  # Light gray for undiscovered nodes
            node_colors.append(color)

        base_node_size = 1000
        nx.draw_networkx_nodes(self.G, self.pos,
                               ax=self.ax,
                               node_color=node_colors,
                               node_size=base_node_size * self.scale)

        base_font_size = 10
        nx.draw_networkx_labels(self.G, self.pos,
                                ax=self.ax,
                                font_size=base_font_size)

        # Add interface labels
        edge_labels = {}
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            node, interface, connected_to, _ = values
            if node and connected_to:  # Only add labels if both nodes exist
                edge_labels[(node, connected_to)] = interface

        nx.draw_networkx_edge_labels(self.G, self.pos,
                                     edge_labels=edge_labels,
                                     ax=self.ax,
                                     font_size=base_font_size * 0.8)

        # Set axis limits with padding
        padding = 0.1 * self.scale
        if self.pos:
            x_values, y_values = zip(*self.pos.values())
            x_min, x_max = min(x_values), max(x_values)
            y_min, y_max = min(y_values), max(y_values)
            self.ax.set_xlim(x_min - padding, x_max + padding)
            self.ax.set_ylim(y_min - padding, y_max + padding)

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
        if self.G.nodes:
            start_node = list(self.G.nodes())[0]
            self.queue.append(start_node)
            self.visited.add(start_node)  # Only mark start node as visited
            self.current_node = start_node
            self.update_lists()
            self.draw_graph()

    def next_step(self):
        if not self.queue:
            return

        # Get next node from queue and mark it as current
        node = self.queue.popleft()
        self.current_node = node

        # Now we mark the node as visited when we process it
        self.visited.add(node)

        # Add unvisited neighbors to queue only (don't mark as visited yet)
        neighbors = self.graph.get(node, [])
        for neighbor_data in neighbors:
            neighbor = neighbor_data['connected_node']
            if neighbor not in self.visited and neighbor not in self.queue:
                self.queue.append(neighbor)

        self.draw_graph()
        self.update_lists()

    def reset(self):
        self.queue.clear()
        self.visited.clear()
        self.current_node = None
        self.start_traversal()
        self.draw_graph()
        self.update_lists()

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
    root.geometry("1000x800")
    app = NetworkCrawlerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()