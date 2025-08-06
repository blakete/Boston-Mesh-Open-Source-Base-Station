Python 3.13.5 (tags/v3.13.5:6cb20a2, Jun 11 2025, 16:15:46) [MSC v.1943 64 bit (AMD64)] on win32
Enter "help" below or click "Help" above for more information.
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Rectangle
import networkx as nx
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Set, Optional
import random
from collections import defaultdict, deque
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MessageState(Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXPIRED = "expired"

@dataclass
class Person:
    id: int
    x: float
    y: float
    vx: float = 0.0
    vy: float = 0.0
    is_stage_focused: bool = False
    has_bitchat: bool = True
    battery: float = 100.0
    messages_routed: int = 0
    
    def update_position(self, dt: float, bounds: Tuple[float, float]) -> None:
        self.x = np.clip(self.x + self.vx * dt, 0, bounds[0])
        self.y = np.clip(self.y + self.vy * dt, 0, bounds[1])

@dataclass
class Message:
    id: int
    src: int
    dst: int
    created_time: float
    ttl: int
    state: MessageState = MessageState.PENDING
    path: List[int] = field(default_factory=list)
    attempts: int = 0
    delivered_time: Optional[float] = None

@dataclass
class SimParams:
    area_width: float = 200
    area_height: float = 150
    stage_x: float = 100
    stage_y: float = 10
    stage_width: float = 40
    stage_height: float = 10
    
    num_people: int = 500
    bitchat_adoption: float = 0.3
    stage_focus_ratio: float = 0.7
    
    base_speed: float = 0.5
    min_speed: float = 0.05
    stage_attraction: float = 0.7
    direction_change_prob: float = 0.1
    personal_space: float = 1.0
    
    ble_base_range: float = 30.0
    ble_min_range: float = 5.0
    body_attenuation_db: float = 3.0
    base_packet_loss: float = 0.05
    interference_factor: float = 0.15
    
    battery_idle_drain: float = 3.0
    battery_scan_drain: float = 8.0
    battery_routing_cost: float = 0.01
    
    message_ttl: int = 7
    message_rate: float = 0.02
    message_timeout: float = 10.0
    max_message_attempts: int = 3
    
    density_grid_size: float = 10.0
    network_update_interval: float = 1.0

class OptimizedFestivalMeshSim:
    def __init__(self, params: SimParams):
        self.params = params
        self.people: List[Person] = []
        self.time: float = 0.0
        self.dt: float = 0.1
        
        self.messages: Dict[int, Message] = {}
        self.message_id_counter: int = 0
        
        self.network: Optional[nx.Graph] = None
        self.last_network_update: float = 0.0
        self.density_grid: Optional[np.ndarray] = None
        self.grid_update_time: float = 0.0
        
        self.metrics = {
            'delivery_rates': deque(maxlen=1000),
            'latencies': deque(maxlen=1000),
            'hop_counts': deque(maxlen=1000),
            'network_connected': deque(maxlen=1000),
            'battery_levels': deque(maxlen=1000),
            'active_nodes': deque(maxlen=1000)
        }
        
        self.spatial_index = defaultdict(list)
        self.grid_resolution = 10
        
        self._init_people()
        self._update_spatial_index()
    
    def _init_people(self) -> None:
        for i in range(self.params.num_people):
            near_stage = random.random() < 0.6
            
            if near_stage:
                x = np.random.normal(self.params.stage_x, 25)
                y = np.random.normal(self.params.stage_y + 25, 12)
            else:
                x = np.random.uniform(10, self.params.area_width - 10)
                y = np.random.uniform(30, self.params.area_height - 10)
            
            x = np.clip(x, 0, self.params.area_width)
            y = np.clip(y, 0, self.params.area_height)
            
            person = Person(
                id=i,
                x=x,
                y=y,
                has_bitchat=random.random() < self.params.bitchat_adoption,
                is_stage_focused=random.random() < self.params.stage_focus_ratio
            )
            self.people.append(person)
    
    def _update_spatial_index(self) -> None:
        self.spatial_index.clear()
        for person in self.people:
            if person.has_bitchat and person.battery > 0:
                cell_x = int(person.x / self.grid_resolution)
                cell_y = int(person.y / self.grid_resolution)
                self.spatial_index[(cell_x, cell_y)].append(person)
    
    def _get_nearby_people(self, person: Person, radius: float) -> List[Person]:
        nearby = []
        cell_radius = int(np.ceil(radius / self.grid_resolution))
        center_x = int(person.x / self.grid_resolution)
        center_y = int(person.y / self.grid_resolution)
        
        for dx in range(-cell_radius, cell_radius + 1):
            for dy in range(-cell_radius, cell_radius + 1):
                cell = (center_x + dx, center_y + dy)
                for other in self.spatial_index.get(cell, []):
                    if other.id != person.id:
                        dist = np.sqrt((person.x - other.x)**2 + (person.y - other.y)**2)
                        if dist <= radius:
                            nearby.append(other)
        return nearby
    
    def _calculate_density_grid(self) -> None:
        grid_x = int(self.params.area_width / self.params.density_grid_size) + 1
        grid_y = int(self.params.area_height / self.params.density_grid_size) + 1
        self.density_grid = np.zeros((grid_x, grid_y))
        
        for person in self.people:
            if person.has_bitchat:
                x_idx = int(person.x / self.params.density_grid_size)
                y_idx = int(person.y / self.params.density_grid_size)
                self.density_grid[x_idx, y_idx] += 1
        
        from scipy.ndimage import gaussian_filter
        self.density_grid = gaussian_filter(self.density_grid, sigma=1.0)
        self.grid_update_time = self.time
    
    def get_local_density(self, person: Person) -> float:
        if self.density_grid is None or self.time - self.grid_update_time > 1.0:
            self._calculate_density_grid()
        
        x_idx = int(person.x / self.params.density_grid_size)
        y_idx = int(person.y / self.params.density_grid_size)
        
        raw_density = self.density_grid[x_idx, y_idx]
        return min(raw_density / 20.0, 1.0)
    
    def calculate_ble_range(self, person: Person, density: float) -> float:
        density_factor = np.exp(-density * 1.5)
        effective_range = self.params.ble_base_range * density_factor
        return max(effective_range, self.params.ble_min_range)
    
    def calculate_link_quality(self, p1: Person, p2: Person, distance: float) -> float:
        density1 = self.get_local_density(p1)
        density2 = self.get_local_density(p2)
        avg_density = (density1 + density2) / 2
        
        effective_range = self.calculate_ble_range(p1, avg_density)
        
        if distance > effective_range:
            return 0.0
        
        path_loss = 20 * np.log10(distance / 10) if distance > 10 else 0
        
        people_in_path = avg_density * distance / 2
        body_loss = self.params.body_attenuation_db * people_in_path
        
        total_loss_db = path_loss + body_loss
        
        rssi = -40 - total_loss_db
        quality = max(0, min(1, (rssi + 90) / 50))
        
        packet_loss = self.params.base_packet_loss + self.params.interference_factor * avg_density
        quality *= (1 - packet_loss)
        
        return quality
    
    def build_network(self, force_rebuild: bool = False) -> nx.Graph:
        if not force_rebuild and self.network is not None:
            if self.time - self.last_network_update < self.params.network_update_interval:
                return self.network
        
        G = nx.Graph()
        self._update_spatial_index()
        
        active_people = [p for p in self.people if p.has_bitchat and p.battery > 0]
        for person in active_people:
            G.add_node(person.id, pos=(person.x, person.y), battery=person.battery)
        
        for person in active_people:
            max_range = self.calculate_ble_range(person, 0)
            nearby = self._get_nearby_people(person, max_range)
            
            for other in nearby:
                if other.id > person.id and other.has_bitchat and other.battery > 0:
                    dist = np.sqrt((person.x - other.x)**2 + (person.y - other.y)**2)
                    quality = self.calculate_link_quality(person, other, dist)
                    
                    if quality > 0.1:
                        G.add_edge(person.id, other.id, weight=quality, distance=dist)
        
        self.network = G
        self.last_network_update = self.time
        return G
    
    def update_movement(self) -> None:
        for person in self.people:
            if not person.has_bitchat:
                continue
            
            density = self.get_local_density(person)
            
            speed_factor = np.exp(-density * 2)
            speed = self.params.base_speed * speed_factor
            speed = max(speed, self.params.min_speed)
            
            if person.is_stage_focused and random.random() < self.params.stage_attraction:
                target_x = self.params.stage_x + random.uniform(-20, 20)
                target_y = self.params.stage_y + 30 + random.uniform(-10, 10)
                
                dx = target_x - person.x
                dy = target_y - person.y
                dist = np.sqrt(dx**2 + dy**2)
                
                if dist > self.params.personal_space * 3:
                    person.vx = speed * dx / dist
                    person.vy = speed * dy / dist
                else:
                    person.vx *= 0.8
                    person.vy *= 0.8
            else:
                if random.random() < self.params.direction_change_prob:
                    angle = random.uniform(0, 2 * np.pi)
                    person.vx = speed * np.cos(angle)
                    person.vy = speed * np.sin(angle)
                else:
                    person.vx += random.uniform(-0.1, 0.1) * speed
                    person.vy += random.uniform(-0.1, 0.1) * speed
                    
                    v_mag = np.sqrt(person.vx**2 + person.vy**2)
                    if v_mag > 0:
                        person.vx = speed * person.vx / v_mag
                        person.vy = speed * person.vy / v_mag
            
            person.update_position(self.dt, (self.params.area_width, self.params.area_height))
    
    def update_battery(self) -> None:
        for person in self.people:
            if not person.has_bitchat or person.battery <= 0:
                continue
            
            hourly_drain = self.params.battery_idle_drain
            if person.battery > 20:
                hourly_drain += self.params.battery_scan_drain
            
            base_drain = (hourly_drain / 3600) * self.dt
            
            routing_drain = person.messages_routed * self.params.battery_routing_cost
            person.messages_routed = 0
            
            person.battery = max(0, person.battery - base_drain - routing_drain)
    
    def generate_messages(self) -> None:
        G = self.network
        if G is None or len(G) < 2:
            return
        
        for person in self.people:
            if (person.has_bitchat and person.battery > 10 and 
                random.random() < self.params.message_rate * self.dt):
                
                if person.id in G:
                    component = nx.node_connected_component(G, person.id)
                    possible_dests = [n for n in component if n != person.id]
                    
                    if possible_dests:
                        dst = random.choice(possible_dests)
                        
                        message = Message(
                            id=self.message_id_counter,
                            src=person.id,
                            dst=dst,
                            created_time=self.time,
                            ttl=self.params.message_ttl
                        )
                        
                        self.messages[self.message_id_counter] = message
                        self.message_id_counter += 1
    
    def route_messages(self) -> None:
        G = self.network
        if G is None:
            return
        
        current_time = self.time
        
        for msg_id, msg in list(self.messages.items()):
            if msg.state != MessageState.PENDING:
                continue
            
            if current_time - msg.created_time > self.params.message_timeout:
                msg.state = MessageState.EXPIRED
                continue
            
            if msg.src not in G or msg.dst not in G:
                continue
            
            if msg.attempts >= self.params.max_message_attempts:
                msg.state = MessageState.FAILED
                continue
            
            msg.attempts += 1
            
            try:
                weight_dict = {}
                for u, v, data in G.edges(data=True):
                    weight = 1.0 / (data['weight'] + 0.01)
                    weight_dict[(u, v)] = weight
                    weight_dict[(v, u)] = weight
                
                path = nx.shortest_path(G, msg.src, msg.dst, weight=lambda u, v, d: weight_dict.get((u, v), float('inf')))
                
                if len(path) - 1 > msg.ttl:
                    msg.state = MessageState.FAILED
                    continue
                
                success_prob = 1.0
                for i in range(len(path) - 1):
                    edge_data = G.get_edge_data(path[i], path[i+1])
                    if edge_data:
                        success_prob *= edge_data['weight']
                    
                    self.people[path[i]].messages_routed += 1
                
                if random.random() < success_prob:
                    msg.state = MessageState.DELIVERED
                    msg.delivered_time = current_time
                    msg.path = path
                    
                    latency = current_time - msg.created_time
                    self.metrics['latencies'].append(latency)
                    self.metrics['hop_counts'].append(len(path) - 1)
                    
            except nx.NetworkXNoPath:
                pass
    
    def update_metrics(self) -> None:
        recent_messages = [m for m in self.messages.values() 
                          if self.time - m.created_time < 60]
        if recent_messages:
            delivered = sum(1 for m in recent_messages if m.state == MessageState.DELIVERED)
            self.metrics['delivery_rates'].append(delivered / len(recent_messages))
        
        G = self.network
        if G and len(G) > 0:
            largest_cc = max(nx.connected_components(G), key=len)
            self.metrics['network_connected'].append(len(largest_cc) / len(G))
            self.metrics['active_nodes'].append(len(G))
        
        active_batteries = [p.battery for p in self.people if p.has_bitchat and p.battery > 0]
        if active_batteries:
            self.metrics['battery_levels'].append(np.mean(active_batteries))
    
    def step(self) -> None:
        self.update_movement()
        self.update_battery()
        
        self.build_network()
        
        self.generate_messages()
        self.route_messages()
        self.update_metrics()
        
        self.time += self.dt
        
        if int(self.time) % 30 == 0:
            cutoff_time = self.time - 120
            self.messages = {k: v for k, v in self.messages.items() 
                           if v.created_time > cutoff_time}
    
    def get_statistics(self) -> Dict:
        total_messages = len(self.messages)
        delivered = sum(1 for m in self.messages.values() if m.state == MessageState.DELIVERED)
        failed = sum(1 for m in self.messages.values() if m.state == MessageState.FAILED)
        expired = sum(1 for m in self.messages.values() if m.state == MessageState.EXPIRED)
        pending = sum(1 for m in self.messages.values() if m.state == MessageState.PENDING)
        
        stats = {
            'time': self.time,
            'total_messages': total_messages,
            'delivered': delivered,
            'failed': failed,
            'expired': expired,
            'pending': pending,
            'delivery_rate': delivered / total_messages if total_messages > 0 else 0,
            'avg_latency': np.mean(self.metrics['latencies']) if self.metrics['latencies'] else 0,
            'avg_hops': np.mean(self.metrics['hop_counts']) if self.metrics['hop_counts'] else 0,
            'network_size': len(self.network) if self.network else 0,
            'network_edges': self.network.number_of_edges() if self.network else 0,
            'avg_battery': np.mean([p.battery for p in self.people if p.has_bitchat])
        }
        
        return stats
    
    def visualize_snapshot(self, save_path: Optional[str] = None) -> None:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
        
        ax1.set_xlim(0, self.params.area_width)
        ax1.set_ylim(0, self.params.area_height)
        ax1.set_aspect('equal')
        ax1.set_title(f'Festival BLE Mesh (t={self.time:.1f}s)', fontsize=14)
        ax1.set_xlabel('Distance (m)')
        ax1.set_ylabel('Distance (m)')
        
        stage = Rectangle(
            (self.params.stage_x - self.params.stage_width/2, self.params.stage_y),
            self.params.stage_width, self.params.stage_height,
            fill=True, color='saddlebrown', alpha=0.8
        )
        ax1.add_patch(stage)
        ax1.text(self.params.stage_x, self.params.stage_y + self.params.stage_height/2,
                'STAGE', ha='center', va='center', fontsize=12, color='white', weight='bold')
        
        G = self.network
        for person in self.people:
            if person.has_bitchat:
                if person.battery > 0:
                    battery_ratio = person.battery / 100
                    color = plt.cm.RdYlGn(battery_ratio)
                    
                    if person.id % 10 == 0:
                        density = self.get_local_density(person)
                        range_circle = Circle(
                            (person.x, person.y),
                            self.calculate_ble_range(person, density),
                            fill=False, alpha=0.2, color='blue', linewidth=0.5
                        )
                        ax1.add_patch(range_circle)
                    
                    ax1.plot(person.x, person.y, 'o', color=color, markersize=4, alpha=0.8)
                else:
                    ax1.plot(person.x, person.y, 'x', color='red', markersize=3, alpha=0.5)
        
        if G and len(G) > 0:
            pos = nx.get_node_attributes(G, 'pos')
            for u, v, data in G.edges(data=True):
                if u in pos and v in pos:
                    x1, y1 = pos[u]
                    x2, y2 = pos[v]
                    quality = data['weight']
                    ax1.plot([x1, x2], [y1, y2], 'b-', alpha=quality*0.3, linewidth=0.5)
        
        stats = self.get_statistics()
        stats_text = (
            f"Active Nodes: {stats['network_size']}\n"
            f"Network Edges: {stats['network_edges']}\n"
            f"Avg Degree: {2*stats['network_edges']/stats['network_size'] if stats['network_size'] > 0 else 0:.1f}\n"
            f"Messages: {stats['total_messages']} (D:{stats['delivered']} F:{stats['failed']} P:{stats['pending']})\n"
            f"Delivery Rate: {stats['delivery_rate']:.1%}\n"
            f"Avg Latency: {stats['avg_latency']:.1f}s\n"
            f"Avg Hops: {stats['avg_hops']:.1f}\n"
            f"Avg Battery: {stats['avg_battery']:.1f}%"
        )
        
        ax1.text(0.02, 0.98, stats_text, transform=ax1.transAxes,
                verticalalignment='top', fontsize=10,
                bbox=dict(boxstyle='round,pad=0.5', facecolor='wheat', alpha=0.8))
        
        ax2.set_title('Network Performance Metrics', fontsize=14)
        
        if len(self.metrics['delivery_rates']) > 10:
            time_points = np.arange(len(self.metrics['delivery_rates'])) * self.dt
            
            ax2_twin = ax2.twinx()
            
            ax2.plot(time_points, self.metrics['delivery_rates'], 'g-', 
                    label='Delivery Rate', linewidth=2)
            ax2.plot(time_points, self.metrics['network_connected'], 'b-', 
                    label='Network Connected %', linewidth=2)
            ax2_twin.plot(time_points, self.metrics['battery_levels'], 'r--', 
                         label='Avg Battery %', linewidth=2)
            
            ax2.set_xlabel('Time (s)')
            ax2.set_ylabel('Rate / Connectivity')
            ax2_twin.set_ylabel('Battery Level (%)')
            ax2.set_ylim(0, 1.05)
            ax2_twin.set_ylim(0, 105)
            ax2.grid(True, alpha=0.3)
            
            lines1, labels1 = ax2.get_legend_handles_labels()
            lines2, labels2 = ax2_twin.get_legend_handles_labels()
            ax2.legend(lines1 + lines2, labels1 + labels2, loc='lower left')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            plt.close()
        else:
            plt.show()

def run_parameter_sweep(param_ranges: Dict[str, List], base_params: SimParams = None) -> Dict:
    if base_params is None:
        base_params = SimParams()
    
    results = {}
    
    import itertools
    param_names = list(param_ranges.keys())
    param_values = list(param_ranges.values())
    
    for combination in itertools.product(*param_values):
        params_dict = {name: value for name, value in zip(param_names, combination)}
        params = SimParams(**{**base_params.__dict__, **params_dict})
        
        logger.info(f"Running simulation with: {params_dict}")
        
        sim = OptimizedFestivalMeshSim(params)
        
        for _ in range(int(300 / sim.dt)):
            sim.step()
        
        stats = sim.get_statistics()
        results[tuple(combination)] = {
            'delivery_rate': stats['delivery_rate'],
            'avg_latency': stats['avg_latency'],
            'avg_hops': stats['avg_hops'],
            'final_battery': stats['avg_battery'],
            'network_connectivity': np.mean(list(sim.metrics['network_connected']))
        }
        
        logger.info(f"Results: DR={stats['delivery_rate']:.1%}, "
                   f"Latency={stats['avg_latency']:.1f}s, "
                   f"Battery={stats['avg_battery']:.1f}%")
    
    return results

def create_heatmap(results: Dict, x_param: str, y_param: str, metric: str = 'delivery_rate') -> None:
    x_values = sorted(set(k[0] for k in results.keys()))
    y_values = sorted(set(k[1] for k in results.keys()))
    
    data = np.zeros((len(y_values), len(x_values)))
    for i, y in enumerate(y_values):
        for j, x in enumerate(x_values):
            data[i, j] = results.get((x, y), {}).get(metric, 0)
    
    plt.figure(figsize=(10, 8))
    im = plt.imshow(data, aspect='auto', origin='lower', cmap='RdYlGn', vmin=0, vmax=1)
    plt.colorbar(im, label=metric.replace('_', ' ').title())
    
    plt.xticks(range(len(x_values)), [f'{v:.0%}' if v < 1 else f'{v:.0f}' for v in x_values])
    plt.yticks(range(len(y_values)), [f'{v:.0%}' if v < 1 else f'{v:.0f}' for v in y_values])
    
    plt.xlabel(x_param.replace('_', ' ').title())
    plt.ylabel(y_param.replace('_', ' ').title())
    plt.title(f'{metric.replace("_", " ").title()} vs {x_param} and {y_param}')
    
    for i in range(len(y_values)):
        for j in range(len(x_values)):
            text = plt.text(j, i, f'{data[i, j]:.2f}',
                          ha="center", va="center", color="black" if data[i, j] > 0.5 else "white")
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    np.random.seed(42)
    random.seed(42)
    
    params = SimParams(
        num_people=500,
        ble_base_range=30.0,
        bitchat_adoption=0.3
    )
    
...     logger.info("Starting festival mesh simulation...")
...     sim = OptimizedFestivalMeshSim(params)
...     
...     frames_to_save = []
...     for i in range(int(60 / sim.dt)):
...         sim.step()
...         
...         if i % int(10 / sim.dt) == 0:
...             sim.visualize_snapshot(save_path=f'festival_mesh_{i//int(10/sim.dt)}.png')
...             frames_to_save.append(i)
...             
...             stats = sim.get_statistics()
...             logger.info(f"Time: {stats['time']:.1f}s, "
...                        f"Delivery Rate: {stats['delivery_rate']:.1%}, "
...                        f"Active Nodes: {stats['network_size']}")
...     
...     final_stats = sim.get_statistics()
...     print("\n" + "="*50)
...     print("FINAL SIMULATION STATISTICS")
...     print("="*50)
...     for key, value in final_stats.items():
...         if isinstance(value, float):
...             print(f"{key}: {value:.2f}")
...         else:
...             print(f"{key}: {value}")
...     
...     print("\n" + "="*50)
...     print("RUNNING PARAMETER SWEEP")
...     print("="*50)
...     
...     param_ranges = {
...         'ble_base_range': [15, 25, 35, 45],
...         'bitchat_adoption': [0.1, 0.2, 0.3, 0.4, 0.5]
...     }
...     
...     results = run_parameter_sweep(param_ranges, base_params=params)
...     
