# Festival BLE Mesh Simulator

Optimized simulation of Bitchat BLE mesh networks in crowded festival environments.

## Features

- Realistic crowd movement and density modeling
- Accurate BLE range calculations with body attenuation
- Battery drain simulation
- Message routing with TTL and retries
- Performance metrics tracking
- Parameter sweep capabilities

## Usage
```python
from festival_mesh_sim import OptimizedFestivalMeshSim, SimParams

params = SimParams(
    num_people=500,
    bitchat_adoption=0.3,
    ble_base_range=30.0
)

sim = OptimizedFestivalMeshSim(params)
for _ in range(600):  # 60 seconds
    sim.step()
    
stats = sim.get_statistics()
print(f"Delivery rate: {stats['delivery_rate']:.1%}")