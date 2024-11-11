from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class NetworkCredentials:
    ssh_username: str
    ssh_password: str
    snmp_communities: List[str] = field(default_factory=list)
    enable_password: Optional[str] = None
    arista_credentials: Dict[str, str] = field(default_factory=lambda: {
        'username': None,
        'password': None,
        'enable': None
    })
    aruba_credentials: Dict[str, str] = field(default_factory=lambda: {
        'username': None,
        'password': None,
        'enable': None
    })
    paloalto_credentials: Dict[str, str] = field(default_factory=lambda: {
        'username': None,
        'password': None
    })

@dataclass
class DeviceData:
    ip_address: str
    access_info: Dict = field(default_factory=lambda: {
        'ssh_works': False,
        'snmp_works': False,
        'working_community': None,
        'os_type': None,
        'prompt': None,
        'hostname': None
    })
    collected_data: Dict = field(default_factory=dict)
    collection_errors: List[str] = field(default_factory=list)
    discovery_time: datetime = field(default_factory=datetime.now)
