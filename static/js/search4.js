// UI Elements cache
const UI = {
    searchForm: null,
    searchQuery: null,
    searchResults: null,
    errorAlert: null,
    loadingSpinner: null,
    searchText: null,
    basicInfo: null,
    accessStatus: null,
    interfacesTable: null,
    cdpTable: null,
    lldpTable: null,
    inventoryTable: null,
    rawData: null,
    // Add modal elements
    deviceModal: null,
    deviceList: null,

    initialize() {
        this.searchForm = document.getElementById('searchForm');
        this.searchQuery = document.getElementById('searchQuery');
        this.searchResults = document.getElementById('searchResults');
        this.errorAlert = document.getElementById('errorAlert');
        this.loadingSpinner = document.querySelector('.loading-spinner');
        this.searchText = document.querySelector('.search-text');
        this.basicInfo = document.getElementById('basicInfo');
        this.accessStatus = document.getElementById('accessStatus');
        this.interfacesTable = document.getElementById('interfacesTable');
        this.cdpTable = document.getElementById('cdpTable');
        this.lldpTable = document.getElementById('lldpTable');
        this.inventoryTable = document.getElementById('inventoryTable');
        this.rawData = document.getElementById('rawData');
        // Initialize modal elements
        this.deviceModal = new bootstrap.Modal(document.getElementById('deviceSelectorModal'));
        this.deviceList = document.getElementById('deviceList');
    }
};

// Loading state management
const LoadingManager = {
    show() {
        UI.loadingSpinner.style.display = 'inline-block';
        UI.searchText.textContent = 'Searching...';
    },
    hide() {
        UI.loadingSpinner.style.display = 'none';
        UI.searchText.textContent = 'Search';
    }
};

// Error handling
const ErrorManager = {
    show(message) {
        UI.errorAlert.textContent = message;
        UI.errorAlert.style.display = 'block';
        UI.searchResults.style.display = 'none';
    },
    hide() {
        UI.errorAlert.style.display = 'none';
    }
};

// Status badge utilities
const StatusBadgeUtil = {
    getStatusBadge(status) {
        const statusMap = {
            'up': 'success',
            'down': 'danger',
            'disabled': 'warning',
            'true': 'success',
            'false': 'danger'
        };
        const badgeType = statusMap[status?.toLowerCase()] || 'secondary';
        return `<span class="badge bg-${badgeType} status-badge">${status}</span>`;
    }
};

// Add Modal Manager
// Modal Manager
const ModalManager = {
    createDeviceListItem(device) {
        console.log('Creating list item for device:', device); // Debug log
        const listItem = document.createElement('button');
        listItem.className = 'list-group-item list-group-item-action';
        listItem.type = 'button';

        const sshBadge = StatusBadgeUtil.getStatusBadge(device.access_info?.ssh_works?.toString() || 'N/A');
        const snmpBadge = StatusBadgeUtil.getStatusBadge(device.access_info?.snmp_works?.toString() || 'N/A');

        listItem.innerHTML = `
            <div class="d-flex w-100 justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${device.name || 'Unknown Device'}</h6>
                    <p class="mb-1">IP: ${device.ip_address || 'N/A'}</p>
                    <small class="text-muted">Hostname: ${device.access_info?.hostname || 'N/A'}</small>
                </div>
                <div class="d-flex flex-column gap-1">
                    ${sshBadge}
                    ${snmpBadge}
                </div>
            </div>
        `;

        return listItem;
    },

    show(devices) {
        console.log('Show modal called with devices:', devices); // Debug log

        if (!UI.deviceModal) {
            console.error('Modal not initialized!'); // Debug log
            return;
        }

        if (!UI.deviceList) {
            console.error('Device list container not found!'); // Debug log
            return;
        }

        UI.deviceList.innerHTML = '';
        devices.forEach(device => {
            const listItem = this.createDeviceListItem(device);
            listItem.addEventListener('click', () => {
                console.log('Device selected:', device); // Debug log
                this.hide();
                UIUpdater.updateAll(device);
            });
            UI.deviceList.appendChild(listItem);
        });

        try {
            UI.deviceModal.show();
            console.log('Modal shown successfully'); // Debug log
        } catch (error) {
            console.error('Error showing modal:', error); // Debug log
        }
    },

    hide() {
        if (UI.deviceModal) {
            UI.deviceModal.hide();
        }
    }
};

// Data fetching
// Data fetching
const DataFetcher = {
    async fetchSearchResults(query) {
        try {
            const response = await fetch(`/search?query=${encodeURIComponent(query)}`);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'No results found');
            }

            return data;
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }
};
// UI Updaters
const UIUpdater = {
    updateBasicInfo(data) {
        UI.basicInfo.innerHTML = `
            <tr><td><strong>Name:</strong></td><td>${data.name || 'N/A'}</td></tr>
            <tr><td><strong>IP Address:</strong></td><td>${data.ip_address || 'N/A'}</td></tr>
            <tr><td><strong>OS Type:</strong></td><td>${data.access_info?.os_type || 'N/A'}</td></tr>
            <tr><td><strong>System Description:</strong></td><td>${data.collected_data?.snmp?.system?.sysDescr || 'N/A'}</td></tr>
        `;

        UI.accessStatus.innerHTML = `
            <tr><td><strong>SSH Status:</strong></td><td>${StatusBadgeUtil.getStatusBadge(data.access_info?.ssh_works?.toString() || 'N/A')}</td></tr>
            <tr><td><strong>SNMP Status:</strong></td><td>${StatusBadgeUtil.getStatusBadge(data.access_info?.snmp_works?.toString() || 'N/A')}</td></tr>
            <tr><td><strong>Hostname:</strong></td><td>${data.access_info?.hostname || 'N/A'}</td></tr>
        `;
    },

    updateInterfaces(data) {
        const interfaces = data.collected_data?.cli?.['int-status'] || [];
        UI.interfacesTable.innerHTML = interfaces.map(int => `
            <tr>
                <td>${int.interface}</td>
                <td>${int.description || ''}</td>
                <td>${StatusBadgeUtil.getStatusBadge(int.phy_status)}</td>
                <td>${StatusBadgeUtil.getStatusBadge(int.lp_status)}</td>
            </tr>
        `).join('');
    },

updateNeighbors(data) {
    // Add debug logging
    console.log('CDP data:', data.collected_data?.cli?.['cdp-detail']);
    console.log('LLDP data:', data.collected_data?.cli?.['lldp-detail']);

    const cdpNeighbors = data.collected_data?.cli?.['cdp-detail'] || [];
    const lldpNeighbors = data.collected_data?.cli?.['lldp-detail'] || [];


    console.log('Processed CDP neighbors:', cdpNeighbors.length);
    console.log('Processed LLDP neighbors:', lldpNeighbors.length);

    // Template for CDP neighbors
    const cdpTemplate = neighbor => `
        <tr>
            <td>${neighbor.device_id || 'N/A'}</td>
            <td>${neighbor.ip_address || 'N/A'}</td>
            <td>${neighbor.local_interface || 'N/A'}</td>
            <td>${neighbor.remote_interface || 'N/A'}</td>
            <td>${neighbor.platform || 'N/A'}</td>
        </tr>
    `;

    // Template for LLDP neighbors
    const lldpTemplate = neighbor => `
        <tr>
            <td>${neighbor.device_id || 'N/A'}</td>
            <td>${neighbor.ip_address || 'N/A'}</td>
            <td>${neighbor.local_interface || 'N/A'}</td>
            <td>${neighbor.remote_interface || 'N/A'}</td>
            <td>${neighbor.platform || 'N/A'}</td>
        </tr>
    `;

    // Update tables and log the HTML content being set
    const cdpContent = cdpNeighbors.length ?
        cdpNeighbors.map(cdpTemplate).join('') :
        '<tr><td colspan="5" class="text-center">No CDP neighbors found</td></tr>';

    const lldpContent = lldpNeighbors.length ?
        lldpNeighbors.map(lldpTemplate).join('') :
        '<tr><td colspan="5" class="text-center">No LLDP neighbors found</td></tr>';

    console.log('CDP HTML content:', cdpContent);
    console.log('LLDP HTML content:', lldpContent);

    if (!UI.cdpTable) console.error('CDP table element not found');
    if (!UI.lldpTable) console.error('LLDP table element not found');

    UI.cdpTable.innerHTML = cdpContent;
    UI.lldpTable.innerHTML = lldpContent;

    // Make sure the LLDP section is visible
    const lldpSection = UI.lldpTable.closest('.card');
    if (lldpSection) {
        lldpSection.style.display = 'block';
    } else {
        console.error('Could not find LLDP section container');
    }
},

    updateInventory(data) {
        const inventory = data.collected_data?.cli?.inventory || [];
        UI.inventoryTable.innerHTML = inventory.map(item => `
            <tr>
                <td>${item.part_name}</td>
                <td>${item.part_no}</td>
                <td>${item.serial_number}</td>
                <td>${item.description}</td>
            </tr>
        `).join('');
    },

    updateRawData(data) {
        UI.rawData.textContent = JSON.stringify(data, null, 2);
    },

    showResults() {
        UI.searchResults.style.display = 'block';
    },

    updateAll(data) {
        this.updateBasicInfo(data);
        this.updateInterfaces(data);
        this.updateNeighbors(data);
        this.updateInventory(data);
        this.updateRawData(data);
        this.showResults();
    }
};

// Search Handler
// Search Handler
const SearchHandler = {
    async handleSearch(query) {
        if (!query) {
            throw new Error('Please enter a search query');
        }

        LoadingManager.show();
        ErrorManager.hide();

        try {
            const response = await DataFetcher.fetchSearchResults(query);
            console.log('Search response:', response); // Debug log

            if (response.devices) {
                console.log('Number of devices:', response.devices.length); // Debug log

                if (response.devices.length > 1) {
                    console.log('Showing modal for multiple devices'); // Debug log
                    UI.searchResults.style.display = 'none';
                    ModalManager.show(response.devices);
                } else if (response.devices.length === 1) {
                    console.log('Showing single device'); // Debug log
                    UIUpdater.updateAll(response.devices[0]);
                } else {
                    throw new Error('No devices found');
                }
            } else {
                throw new Error('Invalid response format');
            }
        } catch (error) {
            console.error('Search error:', error); // Debug log
            ErrorManager.show(error.message);
        }
    }
};
// Initialize application
function initializeApp() {
    UI.initialize();
        this.cdpTable = document.getElementById('cdpTable');
    this.lldpTable = document.getElementById('lldpTable');

    if (!this.cdpTable) alert('CDP table not found during initialization');
    if (!this.lldpTable) alert('LLDP table not found during initialization');

    UI.searchForm.onsubmit = async (event) => {
        event.preventDefault();
        event.stopPropagation();

        const query = UI.searchQuery.value.trim();

        try {
            await SearchHandler.handleSearch(query);
        } catch (error) {
            ErrorManager.show(error.message);
        } finally {
            LoadingManager.hide();
        }

        return false;
    };
}

// Wait for DOM to load then initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}