// search.js

// UI Elements cache
const UI = {
    searchForm: null, // Will initialize after DOM loads
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

// Data fetching
const DataFetcher = {
    async fetchSearchResults(query) {
        const response = await fetch(`/search?query=${encodeURIComponent(query)}`);
        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'No results found');
        }
        return response.json();
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
        const cdpNeighbors = data.collected_data?.cli?.['cdp-detail'] || [];
        const lldpNeighbors = data.collected_data?.cli?.['lldp-detail'] || [];

        const neighborTemplate = neighbor => `
            <tr>
                <td>${neighbor.device_id}</td>
                <td>${neighbor.ip_address}</td>
                <td>${neighbor.local_interface}</td>
                <td>${neighbor.remote_interface}</td>
                <td>${neighbor.platform}</td>
            </tr>
        `;

        UI.cdpTable.innerHTML = cdpNeighbors.map(neighborTemplate).join('');
        UI.lldpTable.innerHTML = lldpNeighbors.map(neighborTemplate).join('');
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
const SearchHandler = {
    async handleSearch(query) {
        if (!query) {
            throw new Error('Please enter a search query');
        }

        LoadingManager.show();
        ErrorManager.hide();

        const data = await DataFetcher.fetchSearchResults(query);
        UIUpdater.updateAll(data);
    }
};

// Initialize application
function initializeApp() {
    // Initialize UI elements
    UI.initialize();

    // Explicitly prevent form submission and handle search
    UI.searchForm.onsubmit = async (event) => {
        event.preventDefault(); // This stops the form from submitting
        event.stopPropagation(); // This prevents the event from bubbling up

        const query = UI.searchQuery.value.trim();

        try {
            await SearchHandler.handleSearch(query);
        } catch (error) {
            ErrorManager.show(error.message);
        } finally {
            LoadingManager.hide();
        }

        return false; // Extra prevention of form submission
    };
}

// Wait for DOM to load then initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}