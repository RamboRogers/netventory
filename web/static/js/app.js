class NetVentoryApp {
    constructor() {
        this.ws = null;
        this.currentScreen = 'interface-selection';
        this.devices = new Map();
        this.scanStartTime = null;
        this.scanActive = false;
        this.setupWebSocket();
        this.setupEventListeners();
        document.querySelectorAll('main > div').forEach(div => div.classList.add('hidden'));

        // Start with interface selection, WebSocket connection will update if we have data
        document.querySelector('.interface-selection').classList.remove('hidden');
    }

    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const authToken = new URLSearchParams(window.location.search).get('auth');
        this.ws = new WebSocket(`${protocol}//${window.location.host}/ws?auth=${authToken}`);

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };

        this.ws.onclose = () => {
            console.log('WebSocket connection closed');
            setTimeout(() => this.setupWebSocket(), 5000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.showError('WebSocket connection error. Please check your authentication token.');
        };
    }

    setupEventListeners() {
        document.getElementById('start-scan').addEventListener('click', () => {
            const range = document.getElementById('cidr-range').value;
            if (!this.validateCIDR(range)) {
                this.showError('Invalid CIDR range format');
                return;
            }
            this.startScan(range);
        });

        // Add enter key handler for CIDR input
        document.getElementById('cidr-range').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const range = e.target.value;
                if (!this.validateCIDR(range)) {
                    this.showError('Invalid CIDR range format');
                    return;
                }
                this.startScan(range);
            }
        });

        document.querySelector('.close-details').addEventListener('click', () => {
            this.showScreen('scanning-view');
        });

        // Create action buttons container
        const actionButtons = document.createElement('div');
        actionButtons.className = 'action-buttons';
        document.querySelector('.container').appendChild(actionButtons);

        // Add stop scan button
        const stopButton = document.createElement('button');
        stopButton.id = 'stop-scan';
        stopButton.textContent = 'Stop Scan';
        stopButton.classList.add('action-button', 'hidden');
        actionButtons.appendChild(stopButton);

        // Add stop scan event listener
        stopButton.addEventListener('click', () => {
            this.stopScan();
        });

        // Add dump scan button
        const dumpButton = document.createElement('button');
        dumpButton.id = 'dump-scan';
        dumpButton.textContent = 'Dump Scan';
        dumpButton.classList.add('action-button', 'dump-scan', 'hidden');
        actionButtons.appendChild(dumpButton);

        // Add dump scan event listener
        dumpButton.addEventListener('click', () => {
            this.dumpScan();
        });

        // Add save scan button
        const saveButton = document.createElement('button');
        saveButton.id = 'save-scan';
        saveButton.textContent = 'Save Scan';
        saveButton.classList.add('action-button', 'save-scan', 'hidden');
        actionButtons.appendChild(saveButton);

        // Add save scan event listener
        saveButton.addEventListener('click', () => {
            this.saveScan();
        });

        // Delegate device row clicks
        document.getElementById('device-table').addEventListener('click', (e) => {
            const row = e.target.closest('tr');
            if (row && row.dataset.ip) {
                this.showDeviceDetails(row.dataset.ip);
            }
        });
    }

    handleWebSocketMessage(data) {
        console.log('Received WebSocket message:', data);  // Debug log

        switch (data.type) {
            case 'interfaces':
                this.updateInterfaces(data.interfaces);
                break;
            case 'devices':
                // Update device list without affecting progress
                if (Array.isArray(data.devices)) {
                    this.updateDevices(data.devices);
                } else if (data.devices && typeof data.devices === 'object') {
                    this.updateDevices(Object.values(data.devices));
                }

                // If we have devices and we're not scanning, show the scan view with completed state
                if (Object.keys(data.devices || {}).length > 0 && !this.scanActive) {
                    this.showScreen('scanning-view');
                    document.querySelector('.current-status').textContent = 'Previous scan results';
                    document.querySelector('.progress').classList.add('complete');
                    document.querySelector('.progress').style.width = '100%';
                    document.querySelector('.progress-status').textContent = 'SCAN DONE';
                    // Show dump and save scan buttons
                    document.getElementById('dump-scan').classList.remove('hidden');
                    document.getElementById('save-scan').classList.remove('hidden');
                }
                break;
            case 'progress':
                console.log('Progress update:', data);  // Debug log
                if (typeof data.scanned === 'number') {
                    this.updateProgress(data);
                }
                break;
            case 'scan_complete':
                this.handleScanComplete();
                break;
            case 'error':
                this.showError(data.error);
                break;
        }
    }

    showScreen(screenName) {
        document.querySelectorAll('main > div').forEach(div => div.classList.add('hidden'));
        document.querySelector(`.${screenName}`).classList.remove('hidden');
        this.currentScreen = screenName;

        // Focus CIDR input when showing scan confirmation
        if (screenName === 'scan-confirmation') {
            setTimeout(() => {
                const input = document.getElementById('cidr-range');
                input.focus();
                input.select();  // Also select the text for easy editing
            }, 0);
        }

        // If returning to scanning view, refresh the device table
        if (screenName === 'scanning-view' && this.devices.size > 0) {
            this.updateDevices(Array.from(this.devices.values()));

            // Update the stats display
            const onlineDevices = Array.from(this.devices.values()).filter(d => d.OpenPorts && d.OpenPorts.length > 0).length;
            document.querySelector('.discovered').textContent = `${onlineDevices} devices`;

            if (!this.scanActive) {
                document.querySelector('.current-status').textContent = 'Previous scan results';
                document.querySelector('.progress').classList.add('complete');
                document.querySelector('.progress').style.width = '100%';
                document.querySelector('.progress-status').textContent = 'SCAN DONE';
            }
        }
    }

    updateInterfaces(interfaces) {
        const container = document.querySelector('.interface-list');
        container.innerHTML = interfaces.map(iface => `
            <div class="interface-card" data-name="${iface.Name}">
                <h3>${iface.FriendlyName}</h3>
                <p>IP: ${iface.IPAddress}</p>
                <p>MAC: ${iface.MACAddress}</p>
                <p>Gateway: ${iface.Gateway}</p>
            </div>
        `).join('');

        // Add click handlers
        container.querySelectorAll('.interface-card').forEach(card => {
            card.addEventListener('click', () => {
                const selectedIface = interfaces.find(i => i.Name === card.dataset.name);
                document.getElementById('cidr-range').value = selectedIface.IPAddress + selectedIface.CIDR;
                this.showScreen('scan-confirmation');
            });
        });
    }

    updateDevices(devices) {
        if (!Array.isArray(devices)) {
            console.error('Expected devices to be an array');
            return;
        }

        devices.forEach(device => {
            if (device && device.IPAddress) {
                this.devices.set(device.IPAddress, device);
            }
        });

        const tbody = document.getElementById('device-table');
        const deviceList = Array.from(this.devices.values())
            .sort((a, b) => this.compareIPs(a.IPAddress, b.IPAddress));

        console.log('Updating device table with', deviceList.length, 'devices');

        tbody.innerHTML = deviceList.map(device => `
            <tr data-ip="${device.IPAddress}">
                <td>${device.IPAddress}</td>
                <td>${device.Hostname ? device.Hostname.join(', ') : ''}</td>
                <td>${this.formatPortsWithUrls(device.IPAddress, device.OpenPorts)}</td>
            </tr>
        `).join('');
    }

    updateProgress(data) {
        if (!this.scanStartTime) {
            this.scanStartTime = new Date();
        }

        // Get total and completed scan counts from server's progress messages
        const total = parseInt(data.total || data.total_ips) || 0;
        const completedScans = parseInt(data.scanned) || 0;

        // Validate the counts
        if (completedScans > total) {
            console.error('Invalid progress: completed scans greater than total');
            return;
        }

        const onlineDevices = Array.from(this.devices.values()).filter(d => d.OpenPorts && d.OpenPorts.length > 0).length;
        const progress = total > 0 ? (completedScans / total) * 100 : 0;

        console.log(`Progress update - Scanned: ${completedScans}, Total: ${total}, Progress: ${progress.toFixed(2)}%, Online: ${onlineDevices}`);

        // Update progress bar
        const progressBar = document.querySelector('.progress');
        progressBar.style.width = `${Math.min(progress, 100)}%`;

        const elapsed = (new Date() - this.scanStartTime) / 1000;
        const rate = elapsed > 0 ? Math.round(completedScans / elapsed) : 0;

        // Update progress stats
        document.querySelector('.scanned').textContent = `${completedScans}/${total}`;
        document.querySelector('.rate').textContent = `${rate}/sec`;
        document.querySelector('.discovered').textContent = `${onlineDevices} devices`;
        document.querySelector('.elapsed').textContent = this.formatElapsedTime(elapsed);

        // Update status text based on progress
        if (progress >= 100) {
            document.querySelector('.current-status').textContent = 'Scan Complete';
            document.querySelector('.progress-status').textContent = 'SCAN DONE';
            progressBar.classList.add('complete');
            document.getElementById('stop-scan').classList.add('hidden');
            document.getElementById('dump-scan').classList.remove('hidden');
            document.getElementById('save-scan').classList.remove('hidden');
            this.scanActive = false;
        } else {
            document.querySelector('.current-status').textContent =
                `Scanning: ${onlineDevices} devices found`;
            document.querySelector('.progress-status').textContent = 'SCANNING';
        }
    }

    formatElapsedTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    handleScanComplete() {
        // Update status text
        document.querySelector('.current-status').textContent = 'Scan Complete';
        document.querySelector('.progress-status').textContent = 'SCAN DONE';

        // Update progress bar
        const progressBar = document.querySelector('.progress');
        progressBar.classList.add('complete');
        progressBar.style.width = '100%';

        // Hide stop scan button
        document.getElementById('stop-scan').classList.add('hidden');

        // Show dump and save scan buttons
        document.getElementById('dump-scan').classList.remove('hidden');
        document.getElementById('save-scan').classList.remove('hidden');

        // Update scan state
        this.scanActive = false;
        this.scanStartTime = null;
        sessionStorage.removeItem('scanActive');
        sessionStorage.removeItem('scanStartTime');

        // Save devices to session storage
        if (this.devices.size > 0) {
            sessionStorage.setItem('scanDevices', JSON.stringify(Array.from(this.devices.entries())));
        }
    }

    startScan(range) {
        this.ws.send(JSON.stringify({
            type: 'start_scan',
            range: range
        }));
        this.showScreen('scanning-view');
        this.scanStartTime = new Date();
        this.scanActive = true;
        sessionStorage.setItem('scanActive', 'true');
        sessionStorage.setItem('scanStartTime', this.scanStartTime.getTime().toString());

        const progressBar = document.querySelector('.progress');
        progressBar.style.width = '0%';
        progressBar.classList.remove('complete');
        document.querySelector('.progress-status').textContent = 'Scanning';
        document.getElementById('stop-scan').classList.remove('hidden');
        document.querySelector('.current-status').textContent = 'Starting scan...';
        document.querySelector('.current-status').style.color = 'var(--text-secondary)';
    }

    stopScan() {
        if (!this.scanActive) return;

        this.ws.send(JSON.stringify({
            type: 'stop_scan'
        }));
        this.scanActive = false;
        sessionStorage.removeItem('scanActive');
        sessionStorage.removeItem('scanStartTime');
        document.getElementById('stop-scan').classList.add('hidden');
        document.querySelector('.current-status').textContent = 'Scan stopped by user';
    }

    formatPortsWithUrls(ip, ports, detailed = false) {
        if (!ports || ports.length === 0) return 'None';

        const formatPort = (port) => {
            const protocols = [];
            if (port === 80) protocols.push('http');
            if (port === 443) protocols.push('https');
            if (port === 22) protocols.push('ssh');
            if (port === 21) protocols.push('ftp');
            if (port === 3389) protocols.push('rdp');
            if (port === 445) protocols.push('smb');
            if (port === 5900) protocols.push('vnc');
            if (port === 8080) protocols.push('http');
            if (port === 8006) protocols.push('http');

            if (detailed) {
                // For device details view, show full URLs
                const links = protocols.map(proto =>
                    `<a href="${proto}://${ip}:${port}" target="_blank">${proto}://${ip}:${port}</a>`
                );
                return links.length > 0 ?
                    `${port} - ${links.join('<br>')}` :
                    `${port}`;
            } else {
                // For main table view, show compact format
                const links = protocols.map(proto =>
                    `<a href="${proto}://${ip}:${port}" target="_blank">${proto}</a>`
                );
                return links.length > 0 ?
                    `${port} (${links.join(', ')})` :
                    port.toString();
            }
        };

        if (detailed) {
            // Show all ports in details view with no extra spacing
            return ports.map(formatPort).join('<br>');
        } else {
            // Show only first 5 ports in main list
            const visiblePorts = ports.slice(0, 5);
            const hasMore = ports.length > 5;
            return visiblePorts.map(formatPort).join(', ') + (hasMore ? ' +' : '');
        }
    }

    showDeviceDetails(ip) {
        const device = this.devices.get(ip);
        if (!device) return;

        const content = document.querySelector('.details-content');
        content.innerHTML = `
            <h2>Device Details</h2>
            <div class="detail-grid">
                <div class="detail-item">
                    <label>IP Address</label>
                    <span class="detail-value">${device.IPAddress}</span>
                </div>
                <div class="detail-item">
                    <label>Hostname</label>
                    <span class="detail-value">${device.Hostname ? device.Hostname.join(', ') : 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <label>MAC Address</label>
                    <span class="detail-value">${device.MACAddress || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <label>Open Ports</label>
                    <span class="detail-value">${this.formatPortsWithUrls(device.IPAddress, device.OpenPorts, true)}</span>
                </div>
                ${device.MDNSName ? `
                    <div class="detail-item">
                        <label>mDNS Name</label>
                        <span class="detail-value">${device.MDNSName}</span>
                    </div>
                ` : ''}
                ${device.MDNSServices ? `
                    <div class="detail-item">
                        <label>mDNS Services</label>
                        <span class="detail-value">${Object.entries(device.MDNSServices).map(([k,v]) =>
                            `${k}: ${v}`).join('<br>')}</span>
                    </div>
                ` : ''}
            </div>
        `;

        this.showScreen('device-details');
    }

    compareIPs(a, b) {
        const aOctets = a.split('.').map(Number);
        const bOctets = b.split('.').map(Number);

        for (let i = 0; i < 4; i++) {
            if (aOctets[i] !== bOctets[i]) {
                return aOctets[i] - bOctets[i];
            }
        }
        return 0;
    }

    showError(message) {
        const statusBar = document.querySelector('.current-status');
        statusBar.textContent = `Error: ${message}`;
        statusBar.style.color = 'var(--error)';
        setTimeout(() => {
            statusBar.style.color = 'var(--text-secondary)';
        }, 5000);
    }

    validateCIDR(cidr) {
        const parts = cidr.split('/');
        if (parts.length !== 2) return false;

        const ip = parts[0].split('.');
        const mask = parseInt(parts[1], 10);

        if (ip.length !== 4) return false;
        if (mask < 0 || mask > 32) return false;

        return ip.every(octet => {
            const num = parseInt(octet, 10);
            return num >= 0 && num <= 255;
        });
    }

    dumpScan() {
        // Send dump request to server
        this.ws.send(JSON.stringify({
            type: 'dump_scan'
        }));

        // Clear all scan data
        this.devices.clear();
        this.scanActive = false;
        this.scanStartTime = null;

        // Clear session storage
        sessionStorage.removeItem('scanActive');
        sessionStorage.removeItem('scanStartTime');
        sessionStorage.removeItem('scanDevices');

        // Reset UI elements
        document.querySelector('.progress').style.width = '0%';
        document.querySelector('.progress').classList.remove('complete');
        document.querySelector('.progress-status').textContent = '';
        document.querySelector('.current-status').textContent = '';
        document.querySelector('.scanned').textContent = '0/0';
        document.querySelector('.rate').textContent = '0/sec';
        document.querySelector('.discovered').textContent = '0 devices';
        document.querySelector('.elapsed').textContent = '00:00';

        // Clear device table
        document.getElementById('device-table').innerHTML = '';

        // Hide buttons
        document.getElementById('dump-scan').classList.add('hidden');
        document.getElementById('save-scan').classList.add('hidden');
        document.getElementById('stop-scan').classList.add('hidden');
        document.getElementById('return-to-scan')?.classList.add('hidden');

        // Return to interface selection
        this.showScreen('interface-selection');
    }

    saveScan() {
        // Get auth token from URL
        const authToken = new URLSearchParams(window.location.search).get('auth');

        // Create download URL with auth token
        const downloadUrl = `/save?auth=${authToken}`;

        // Create temporary link and trigger download
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = ''; // Let server set filename
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new NetVentoryApp();
});