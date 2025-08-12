// Modern IOC Hunter Application - Fixed Version
class ModernIOCHunter {
    constructor() {
        this.patterns = {
            ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
            md5: /\b[a-fA-F0-9]{32}\b/g,
            sha1: /\b[a-fA-F0-9]{40}\b/g,
            sha256: /\b[a-fA-F0-9]{64}\b/g,
            sha512: /\b[a-fA-F0-9]{128}\b/g,
            url: /https?:\/\/[^\s<>"']+/g,
            domain: /\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b/g
        };

        this.ecsMapping = {
            ipv4: ['source.ip', 'destination.ip'],
            md5: ['file.hash.md5', 'process.hash.md5'],
            sha1: ['file.hash.sha1', 'process.hash.sha1'],
            sha256: ['file.hash.sha256', 'process.hash.sha256'],
            sha512: ['file.hash.sha512', 'process.hash.sha512'],
            url: ['url.original'],
            domain: ['destination.domain', 'source.domain']
        };

        this.sampleText = `Threat Report: APT29 Campaign Analysis

The following indicators of compromise (IOCs) were identified during our investigation:

IP Addresses:
- 192.168.1.100 (C2 server)
- 10.0.0.25 (infected host)
- 203.0.113.45 (exfiltration server)

File Hashes:
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
SHA512: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043

URLs:
- https://malicious-domain.com/payload.exe
- http://evil-site.org/data-exfil
- https://c2-server.net/beacon

Domains:
- malicious-domain.com
- evil-site.org
- c2-server.net`;

        this.currentResults = null;
        this.copyCounter = 0;
    }

    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupApplication());
        } else {
            this.setupApplication();
        }
    }

    setupApplication() {
        this.bindEvents();
        this.updateUI();
        this.setupTextareaFeatures();
    }

    bindEvents() {
        // Extract IOCs button
        const extractBtn = document.getElementById('extractBtn');
        if (extractBtn) {
            extractBtn.addEventListener('click', () => this.extractIOCs());
        }

        // Clear button  
        const clearBtn = document.getElementById('clearBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearInput());
        }

        // Load Sample button
        const loadSampleBtn = document.getElementById('loadSampleBtn');
        if (loadSampleBtn) {
            loadSampleBtn.addEventListener('click', () => this.loadSample());
        }

        // Export button
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportResults());
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                this.extractIOCs();
            }
            
            if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
                e.preventDefault();
                this.loadSample();
            }
            
            if (e.key === 'Escape') {
                this.clearInput();
            }
        });
    }

    setupTextareaFeatures() {
        const textarea = document.getElementById('iocInput');
        const charCount = document.getElementById('charCount');
        
        if (textarea && charCount) {
            // Auto-resize and character counting
            const updateTextarea = () => {
                // Update character count
                charCount.textContent = textarea.value.length.toLocaleString();
                
                // Auto-resize
                textarea.style.height = 'auto';
                textarea.style.height = Math.max(300, textarea.scrollHeight) + 'px';
            };

            textarea.addEventListener('input', updateTextarea);
            textarea.addEventListener('paste', () => setTimeout(updateTextarea, 10));

            // Initial character count
            charCount.textContent = '0';
        }
    }

    extractIOCs() {
        const textarea = document.getElementById('iocInput');
        if (!textarea) {
            this.showToast('Input field not found', 'error');
            return;
        }

        const input = textarea.value;
        console.log('Input text:', input);
        console.log('Input length:', input.length);
        console.log('Input trimmed length:', input.trim().length);
        
        if (!input || input.trim().length === 0) {
            this.showToast('Please enter some text to analyze', 'error');
            return;
        }

        const extractBtn = document.getElementById('extractBtn');
        const originalHtml = extractBtn ? extractBtn.innerHTML : '';

        try {
            // Show loading state
            if (extractBtn) {
                extractBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Processing...</span>';
                extractBtn.disabled = true;
                extractBtn.classList.add('loading');
            }

            // Process the text immediately for better UX
            const results = this.analyzeText(input);
            console.log('Analysis results:', results);
            
            this.currentResults = results;
            this.displayResults(results);
            
            this.showToast('IOCs extracted successfully!');
            
        } catch (error) {
            console.error('Error during IOC extraction:', error);
            this.showToast('Error during IOC extraction: ' + error.message, 'error');
        } finally {
            // Restore button state
            if (extractBtn) {
                extractBtn.innerHTML = originalHtml;
                extractBtn.disabled = false;
                extractBtn.classList.remove('loading');
            }
        }
    }

    analyzeText(text) {
        const results = {
            ips: new Set(),
            hashes: {
                md5: new Set(),
                sha1: new Set(),
                sha256: new Set(),
                sha512: new Set()
            },
            urls: new Set(),
            domains: new Set()
        };

        try {
            console.log('Starting analysis of text:', text.substring(0, 100) + '...');

            // Extract IPs
            const ipMatches = Array.from(text.matchAll(this.patterns.ipv4));
            console.log('Found IP matches:', ipMatches.length);
            ipMatches.forEach(match => {
                const ip = match[0];
                if (this.isValidIP(ip)) {
                    results.ips.add(ip);
                    console.log('Added IP:', ip);
                }
            });

            // Extract hashes
            const hashTypes = ['md5', 'sha1', 'sha256', 'sha512'];
            hashTypes.forEach(type => {
                const hashMatches = Array.from(text.matchAll(this.patterns[type]));
                console.log(`Found ${type} matches:`, hashMatches.length);
                hashMatches.forEach(match => {
                    const hash = match[0].toLowerCase();
                    results.hashes[type].add(hash);
                    console.log(`Added ${type}:`, hash);
                });
            });

            // Extract URLs
            const urlMatches = Array.from(text.matchAll(this.patterns.url));
            console.log('Found URL matches:', urlMatches.length);
            urlMatches.forEach(match => {
                const url = match[0];
                results.urls.add(url);
                console.log('Added URL:', url);
                
                // Extract domain from URL
                try {
                    const urlObj = new URL(url);
                    const domain = urlObj.hostname;
                    if (domain && !this.isCommonDomain(domain)) {
                        results.domains.add(domain.toLowerCase());
                        console.log('Added domain from URL:', domain);
                    }
                } catch (e) {
                    console.log('Invalid URL, skipping domain extraction:', url);
                }
            });

            // Extract standalone domains
            const domainMatches = Array.from(text.matchAll(this.patterns.domain));
            console.log('Found domain matches:', domainMatches.length);
            domainMatches.forEach(match => {
                const domain = match[0].toLowerCase();
                if (!this.isCommonDomain(domain) && !this.isIPAddress(domain)) {
                    results.domains.add(domain);
                    console.log('Added standalone domain:', domain);
                }
            });

            console.log('Final results:', {
                ips: Array.from(results.ips),
                hashes: Object.fromEntries(Object.entries(results.hashes).map(([k, v]) => [k, Array.from(v)])),
                urls: Array.from(results.urls),
                domains: Array.from(results.domains)
            });

        } catch (error) {
            console.error('Error in analyzeText:', error);
            throw error;
        }

        return results;
    }

    isValidIP(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(part => isNaN(part) || part < 0 || part > 255)) {
            return false;
        }
        
        // Skip localhost and broadcast addresses
        if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '255.255.255.255') {
            return false;
        }
        
        return true;
    }

    isIPAddress(domain) {
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
    }

    isCommonDomain(domain) {
        const commonDomains = [
            'example.com', 'example.org', 'example.net',
            'localhost', 'test.com', 'test.org'
        ];
        
        // Check if it's a very common domain we want to exclude
        const isCommon = commonDomains.some(common => domain.includes(common));
        const isTooShort = domain.length < 4;
        const hasValidTLD = /\.[a-zA-Z]{2,}$/.test(domain);
        
        return isCommon || isTooShort || !hasValidTLD;
    }

    displayResults(results) {
        try {
            const resultsSection = document.getElementById('resultsSection');
            const emptyState = document.getElementById('emptyState');

            if (resultsSection && emptyState) {
                resultsSection.classList.remove('hidden');
                emptyState.classList.add('hidden');
            }

            this.updateStatsCards(results);
            this.updateIOCsPanel(results);
            this.updateKQLPanel(results);
            
            // Scroll to results
            setTimeout(() => {
                resultsSection?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
            
        } catch (error) {
            console.error('Error displaying results:', error);
            this.showToast('Error displaying results', 'error');
        }
    }

    updateStatsCards(results) {
        const statsCards = document.getElementById('statsCards');
        if (!statsCards) return;

        const totalHashes = Object.values(results.hashes).reduce((sum, set) => sum + set.size, 0);

        statsCards.innerHTML = `
            <div class="stat-card stat-card--ip">
                <div class="stat-number">${results.ips.size}</div>
                <div class="stat-label">IP Addresses</div>
            </div>
            <div class="stat-card stat-card--hash">
                <div class="stat-number">${totalHashes}</div>
                <div class="stat-label">File Hashes</div>
            </div>
            <div class="stat-card stat-card--url">
                <div class="stat-number">${results.urls.size}</div>
                <div class="stat-label">URLs</div>
            </div>
            <div class="stat-card stat-card--domain">
                <div class="stat-number">${results.domains.size}</div>
                <div class="stat-label">Domains</div>
            </div>
        `;
    }

    updateIOCsPanel(results) {
        const iocsContent = document.getElementById('iocsContent');
        if (!iocsContent) return;

        let html = '';

        if (results.ips.size > 0) {
            html += this.createIOCGroup('IP Addresses', Array.from(results.ips), 'fas fa-network-wired');
        }

        Object.entries(results.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                html += this.createIOCGroup(`${type.toUpperCase()} Hashes`, Array.from(hashSet), 'fas fa-fingerprint');
            }
        });

        if (results.urls.size > 0) {
            html += this.createIOCGroup('URLs', Array.from(results.urls), 'fas fa-link');
        }

        if (results.domains.size > 0) {
            html += this.createIOCGroup('Domains', Array.from(results.domains), 'fas fa-globe');
        }

        if (!html) {
            html = `
                <div class="empty-results">
                    <i class="fas fa-search" style="font-size: 48px; color: var(--color-text-secondary); margin-bottom: 16px;"></i>
                    <p style="color: var(--color-text-secondary); text-align: center; margin: 0;">No IOCs found in the provided text.</p>
                </div>
            `;
        }

        iocsContent.innerHTML = html;
    }

    createIOCGroup(title, items, icon) {
        const itemsHtml = items.map(item => `<li class="ioc-item">${this.escapeHtml(item)}</li>`).join('');
        
        return `
            <div class="ioc-group">
                <h4 class="ioc-group-title">
                    <i class="${icon}"></i>
                    ${title}
                    <span class="ioc-count">${items.length}</span>
                </h4>
                <ul class="ioc-list">
                    ${itemsHtml}
                </ul>
            </div>
        `;
    }

    updateKQLPanel(results) {
        const kqlContent = document.getElementById('kqlContent');
        if (!kqlContent) return;

        let html = '';

        if (results.ips.size > 0) {
            html += this.createKQLGroup('IP Addresses', this.generateIPKQL(Array.from(results.ips)), 'fas fa-network-wired');
        }

        Object.entries(results.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                html += this.createKQLGroup(`${type.toUpperCase()} Hashes`, this.generateHashKQL(type, Array.from(hashSet)), 'fas fa-fingerprint');
            }
        });

        if (results.urls.size > 0) {
            html += this.createKQLGroup('URLs', this.generateURLKQL(Array.from(results.urls)), 'fas fa-link');
        }

        if (results.domains.size > 0) {
            html += this.createKQLGroup('Domains', this.generateDomainKQL(Array.from(results.domains)), 'fas fa-globe');
        }

        if (!html) {
            html = `
                <div class="empty-results">
                    <i class="fas fa-code" style="font-size: 48px; color: var(--color-text-secondary); margin-bottom: 16px;"></i>
                    <p style="color: var(--color-text-secondary); text-align: center; margin: 0;">No KQL queries generated.</p>
                </div>
            `;
        }

        kqlContent.innerHTML = html;
    }

    generateIPKQL(ips) {
        const queries = ips.map(ip => `(source.ip:"${ip}" OR destination.ip:"${ip}")`);
        return queries.length === 1 ? queries[0] : `(${queries.join(' OR ')})`;
    }

    generateHashKQL(type, hashes) {
        const fields = this.ecsMapping[type];
        const queries = hashes.map(hash => {
            const fieldQueries = fields.map(field => `${field}:"${hash}"`);
            return `(${fieldQueries.join(' OR ')})`;
        });
        return queries.length === 1 ? queries[0] : `(${queries.join(' OR ')})`;
    }

    generateURLKQL(urls) {
        const queries = urls.map(url => `url.original:"${this.escapeKQL(url)}"`);
        return queries.length === 1 ? queries[0] : `(${queries.join(' OR ')})`;
    }

    generateDomainKQL(domains) {
        const queries = domains.map(domain => `(destination.domain:"${domain}" OR source.domain:"${domain}")`);
        return queries.length === 1 ? queries[0] : `(${queries.join(' OR ')})`;
    }

    createKQLGroup(title, query, icon) {
        this.copyCounter++;
        const queryId = `kql_${this.copyCounter}`;
        
        return `
            <div class="kql-group">
                <h4 class="kql-group-title">
                    <i class="${icon}"></i>
                    ${title}
                </h4>
                <div class="kql-query">
                    <div class="kql-content" id="${queryId}">${this.escapeHtml(query)}</div>
                    <div class="kql-actions">
                        <button class="copy-btn" onclick="window.iocHunter.copyKQL('${queryId}', this)">
                            <i class="fas fa-copy"></i>
                            Copy Query
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    copyKQL(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const text = element.textContent;
        
        // Try modern clipboard API first
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                this.updateCopyButton(button);
                this.showToast('Query copied to clipboard!');
            }).catch(() => {
                this.fallbackCopy(text, button);
            });
        } else {
            this.fallbackCopy(text, button);
        }
    }

    fallbackCopy(text, button) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        textArea.style.top = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                this.updateCopyButton(button);
                this.showToast('Query copied to clipboard!');
            } else {
                this.showToast('Copy failed', 'error');
            }
        } catch (err) {
            this.showToast('Copy failed', 'error');
        }
        
        document.body.removeChild(textArea);
    }

    updateCopyButton(button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>Copied!';
        button.classList.add('copied');
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('copied');
        }, 2000);
    }

    clearInput() {
        const textarea = document.getElementById('iocInput');
        const charCount = document.getElementById('charCount');
        
        if (textarea) {
            textarea.value = '';
            textarea.style.height = '300px';
        }
        
        if (charCount) {
            charCount.textContent = '0';
        }
        
        const resultsSection = document.getElementById('resultsSection');
        const emptyState = document.getElementById('emptyState');
        
        if (resultsSection) resultsSection.classList.add('hidden');
        if (emptyState) emptyState.classList.remove('hidden');
        
        this.currentResults = null;
        this.showToast('Input cleared');
    }

    loadSample() {
        const textarea = document.getElementById('iocInput');
        const charCount = document.getElementById('charCount');
        
        if (textarea) {
            textarea.value = this.sampleText;
            
            // Trigger the input event to update character count and auto-resize
            const event = new Event('input', { bubbles: true });
            textarea.dispatchEvent(event);
        }
        
        this.showToast('Sample data loaded - Click Extract IOCs to analyze');
    }

    exportResults() {
        if (!this.currentResults) {
            this.showToast('No results to export. Please extract IOCs first.', 'error');
            return;
        }

        try {
            const timestamp = new Date().toISOString();
            const exportData = this.generateExportData(timestamp);
            
            // Create download
            const blob = new Blob([exportData], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `ioc-hunter-results-${new Date().toISOString().split('T')[0]}.txt`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            this.showToast('Results exported successfully!');
        } catch (error) {
            console.error('Export error:', error);
            this.showToast('Error exporting results', 'error');
        }
    }

    generateExportData(timestamp) {
        let exportData = `IOC Hunter - Extraction Results
===========================================
Generated: ${new Date().toLocaleString()}
Author: SOC Team Lead
Title: Cyber Security (SOC) Team Lead
Location: Jagtial, TS
Tool: IOC Hunter v2.0

===========================================
SUMMARY STATISTICS
===========================================
`;

        const totalHashes = Object.values(this.currentResults.hashes).reduce((sum, set) => sum + set.size, 0);
        const totalIOCs = this.currentResults.ips.size + totalHashes + this.currentResults.urls.size + this.currentResults.domains.size;

        exportData += `Total IOCs Found: ${totalIOCs}
- IP Addresses: ${this.currentResults.ips.size}
- File Hashes: ${totalHashes}
- URLs: ${this.currentResults.urls.size}
- Domains: ${this.currentResults.domains.size}

===========================================
EXTRACTED INDICATORS OF COMPROMISE (IOCs)
===========================================

`;

        // Export IPs
        if (this.currentResults.ips.size > 0) {
            exportData += `IP ADDRESSES (${this.currentResults.ips.size}):\n`;
            exportData += '─'.repeat(40) + '\n';
            Array.from(this.currentResults.ips).forEach((ip, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${ip}\n`;
            });
            exportData += '\n';
        }

        // Export Hashes
        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                exportData += `${type.toUpperCase()} HASHES (${hashSet.size}):\n`;
                exportData += '─'.repeat(40) + '\n';
                Array.from(hashSet).forEach((hash, index) => {
                    exportData += `${(index + 1).toString().padStart(3)}. ${hash}\n`;
                });
                exportData += '\n';
            }
        });

        // Export URLs
        if (this.currentResults.urls.size > 0) {
            exportData += `URLS (${this.currentResults.urls.size}):\n`;
            exportData += '─'.repeat(40) + '\n';
            Array.from(this.currentResults.urls).forEach((url, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${url}\n`;
            });
            exportData += '\n';
        }

        // Export Domains
        if (this.currentResults.domains.size > 0) {
            exportData += `DOMAINS (${this.currentResults.domains.size}):\n`;
            exportData += '─'.repeat(40) + '\n';
            Array.from(this.currentResults.domains).forEach((domain, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${domain}\n`;
            });
            exportData += '\n';
        }

        exportData += `===========================================
GENERATED KQL QUERIES (ECS FIELDS)
===========================================

`;

        // Export KQL queries
        if (this.currentResults.ips.size > 0) {
            exportData += `IP ADDRESSES KQL:\n`;
            exportData += `${this.generateIPKQL(Array.from(this.currentResults.ips))}\n\n`;
        }

        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                exportData += `${type.toUpperCase()} HASHES KQL:\n`;
                exportData += `${this.generateHashKQL(type, Array.from(hashSet))}\n\n`;
            }
        });

        if (this.currentResults.urls.size > 0) {
            exportData += `URLS KQL:\n`;
            exportData += `${this.generateURLKQL(Array.from(this.currentResults.urls))}\n\n`;
        }

        if (this.currentResults.domains.size > 0) {
            exportData += `DOMAINS KQL:\n`;
            exportData += `${this.generateDomainKQL(Array.from(this.currentResults.domains))}\n\n`;
        }

        exportData += `===========================================
NOTES
===========================================
- All queries use Elastic Common Schema (ECS) field mappings
- Test queries in your environment before production use
- Consider adding time ranges and additional filters as needed
- For questions or support, contact the SOC Team

Generated by IOC Hunter v2.0
Author: SOC Team Lead, Cyber Security (SOC) Team Lead
Location: Jagtial, TS
Bio: Specialized in threat hunting, malware analysis, and security operations
===========================================`;

        return exportData;
    }

    showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = toast?.querySelector('.toast-icon');
        
        if (toast && toastMessage) {
            toastMessage.textContent = message;
            
            // Set icon based on type
            if (toastIcon) {
                toastIcon.className = `toast-icon fas ${type === 'error' ? 'fa-exclamation-triangle' : 'fa-check-circle'}`;
            }
            
            toast.className = `toast ${type} show`;

            setTimeout(() => {
                toast.classList.remove('show');
            }, 4000);
        }
    }

    updateUI() {
        const resultsSection = document.getElementById('resultsSection');
        const emptyState = document.getElementById('emptyState');
        
        if (resultsSection) resultsSection.classList.add('hidden');
        if (emptyState) emptyState.classList.remove('hidden');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    escapeKQL(text) {
        return text.replace(/[\\:"()]/g, '\\$&');
    }
}

// Initialize the application - using consistent naming
window.iocHunter = new ModernIOCHunter();
window.iocHunter.init();
