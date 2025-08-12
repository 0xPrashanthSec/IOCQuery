// Modern IOC Hunter Multi-SIEM Application
class MultiSIEMIOCHunter {
    constructor() {
        // Regex patterns for IOC extraction
        this.patterns = {
            ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
            md5: /\b[a-fA-F0-9]{32}\b/g,
            sha1: /\b[a-fA-F0-9]{40}\b/g,
            sha256: /\b[a-fA-F0-9]{64}\b/g,
            sha512: /\b[a-fA-F0-9]{128}\b/g,
            url: /https?:\/\/[^\s<>"']+/g,
            domain: /\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b/g
        };

        // SIEM platform mappings
        // Replace this entire siemMappings object in app.js
this.siemMappings = {
    "Elastic SIEM": {
        "language": "KQL",
        "field_mappings": {
            "ipv4": {
                "fields": ["source.ip", "destination.ip", "client.ip", "server.ip"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "md5": {
                "fields": ["file.hash.md5", "process.hash.md5", "file.pe.imphash"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "sha1": {
                "fields": ["file.hash.sha1", "process.hash.sha1"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "sha256": {
                "fields": ["file.hash.sha256", "process.hash.sha256"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "sha512": {
                "fields": ["file.hash.sha512", "process.hash.sha512"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "url": {
                "fields": ["url.original", "url.full", "http.request.url"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            },
            "domain": {
                "fields": ["destination.domain", "source.domain", "dns.question.name"],
                "template": "{field}:\"{value}\"",
                "combine_operator": " OR "
            }
        }
    },
    
    "Microsoft Sentinel": {
        "language": "KQL",
        "field_mappings": {
            "ipv4": {
                "fields": ["SrcIpAddr", "DstIpAddr", "ClientIP", "RemoteIP"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "md5": {
                "fields": ["InitiatingProcessMD5", "FileHash", "Hash"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "sha1": {
                "fields": ["InitiatingProcessSHA1", "FileHash", "Hash"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "sha256": {
                "fields": ["InitiatingProcessSHA256", "FileHash", "Hash"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "sha512": {
                "fields": ["FileHash", "Hash"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "url": {
                "fields": ["Url", "RequestURL", "UrlOriginal"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            },
            "domain": {
                "fields": ["DnsQuery", "RemoteDomain", "RequestDomain"],
                "template": "{field} == \"{value}\"",
                "combine_operator": " or "
            }
        }
    },
    
    "IBM QRadar": {
        "language": "AQL",
        "field_mappings": {
            "ipv4": {
                "fields": ["sourceip", "destinationip"],
                "template": "{field} = '{value}'",
                "combine_operator": " OR "
            },
            "md5": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            },
            "sha1": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            },
            "sha256": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            },
            "sha512": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            },
            "url": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            },
            "domain": {
                "fields": ["TEXT SEARCH"],
                "template": "TEXT SEARCH = '{value}'",
                "combine_operator": " OR "
            }
        }
    },
    
    "Splunk": {
        "language": "SPL",
        "field_mappings": {
            "ipv4": {
                "fields": ["src_ip", "dest_ip", "src", "dest"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "md5": {
                "fields": ["file_hash", "hash", "md5"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "sha1": {
                "fields": ["file_hash", "hash", "sha1"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "sha256": {
                "fields": ["file_hash", "hash", "sha256"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "sha512": {
                "fields": ["file_hash", "hash", "sha512"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "url": {
                "fields": ["url", "uri", "request_url"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            },
            "domain": {
                "fields": ["domain", "dest_domain", "dns_query"],
                "template": "{field}=\"{value}\"",
                "combine_operator": " OR "
            }
        }
    },
    
    "ArcSight": {
        "language": "CEF",
        "field_mappings": {
            "ipv4": {
                "fields": ["sourceAddress", "destinationAddress"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "md5": {
                "fields": ["fileHash", "oldFileHash"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "sha1": {
                "fields": ["fileHash", "oldFileHash"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "sha256": {
                "fields": ["fileHash", "oldFileHash"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "sha512": {
                "fields": ["fileHash", "oldFileHash"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "url": {
                "fields": ["requestURL", "request"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            },
            "domain": {
                "fields": ["destinationDnsDomain", "sourceDnsDomain"],
                "template": "{field} = \"{value}\"",
                "combine_operator": " OR "
            }
        }
    }
};


        this.sampleText = `Threat Report: APT29 Campaign Analysis

The following indicators of compromise (IOCs) were identified during our investigation:

IP Addresses:
- 192.168.1.100 (C2 server)
- 10.0.0.25 (infected host)
- 203.0.113.45 (exfiltration server)
- 198.51.100.42 (beacon server)

File Hashes:
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
SHA512: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043

URLs:
- https://malicious-domain.com/payload.exe
- http://evil-site.org/data-exfil
- https://c2-server.net/beacon
- https://apt29-infrastructure.com/command

Domains:
- malicious-domain.com
- evil-site.org
- c2-server.net
- apt29-infrastructure.com`;

        this.currentResults = null;
        this.currentPlatform = 'Elastic SIEM';
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
        this.updatePlatformUI();
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

        // SIEM platform selector
        const siemSelect = document.getElementById('siemSelect');
        if (siemSelect) {
            siemSelect.addEventListener('change', (e) => {
                this.currentPlatform = e.target.value;
                this.updatePlatformUI();
                if (this.currentResults) {
                    this.regenerateQueries();
                }
            });
        }

        // Export buttons
        const bulkCopyBtn = document.getElementById('bulkCopyBtn');
        if (bulkCopyBtn) {
            bulkCopyBtn.addEventListener('click', () => this.bulkCopyQueries());
        }

        const exportTxtBtn = document.getElementById('exportTxtBtn');
        if (exportTxtBtn) {
            exportTxtBtn.addEventListener('click', () => this.exportTxt());
        }

        const exportJsonBtn = document.getElementById('exportJsonBtn');
        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => this.exportJson());
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
            const updateTextarea = () => {
                charCount.textContent = textarea.value.length.toLocaleString();
                textarea.style.height = 'auto';
                textarea.style.height = Math.max(300, textarea.scrollHeight) + 'px';
            };

            textarea.addEventListener('input', updateTextarea);
            textarea.addEventListener('paste', () => setTimeout(updateTextarea, 10));
            charCount.textContent = '0';
        }
    }

    updatePlatformUI() {
        const queryLanguage = document.getElementById('queryLanguage');
        const platformBadge = document.getElementById('platformBadge');
        
        if (queryLanguage && this.siemMappings[this.currentPlatform]) {
            queryLanguage.textContent = this.siemMappings[this.currentPlatform].language;
        }
        
        if (platformBadge) {
            platformBadge.textContent = this.currentPlatform;
        }
    }

    extractIOCs() {
        const textarea = document.getElementById('iocInput');
        if (!textarea) {
            this.showToast('Input field not found', 'error');
            return;
        }

        const input = textarea.value;
        
        if (!input || input.trim().length === 0) {
            this.showToast('Please enter some text to analyze', 'error');
            return;
        }

        const extractBtn = document.getElementById('extractBtn');
        const originalHtml = extractBtn ? extractBtn.innerHTML : '';

        try {
            if (extractBtn) {
                extractBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Processing...</span>';
                extractBtn.disabled = true;
                extractBtn.classList.add('loading');
            }

            // Small delay to show loading state
            setTimeout(() => {
                try {
                    const results = this.analyzeText(input);
                    console.log('Analyzed results:', results);
                    this.currentResults = results;
                    this.displayResults(results);
                    this.showToast('IOCs extracted successfully!');
                } catch (error) {
                    console.error('Error during analysis:', error);
                    this.showToast('Error during IOC extraction: ' + error.message, 'error');
                } finally {
                    if (extractBtn) {
                        extractBtn.innerHTML = originalHtml;
                        extractBtn.disabled = false;
                        extractBtn.classList.remove('loading');
                    }
                }
            }, 500);
            
        } catch (error) {
            console.error('Error during IOC extraction:', error);
            this.showToast('Error during IOC extraction: ' + error.message, 'error');
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

            console.log('Final analysis results:', {
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
        
        const isCommon = commonDomains.some(common => domain.includes(common));
        const isTooShort = domain.length < 4;
        const hasValidTLD = /\.[a-zA-Z]{2,}$/.test(domain);
        
        return isCommon || isTooShort || !hasValidTLD;
    }

    buildPlatformQuery(iocType, values, platformConfig) {
        if (!values || values.length === 0) return '';
        
        const fieldMapping = platformConfig.field_mappings[iocType];
        if (!fieldMapping) return '';
        
        const { fields, template, combine_operator } = fieldMapping;
        
        // Build queries for each value
        const valueQueries = values.map(value => {
            const fieldQueries = fields.map(field => {
                return template
                    .replace('{field}', field)
                    .replace('{value}', this.escapeQueryValue(value, platformConfig.language));
            });
            
            return fieldQueries.length === 1 
                ? fieldQueries[0] 
                : `(${fieldQueries.join(combine_operator)})`;
        });
        
        // Combine all value queries
        return valueQueries.length === 1 
            ? valueQueries[0] 
            : `(${valueQueries.join(' OR ')})`;
    }

    escapeQueryValue(value, language) {
        switch (language) {
            case 'KQL':
                return value.replace(/[\\:"()]/g, '\\$&');
            case 'SPL':
                return value.replace(/[\\:"]/g, '\\$&');
            case 'AQL':
                return value.replace(/'/g, "''");
            case 'CEF':
                return value.replace(/[\\:"]/g, '\\$&');
            default:
                return value;
        }
    }

    regenerateQueries() {
        if (!this.currentResults) return;
        
        console.log('Regenerating queries for platform:', this.currentPlatform);
        this.updatePlatformUI();
        this.updateQueriesPanel(this.currentResults);
        this.showToast(`Queries updated for ${this.currentPlatform}!`);
    }

    displayResults(results) {
        try {
            console.log('Displaying results:', results);
            
            const resultsSection = document.getElementById('resultsSection');
            const emptyState = document.getElementById('emptyState');

            console.log('Found elements:', { resultsSection: !!resultsSection, emptyState: !!emptyState });

            if (resultsSection && emptyState) {
                resultsSection.classList.remove('hidden');
                emptyState.classList.add('hidden');
                console.log('Toggled visibility');
            }

            this.updateStatsCards(results);
            this.updateIOCsPanel(results);
            this.updateQueriesPanel(results);
            
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
        console.log('Updating stats cards, element found:', !!statsCards);
        
        if (!statsCards) return;

        const totalHashes = Object.values(results.hashes).reduce((sum, set) => sum + set.size, 0);
        console.log('Stats:', {
            ips: results.ips.size,
            hashes: totalHashes,
            urls: results.urls.size,
            domains: results.domains.size
        });

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
        console.log('Stats cards updated');
    }

    updateIOCsPanel(results) {
        const iocsContent = document.getElementById('iocsContent');
        console.log('Updating IOCs panel, element found:', !!iocsContent);
        
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
        console.log('IOCs panel updated');
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

    updateQueriesPanel(results) {
        const queriesContent = document.getElementById('queriesContent');
        console.log('Updating queries panel, element found:', !!queriesContent);
        
        if (!queriesContent) return;

        const platformConfig = this.siemMappings[this.currentPlatform];
        console.log('Platform config:', this.currentPlatform, platformConfig);
        
        let html = '';

        if (results.ips.size > 0) {
            const query = this.buildPlatformQuery('ipv4', Array.from(results.ips), platformConfig);
            console.log('Generated IP query:', query);
            html += this.createQueryGroup('IP Addresses', query, 'fas fa-network-wired');
        }

        Object.entries(results.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                const query = this.buildPlatformQuery(type, Array.from(hashSet), platformConfig);
                console.log(`Generated ${type} query:`, query);
                html += this.createQueryGroup(`${type.toUpperCase()} Hashes`, query, 'fas fa-fingerprint');
            }
        });

        if (results.urls.size > 0) {
            const query = this.buildPlatformQuery('url', Array.from(results.urls), platformConfig);
            console.log('Generated URL query:', query);
            html += this.createQueryGroup('URLs', query, 'fas fa-link');
        }

        if (results.domains.size > 0) {
            const query = this.buildPlatformQuery('domain', Array.from(results.domains), platformConfig);
            console.log('Generated domain query:', query);
            html += this.createQueryGroup('Domains', query, 'fas fa-globe');
        }

        if (!html) {
            html = `
                <div class="empty-results">
                    <i class="fas fa-code" style="font-size: 48px; color: var(--color-text-secondary); margin-bottom: 16px;"></i>
                    <p style="color: var(--color-text-secondary); text-align: center; margin: 0;">No queries generated.</p>
                </div>
            `;
        }

        queriesContent.innerHTML = html;
        console.log('Queries panel updated with HTML length:', html.length);
    }

    createQueryGroup(title, query, icon) {
        this.copyCounter++;
        const queryId = `query_${this.copyCounter}`;
        
        return `
            <div class="query-group">
                <h4 class="query-group-title">
                    <i class="${icon}"></i>
                    ${title}
                </h4>
                <div class="query-block">
                    <div class="query-content" id="${queryId}">${this.escapeHtml(query)}</div>
                    <div class="query-actions">
                        <button class="copy-btn" onclick="window.multiSiemIOCHunter.copyQuery('${queryId}', this)">
                            <i class="fas fa-copy"></i>
                            Copy Query
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    copyQuery(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const text = element.textContent;
        
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

    bulkCopyQueries() {
        if (!this.currentResults) {
            this.showToast('No queries to copy. Please extract IOCs first.', 'error');
            return;
        }

        const queries = this.getAllQueries();
        const allQueriesText = queries.join('\n\n');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(allQueriesText).then(() => {
                this.showToast(`All ${queries.length} queries copied to clipboard!`);
            }).catch(() => {
                this.fallbackBulkCopy(allQueriesText);
            });
        } else {
            this.fallbackBulkCopy(allQueriesText);
        }
    }

    fallbackBulkCopy(text) {
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
                this.showToast('All queries copied to clipboard!');
            } else {
                this.showToast('Bulk copy failed', 'error');
            }
        } catch (err) {
            this.showToast('Bulk copy failed', 'error');
        }
        
        document.body.removeChild(textArea);
    }

    getAllQueries() {
        if (!this.currentResults) return [];

        const platformConfig = this.siemMappings[this.currentPlatform];
        const queries = [];

        if (this.currentResults.ips.size > 0) {
            queries.push(this.buildPlatformQuery('ipv4', Array.from(this.currentResults.ips), platformConfig));
        }

        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                queries.push(this.buildPlatformQuery(type, Array.from(hashSet), platformConfig));
            }
        });

        if (this.currentResults.urls.size > 0) {
            queries.push(this.buildPlatformQuery('url', Array.from(this.currentResults.urls), platformConfig));
        }

        if (this.currentResults.domains.size > 0) {
            queries.push(this.buildPlatformQuery('domain', Array.from(this.currentResults.domains), platformConfig));
        }

        return queries;
    }

    exportTxt() {
        if (!this.currentResults) {
            this.showToast('No results to export. Please extract IOCs first.', 'error');
            return;
        }

        try {
            const exportData = this.generateTxtExport();
            this.downloadFile(exportData, 'text/plain', `ioc-hunter-${this.currentPlatform.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}.txt`);
            this.showToast('TXT export completed successfully!');
        } catch (error) {
            console.error('Export error:', error);
            this.showToast('Error exporting TXT file', 'error');
        }
    }

    exportJson() {
        if (!this.currentResults) {
            this.showToast('No results to export. Please extract IOCs first.', 'error');
            return;
        }

        try {
            const exportData = this.generateJsonExport();
            this.downloadFile(exportData, 'application/json', `ioc-hunter-${this.currentPlatform.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}.json`);
            this.showToast('JSON export completed successfully!');
        } catch (error) {
            console.error('Export error:', error);
            this.showToast('Error exporting JSON file', 'error');
        }
    }

    generateTxtExport() {
        const timestamp = new Date().toISOString();
        const totalHashes = Object.values(this.currentResults.hashes).reduce((sum, set) => sum + set.size, 0);
        const totalIOCs = this.currentResults.ips.size + totalHashes + this.currentResults.urls.size + this.currentResults.domains.size;

        let exportData = `IOC Hunter – Multi-SIEM Export
===============================================
Generated: ${new Date().toLocaleString()}
Platform: ${this.currentPlatform}
Query Language: ${this.siemMappings[this.currentPlatform].language}
Author: SOC Team Lead
Title: Cyber Security (SOC) Team Lead
Location: Jagtial, TS
Tool: IOC Hunter Multi-SIEM v3.0

===============================================
SUMMARY STATISTICS
===============================================
Total IOCs Found: ${totalIOCs}
- IP Addresses: ${this.currentResults.ips.size}
- File Hashes: ${totalHashes}
- URLs: ${this.currentResults.urls.size}
- Domains: ${this.currentResults.domains.size}

===============================================
GENERATED QUERIES (${this.siemMappings[this.currentPlatform].language})
===============================================

`;

        const queries = this.getAllQueries();
        const types = [];
        
        if (this.currentResults.ips.size > 0) types.push('IP Addresses');
        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) types.push(`${type.toUpperCase()} Hashes`);
        });
        if (this.currentResults.urls.size > 0) types.push('URLs');
        if (this.currentResults.domains.size > 0) types.push('Domains');

        queries.forEach((query, index) => {
            exportData += `${types[index]}:\n`;
            exportData += `${'-'.repeat(40)}\n`;
            exportData += `${query}\n\n`;
        });

        exportData += `===============================================
EXTRACTED INDICATORS OF COMPROMISE (IOCs)
===============================================

`;

        // Export IOCs
        if (this.currentResults.ips.size > 0) {
            exportData += `IP ADDRESSES (${this.currentResults.ips.size}):\n`;
            exportData += `${'-'.repeat(40)}\n`;
            Array.from(this.currentResults.ips).forEach((ip, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${ip}\n`;
            });
            exportData += '\n';
        }

        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) {
                exportData += `${type.toUpperCase()} HASHES (${hashSet.size}):\n`;
                exportData += `${'-'.repeat(40)}\n`;
                Array.from(hashSet).forEach((hash, index) => {
                    exportData += `${(index + 1).toString().padStart(3)}. ${hash}\n`;
                });
                exportData += '\n';
            }
        });

        if (this.currentResults.urls.size > 0) {
            exportData += `URLS (${this.currentResults.urls.size}):\n`;
            exportData += `${'-'.repeat(40)}\n`;
            Array.from(this.currentResults.urls).forEach((url, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${url}\n`;
            });
            exportData += '\n';
        }

        if (this.currentResults.domains.size > 0) {
            exportData += `DOMAINS (${this.currentResults.domains.size}):\n`;
            exportData += `${'-'.repeat(40)}\n`;
            Array.from(this.currentResults.domains).forEach((domain, index) => {
                exportData += `${(index + 1).toString().padStart(3)}. ${domain}\n`;
            });
            exportData += '\n';
        }

        exportData += `===============================================
NOTES
===============================================
- Queries generated for ${this.currentPlatform} platform
- Test queries in your environment before production use
- Consider adding time ranges and additional filters as needed
- For questions or support, contact the SOC Team

Generated by IOC Hunter Multi-SIEM v3.0
Author: SOC Team Lead, Cyber Security (SOC) Team Lead
Location: Jagtial, TS
Bio: Specialized in threat hunting, malware analysis, and security operations
===============================================`;

        return exportData;
    }

    generateJsonExport() {
        const queries = this.getAllQueries();
        const queryTypes = [];
        
        if (this.currentResults.ips.size > 0) queryTypes.push('ip_addresses');
        Object.entries(this.currentResults.hashes).forEach(([type, hashSet]) => {
            if (hashSet.size > 0) queryTypes.push(`${type}_hashes`);
        });
        if (this.currentResults.urls.size > 0) queryTypes.push('urls');
        if (this.currentResults.domains.size > 0) queryTypes.push('domains');

        const queriesObject = {};
        queries.forEach((query, index) => {
            queriesObject[queryTypes[index]] = query;
        });

        const exportData = {
            metadata: {
                generated_at: new Date().toISOString(),
                generator: "IOC Hunter Multi-SIEM v3.0",
                platform: this.currentPlatform,
                query_language: this.siemMappings[this.currentPlatform].language,
                author: {
                    name: "SOC Team Lead",
                    title: "Cyber Security (SOC) Team Lead",
                    location: "Jagtial, TS"
                }
            },
            statistics: {
                total_iocs: this.currentResults.ips.size + 
                           Object.values(this.currentResults.hashes).reduce((sum, set) => sum + set.size, 0) +
                           this.currentResults.urls.size + 
                           this.currentResults.domains.size,
                ip_addresses: this.currentResults.ips.size,
                file_hashes: Object.values(this.currentResults.hashes).reduce((sum, set) => sum + set.size, 0),
                urls: this.currentResults.urls.size,
                domains: this.currentResults.domains.size
            },
            iocs: {
                ip_addresses: Array.from(this.currentResults.ips),
                hashes: Object.fromEntries(
                    Object.entries(this.currentResults.hashes).map(([k, v]) => [k, Array.from(v)])
                ),
                urls: Array.from(this.currentResults.urls),
                domains: Array.from(this.currentResults.domains)
            },
            queries: queriesObject
        };

        return JSON.stringify(exportData, null, 2);
    }

    downloadFile(content, mimeType, filename) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
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
        
        if (textarea) {
            textarea.value = this.sampleText;
            
            const event = new Event('input', { bubbles: true });
            textarea.dispatchEvent(event);
        }
        
        this.showToast('Sample data loaded - Click Extract IOCs to analyze');
    }

    showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = toast?.querySelector('.toast-icon');
        
        if (toast && toastMessage) {
            toastMessage.textContent = message;
            
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
}

// Initialize the application
window.multiSiemIOCHunter = new MultiSIEMIOCHunter();
window.multiSiemIOCHunter.init();