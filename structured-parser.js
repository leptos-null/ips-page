// IPS Crash Report Structured Parser
class StructuredIPSParser {
    constructor(ipsContent) {
        this.ipsContent = ipsContent;
        this.metadata = null;
        this.report = null;
    }

    parse() {
        try {
            const lines = this.ipsContent.trim().split('\n');

            if (lines.length < 2) {
                throw new Error('Invalid IPS file format. Expected at least 2 lines (metadata + report).');
            }

            // Parse metadata (first line)
            this.metadata = JSON.parse(lines[0]);

            // Parse crash report (remaining lines)
            const reportLines = lines.slice(1).join('\n');
            this.report = JSON.parse(reportLines);

            // Verify it's a crash report
            if (this.metadata.bug_type !== "309") {
                throw new Error(`Not a crash report (bug_type: ${this.metadata.bug_type}). Expected bug_type "309".`);
            }

            return true;
        } catch (error) {
            throw new Error(`Failed to parse IPS file: ${error.message}`);
        }
    }

    formatAddress(addr) {
        return `<span class="addr">0x${addr.toString(16).padStart(16, '0')}</span>`;
    }

    formatNumber(num) {
        return `<span class="number">${num}</span>`;
    }

    formatSymbol(sym) {
        return `<span class="symbol">${this.escapeHtml(sym)}</span>`;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatReport() {
        if (!this.metadata || !this.report) {
            throw new Error('Report not parsed. Call parse() first.');
        }

        let sections = [];

        // Process Information
        sections.push(this.formatProcessInfo());

        // Exception Information
        sections.push(this.formatException());

        // Application Specific Information
        if (this.report.asi) {
            sections.push(this.formatASI());
        }

        // Last Exception Backtrace
        if (this.report.lastExceptionBacktrace) {
            sections.push(this.formatLastExceptionBacktrace());
        }

        // Threads
        sections.push(this.formatThreads());

        // Binary Images
        sections.push(this.formatBinaryImages());

        // VM Summary
        if (this.report.vmSummary) {
            sections.push(this.formatVMSummary());
        }

        return sections.join('\n');
    }

    formatProcessInfo() {
        const b = this.report.bundleInfo || {};
        const os = this.report.osVersion || {};

        let html = '<div class="crash-section">';
        html += '<details open>';
        html += '<summary>Process Information</summary>';
        html += '<div class="info-grid">';

        html += `<div class="info-label">Process:</div>`;
        html += `<div class="info-value">${this.escapeHtml(this.report.procName || 'Unknown')} [${this.formatNumber(this.report.pid || 0)}]</div>`;

        html += `<div class="info-label">Path:</div>`;
        html += `<div class="info-value">${this.escapeHtml(this.report.procPath || 'Unknown')}</div>`;

        html += `<div class="info-label">Identifier:</div>`;
        html += `<div class="info-value">${this.escapeHtml(b.CFBundleIdentifier || 'Unknown')}</div>`;

        html += `<div class="info-label">Version:</div>`;
        html += `<div class="info-value">${this.escapeHtml(b.CFBundleShortVersionString || '?')} (${this.escapeHtml(b.CFBundleVersion || '?')})</div>`;

        html += `<div class="info-label">Code Type:</div>`;
        html += `<div class="info-value">${this.escapeHtml(this.report.cpuType || 'Unknown')}</div>`;

        if (this.report.procRole) {
            html += `<div class="info-label">Role:</div>`;
            html += `<div class="info-value">${this.escapeHtml(this.report.procRole)}</div>`;
        }

        html += `<div class="info-label">Parent Process:</div>`;
        html += `<div class="info-value">${this.escapeHtml(this.report.parentProc || 'Unknown')} [${this.formatNumber(this.report.parentPid || 0)}]</div>`;

        if (this.report.coalitionName) {
            html += `<div class="info-label">Coalition:</div>`;
            html += `<div class="info-value">${this.escapeHtml(this.report.coalitionName)} [${this.formatNumber(this.report.coalitionID || 0)}]</div>`;
        }

        html += `<div class="info-label">Date/Time:</div>`;
        html += `<div class="info-value">${this.escapeHtml(this.report.captureTime || 'Unknown')}</div>`;

        if (this.report.procLaunch) {
            html += `<div class="info-label">Launch Time:</div>`;
            html += `<div class="info-value">${this.escapeHtml(this.report.procLaunch)}</div>`;
        }

        if (this.report.modelCode) {
            html += `<div class="info-label">Hardware Model:</div>`;
            html += `<div class="info-value">${this.escapeHtml(this.report.modelCode)}</div>`;
        }

        html += `<div class="info-label">OS Version:</div>`;
        html += `<div class="info-value">${this.escapeHtml(os.train || 'Unknown')} (${this.escapeHtml(os.build || 'Unknown')})</div>`;

        if (os.releaseType) {
            html += `<div class="info-label">Release Type:</div>`;
            html += `<div class="info-value">${this.escapeHtml(os.releaseType)}</div>`;
        }

        if (this.report.incident) {
            html += `<div class="info-label">Incident ID:</div>`;
            html += `<div class="info-value">${this.escapeHtml(this.report.incident)}</div>`;
        }

        if (this.report.uptime !== undefined) {
            html += `<div class="info-label">Uptime:</div>`;
            html += `<div class="info-value">${this.formatNumber(this.report.uptime)} seconds</div>`;
        }

        html += '</div></details></div>';
        return html;
    }

    formatException() {
        const ex = this.report.exception || {};
        const term = this.report.termination;

        let html = '<div class="crash-section">';
        html += '<details open>';
        html += '<summary>Exception Information</summary>';
        html += '<div class="exception-info">';

        html += `<div class="exception-type">`;
        html += this.escapeHtml(ex.type || 'Unknown');
        if (ex.signal) {
            html += ` (${this.escapeHtml(ex.signal)})`;
        }
        html += '</div>';

        if (ex.codes) {
            html += `<div class="exception-detail">Codes: ${this.escapeHtml(ex.codes)}</div>`;
        }

        if (ex.message) {
            html += `<div class="exception-detail">Message: ${this.escapeHtml(ex.message)}</div>`;
        }

        if (term) {
            html += `<div class="exception-detail" style="margin-top: 10px;">`;
            html += `Termination: Namespace ${this.escapeHtml(term.namespace || 'Unknown')}, Code ${this.formatNumber(term.code || 0)}`;
            if (term.indicator) {
                html += `, ${this.escapeHtml(term.indicator)}`;
            }
            html += '</div>';

            if (term.byProc) {
                html += `<div class="exception-detail">Terminating Process: ${this.escapeHtml(term.byProc)} [${this.formatNumber(term.byPid || 0)}]</div>`;
            }
        }

        if (this.report.faultingThread !== undefined) {
            html += `<div class="exception-detail" style="margin-top: 10px;">Faulting Thread: ${this.formatNumber(this.report.faultingThread)}</div>`;
        }

        html += '</div></details></div>';
        return html;
    }

    formatASI() {
        let html = '<div class="crash-section">';
        html += '<details open>';
        html += '<summary>Application Specific Information</summary>';
        html += '<div class="info-grid">';

        for (const [key, value] of Object.entries(this.report.asi)) {
            if (Array.isArray(value)) {
                value.forEach(v => {
                    html += `<div class="info-label">${this.escapeHtml(key)}:</div>`;
                    html += `<div class="info-value">${this.escapeHtml(v)}</div>`;
                });
            } else {
                html += `<div class="info-label">${this.escapeHtml(key)}:</div>`;
                html += `<div class="info-value">${this.escapeHtml(value)}</div>`;
            }
        }

        html += '</div></details></div>';
        return html;
    }

    formatLastExceptionBacktrace() {
        const backtrace = this.report.lastExceptionBacktrace;
        if (!backtrace || backtrace.length === 0) return '';

        let html = '<div class="crash-section">';
        html += '<details>';
        html += '<summary>Last Exception Backtrace</summary>';
        html += '<div style="margin-top: 15px;">';

        backtrace.forEach((frame, index) => {
            const imageInfo = this.report.usedImages[frame.imageIndex];
            const imageName = imageInfo ? imageInfo.name : 'Unknown';
            const address = (imageInfo?.base || 0) + frame.imageOffset;

            html += '<div class="stack-frame">';
            html += `<div class="frame-index">${index}</div>`;
            html += `<div class="frame-image">${this.escapeHtml(imageName)}</div>`;
            html += '<div class="frame-details">';
            html += this.formatAddress(address);

            if (frame.symbol) {
                html += ` ${this.formatSymbol(frame.symbol)}`;
                if (frame.symbolLocation !== undefined) {
                    html += ` <span class="offset">+ ${this.formatNumber(frame.symbolLocation)}</span>`;
                }
            }

            html += '</div></div>';
        });

        html += '</div></details></div>';
        return html;
    }

    formatThreads() {
        const threads = this.report.threads || [];

        let html = '<div class="crash-section">';
        html += '<details open>';
        html += '<summary>Threads</summary>';
        html += '<div class="thread-list">';

        threads.forEach((thread) => {
            const isCrashed = thread.triggered;

            html += `<div class="thread-item ${isCrashed ? 'crashed' : ''}">`;
            html += '<details>';

            let summary = `Thread ${this.formatNumber(thread.id)}`;
            if (thread.name) {
                summary += ` - ${this.escapeHtml(thread.name)}`;
            }
            if (isCrashed) {
                summary += ' ⚠️ CRASHED';
            }

            html += `<summary class="thread-header">${summary}</summary>`;

            // Stack frames
            if (thread.frames && thread.frames.length > 0) {
                html += '<div style="margin-top: 10px;">';
                thread.frames.forEach((frame, index) => {
                    const imageInfo = this.report.usedImages[frame.imageIndex];
                    const imageName = imageInfo ? imageInfo.name : 'Unknown';
                    const address = (imageInfo?.base || 0) + frame.imageOffset;

                    html += '<div class="stack-frame">';
                    html += `<div class="frame-index">${index}</div>`;
                    html += `<div class="frame-image">${this.escapeHtml(imageName)}</div>`;
                    html += '<div class="frame-details">';
                    html += this.formatAddress(address);

                    if (frame.symbol) {
                        html += ` ${this.formatSymbol(frame.symbol)}`;
                        if (frame.symbolLocation !== undefined) {
                            html += ` <span class="offset">+ ${this.formatNumber(frame.symbolLocation)}</span>`;
                        }
                    }

                    html += '</div></div>';
                });
                html += '</div>';
            }

            // Thread state for crashed thread
            if (isCrashed && thread.threadState) {
                html += this.formatThreadState(thread.threadState);
            }

            html += '</details></div>';
        });

        html += '</div></details></div>';
        return html;
    }

    formatThreadState(state) {
        if (!state) return '';

        let html = '<div style="margin-top: 15px;">';
        html += '<h4 style="margin-bottom: 10px; color: #555;">Register State</h4>';
        html += '<div class="registers">';

        let registers = [];

        if (state.x) {
            for (let i = 0; i < state.x.length; i++) {
                registers.push({
                    name: 'x' + i,
                    object: state.x[i]
                });
            }
        }
        if (state.fp) registers.push({ name: 'fp', object: state.fp });
        if (state.lr) registers.push({ name: 'lr', object: state.lr });
        if (state.sp) registers.push({ name: 'sp', object: state.sp });
        if (state.pc) registers.push({ name: 'pc', object: state.pc });
        if (state.cpsr) registers.push({ name: 'cpsr', object: state.cpsr });
        if (state.far) registers.push({ name: 'far', object: state.far });
        if (state.esr) registers.push({ name: 'esr', object: state.esr });

        registers.forEach(reg => {
            const value = reg.object.value || 0;
            html += '<div class="register">';
            html += `<div class="register-name">${this.escapeHtml(reg.name)}:</div>`;
            html += `<div class="register-value">0x${value.toString(16).padStart(16, '0')}</div>`;
            if (reg.object.description) {
                html += `<div class="register-desc">${this.escapeHtml(reg.object.description)}</div>`;
            }
            html += '</div>';
        });

        html += '</div></div>';
        return html;
    }

    formatBinaryImages() {
        const images = this.report.usedImages || [];

        let html = '<div class="crash-section">';
        html += '<details>';
        html += '<summary>Binary Images</summary>';
        html += '<div style="margin-top: 15px;">';

        images.forEach((image) => {
            if (image.size === 0) return;

            const base = image.base || 0;
            const end = base + (image.size || 0) - 1;

            html += '<div class="binary-image">';
            html += `<div class="image-range">${this.formatAddress(base)} - ${this.formatAddress(end)}</div>`;
            html += `<div class="image-name">${this.escapeHtml(image.name || '???')}</div>`;
            html += `<div class="image-details">`;
            html += `${this.escapeHtml(image.arch || 'unknown')} `;
            html += `&lt;${this.escapeHtml(image.uuid || '')}&gt; `;
            html += `${this.escapeHtml(image.path || '???')}`;
            html += '</div></div>';
        });

        html += '</div></details></div>';
        return html;
    }

    formatVMSummary() {
        let html = '<div class="crash-section">';
        html += '<details>';
        html += '<summary>VM Region Summary</summary>';
        html += `<div class="vm-summary">${this.escapeHtml(this.report.vmSummary)}</div>`;
        html += '</details></div>';
        return html;
    }
}

// UI Controller
document.addEventListener('DOMContentLoaded', () => {
    const ipsInput = document.getElementById('ipsInput');
    const parseBtn = document.getElementById('parseBtn');
    const clearBtn = document.getElementById('clearBtn');
    const expandAllBtn = document.getElementById('expandAllBtn');
    const collapseAllBtn = document.getElementById('collapseAllBtn');
    const errorMessage = document.getElementById('errorMessage');
    const outputSection = document.getElementById('output');
    const reportOutput = document.getElementById('reportOutput');

    parseBtn.addEventListener('click', () => {
        const content = ipsInput.value.trim();

        if (!content) {
            showError('Please paste IPS file contents first.');
            return;
        }

        try {
            const parser = new StructuredIPSParser(content);
            parser.parse();
            const formatted = parser.formatReport();

            reportOutput.innerHTML = formatted;
            outputSection.style.display = 'block';
            errorMessage.style.display = 'none';
        } catch (error) {
            showError(error.message);
            outputSection.style.display = 'none';
        }
    });

    clearBtn.addEventListener('click', () => {
        ipsInput.value = '';
        outputSection.style.display = 'none';
        errorMessage.style.display = 'none';
        ipsInput.focus();
    });

    expandAllBtn.addEventListener('click', () => {
        reportOutput.querySelectorAll('details').forEach(detail => {
            detail.open = true;
        });
    });

    collapseAllBtn.addEventListener('click', () => {
        reportOutput.querySelectorAll('details').forEach(detail => {
            detail.open = false;
        });
    });

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }

    // Allow parsing with Enter key (Ctrl/Cmd + Enter)
    ipsInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            parseBtn.click();
        }
    });
});
