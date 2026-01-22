// IPS Crash Report Parser
class IPSParser {
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

    formatReport() {
        if (!this.metadata || !this.report) {
            throw new Error('Report not parsed. Call parse() first.');
        }

        let output = '';

        // Header - Process Information
        output += this.formatHeader();
        output += '\n';

        // Exception Information
        output += this.formatException();
        output += '\n';

        // Application Specific Information
        if (this.report.asi) {
            output += this.formatASI();
            output += '\n';
        }

        // Last Exception Backtrace
        if (this.report.lastExceptionBacktrace) {
            output += this.formatLastExceptionBacktrace();
            output += '\n';
        }

        // Threads
        output += this.formatThreads();
        output += '\n';

        // Binary Images
        output += this.formatBinaryImages();
        output += '\n';

        // VM Summary
        if (this.report.vmSummary) {
            output += 'VM Region Summary:\n';
            output += this.report.vmSummary;
            output += '\n';
        }

        return output;
    }

    formatHeader() {
        const b = this.report.bundleInfo || {};
        const os = this.report.osVersion || {};

        let header = '';
        header += `Process:             ${this.report.procName || 'Unknown'} [${this.report.pid || 0}]\n`;
        header += `Path:                ${this.report.procPath || 'Unknown'}\n`;
        header += `Identifier:          ${b.CFBundleIdentifier || 'Unknown'}\n`;
        header += `Version:             ${b.CFBundleShortVersionString || '?'} (${b.CFBundleVersion || '?'})\n`;
        header += `Code Type:           ${this.formatCPUType(this.report.cpuType)}\n`;

        if (this.report.procRole) {
            header += `Role:                ${this.report.procRole}\n`;
        }

        header += `Parent Process:      ${this.report.parentProc || 'Unknown'} [${this.report.parentPid || 0}]\n`;

        if (this.report.coalitionName) {
            header += `Coalition:           ${this.report.coalitionName} [${this.report.coalitionID || 0}]\n`;
        }

        if (this.report.userID !== undefined) {
            header += `User ID:             ${this.report.userID}\n`;
        }

        header += `\n`;
        header += `Date/Time:           ${this.report.captureTime || 'Unknown'}\n`;

        if (this.report.procLaunch) {
            header += `Launch Time:         ${this.report.procLaunch}\n`;
        }

        if (this.report.modelCode) {
            header += `Hardware Model:      ${this.report.modelCode}\n`;
        }

        header += `OS Version:          ${os.train || 'Unknown'} (${os.build || 'Unknown'})\n`;

        if (os.releaseType) {
            header += `Release Type:        ${os.releaseType}\n`;
        }

        header += `\n`;

        if (this.report.crashReporterKey) {
            header += `Crash Reporter Key:  ${this.report.crashReporterKey}\n`;
        }

        header += `Incident Identifier: ${this.report.incident || this.metadata.incident_id || 'Unknown'}\n`;
        header += `\n`;

        if (this.report.uptime !== undefined) {
            header += `Time Awake Since Boot: ${this.report.uptime} seconds\n`;
            header += `\n`;
        }

        if (this.report.faultingThread !== undefined) {
            header += `Triggered by Thread: ${this.report.faultingThread}\n`;
        }

        return header;
    }

    formatException() {
        const ex = this.report.exception || {};
        const term = this.report.termination;

        let output = '\n';
        output += `Exception Type:    ${ex.type || 'Unknown'}`;
        if (ex.signal) {
            output += ` (${ex.signal})`;
        }
        output += '\n';

        if (ex.codes) {
            output += `Exception Codes:   ${ex.codes}\n`;
        }

        if (term) {
            output += `\n`;
            output += `Termination Reason:  Namespace ${term.namespace || 'Unknown'}, Code ${term.code || 0}`;
            if (term.indicator) {
                output += `, ${term.indicator}`;
            }
            output += '\n';

            if (term.byProc) {
                output += `Terminating Process: ${term.byProc} [${term.byPid || 0}]\n`;
            }
        }

        return output;
    }

    formatASI() {
        let output = '\n';
        output += 'Application Specific Information:\n';

        for (const [key, value] of Object.entries(this.report.asi)) {
            if (Array.isArray(value)) {
                value.forEach(v => {
                    output += `${v}\n`;
                });
            } else {
                output += `${key}: ${value}\n`;
            }
        }

        return output;
    }

    formatLastExceptionBacktrace() {
        const backtrace = this.report.lastExceptionBacktrace;
        if (!backtrace || backtrace.length === 0) return '';

        let output = '\n';
        output += 'Last Exception Backtrace:\n';

        backtrace.forEach((frame, index) => {
            const imageInfo = this.report.usedImages[frame.imageIndex];
            const imageName = imageInfo ? imageInfo.name : 'Unknown';
            const symbol = frame.symbol || `0x${(imageInfo?.base || 0).toString(16)} + ${frame.imageOffset}`;

            output += `${index.toString().padStart(2, ' ')}  ${imageName.padEnd(30, ' ')}\t`;
            output += `0x${((imageInfo?.base || 0) + frame.imageOffset).toString(16).padStart(16, '0')} `;
            output += `${symbol}`;

            if (frame.symbolLocation !== undefined) {
                output += ` + ${frame.symbolLocation}`;
            }

            output += '\n';
        });

        return output;
    }

    formatThreads() {
        const threads = this.report.threads || [];
        let output = '\n';

        threads.forEach((thread) => {
            const threadNum = thread.id;
            const isCrashed = thread.triggered;

            // Thread header
            output += `Thread ${threadNum}`;
            if (thread.name) {
                output += ` name:  ${thread.name}`;
            }
            if (isCrashed) {
                output += ' Crashed';
            }
            output += ':\n';

            // Stack frames
            if (thread.frames && thread.frames.length > 0) {
                thread.frames.forEach((frame, index) => {
                    const imageInfo = this.report.usedImages[frame.imageIndex];
                    const imageName = imageInfo ? imageInfo.name : 'Unknown';
                    const address = (imageInfo?.base || 0) + frame.imageOffset;
                    const symbol = frame.symbol || `0x${(imageInfo?.base || 0).toString(16)} + ${frame.imageOffset}`;

                    output += `${index.toString().padStart(2, ' ')}  ${imageName.padEnd(30, ' ')}\t`;
                    output += `0x${address.toString(16).padStart(16, '0')} `;
                    output += `${symbol}`;

                    if (frame.symbolLocation !== undefined) {
                        output += ` + ${frame.symbolLocation}`;
                    }

                    output += '\n';
                });
            }

            output += '\n';
        });

        // Thread state for crashed thread
        if (this.report.faultingThread !== undefined) {
            const crashedThread = threads.find(t => t.triggered);
            if (crashedThread && crashedThread.threadState) {
                output += this.formatThreadState(crashedThread, this.report.faultingThread);
            }
        }

        return output;
    }

    formatThreadState(thread, threadNum) {
        const state = thread.threadState;
        if (!state) return '';

        let output = `\nThread ${threadNum} crashed with ARM Thread State (64-bit):\n`;

        if (state.x) {
            // Format registers in groups of 4
            for (let i = 0; i < state.x.length; i += 4) {
                const line = state.x.slice(i, i + 4).map((reg, idx) => {
                    const regNum = i + idx;
                    const value = reg.value || 0;
                    return `   x${regNum.toString().padStart(2, ' ')}: 0x${value.toString(16).padStart(16, '0')}`;
                }).join('');
                output += line + '\n';
            }
        }

        if (state.fp) output += `   fp: 0x${(state.fp.value || 0).toString(16).padStart(16, '0')}`;
        if (state.lr) output += `   lr: 0x${(state.lr.value || 0).toString(16).padStart(16, '0')}\n`;
        if (state.sp) output += `   sp: 0x${(state.sp.value || 0).toString(16).padStart(16, '0')}`;
        if (state.pc) output += `   pc: 0x${(state.pc.value || 0).toString(16).padStart(16, '0')}`;
        if (state.cpsr) output += ` cpsr: 0x${(state.cpsr.value || 0).toString(16).padStart(8, '0')}\n`;
        if (state.far) output += `  far: 0x${(state.far.value || 0).toString(16).padStart(16, '0')}`;
        if (state.esr) output += `  esr: 0x${(state.esr.value || 0).toString(16).padStart(8, '0')}`;
        if (state.esr?.description) output += ` (${state.esr.description})`;
        output += '\n';

        return output;
    }

    formatBinaryImages() {
        const images = this.report.usedImages || [];
        let output = '\nBinary Images:\n';

        images.forEach((image) => {
            if (image.size === 0) {
                // Skip placeholder entries
                return;
            }

            const base = image.base || 0;
            const end = base + (image.size || 0) - 1;

            output += `       0x${base.toString(16)} - `;
            output += `       0x${end.toString(16)}`;
            output += ` ${(image.name || '???').padEnd(30, ' ')}`;
            output += ` ${image.arch || 'unknown-arch'} `;
            output += ` <${(image.uuid || '').replace(/-/g, '')}>`;
            output += ` ${image.path || '???'}\n`;
        });

        return output;
    }

    formatCPUType(cpuType) {
        const types = {
            'ARM-64': 'ARM-64 (Native)',
            'ARM': 'ARM (Native)',
            'X86-64': 'X86-64 (Native)',
            'X86': 'X86 (Native)'
        };
        return types[cpuType] || cpuType || 'Unknown';
    }
}

// UI Controller
document.addEventListener('DOMContentLoaded', () => {
    const ipsInput = document.getElementById('ipsInput');
    const parseBtn = document.getElementById('parseBtn');
    const clearBtn = document.getElementById('clearBtn');
    const copyBtn = document.getElementById('copyBtn');
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
            const parser = new IPSParser(content);
            parser.parse();
            const formatted = parser.formatReport();

            reportOutput.textContent = formatted;
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

    copyBtn.addEventListener('click', () => {
        const text = reportOutput.textContent;
        navigator.clipboard.writeText(text).then(() => {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        }).catch(err => {
            showError('Failed to copy to clipboard: ' + err.message);
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
