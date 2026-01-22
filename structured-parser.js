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

    // Helper methods for creating DOM elements
    createElement(tag, className, textContent) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (textContent !== undefined) el.textContent = textContent;
        return el;
    }

    createSpan(className, textContent) {
        return this.createElement('span', className, textContent);
    }

    createDiv(className, textContent) {
        return this.createElement('div', className, textContent);
    }

    createAddress(addr) {
        return this.createSpan('addr', `0x${addr.toString(16).padStart(16, '0')}`);
    }

    createNumber(num) {
        return this.createSpan('number', String(num));
    }

    createSymbol(sym) {
        return this.createSpan('symbol', sym);
    }

    formatReport() {
        if (!this.metadata || !this.report) {
            throw new Error('Report not parsed. Call parse() first.');
        }

        const container = document.createDocumentFragment();

        // Process Information
        container.appendChild(this.formatProcessInfo());

        // Exception Information
        container.appendChild(this.formatException());

        // Application Specific Information
        if (this.report.asi) {
            container.appendChild(this.formatASI());
        }

        // Last Exception Backtrace
        if (this.report.lastExceptionBacktrace) {
            container.appendChild(this.formatLastExceptionBacktrace());
        }

        // Threads
        container.appendChild(this.formatThreads());

        // Binary Images
        container.appendChild(this.formatBinaryImages());

        // VM Summary
        if (this.report.vmSummary) {
            container.appendChild(this.formatVMSummary());
        }

        return container;
    }

    formatProcessInfo() {
        const b = this.report.bundleInfo || {};
        const os = this.report.osVersion || {};

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');
        details.open = true;

        const summary = this.createElement('summary', null, 'Process Information');
        details.appendChild(summary);

        const grid = this.createDiv('info-grid');

        const addRow = (label, value) => {
            grid.appendChild(this.createDiv('info-label', label + ':'));
            const valueDiv = this.createDiv('info-value');
            if (typeof value === 'string') {
                valueDiv.textContent = value;
            } else {
                valueDiv.appendChild(value);
            }
            grid.appendChild(valueDiv);
        };

        const procValue = document.createDocumentFragment();
        procValue.append(this.report.procName || 'Unknown', ' [', this.createNumber(this.report.pid || 0), ']');
        addRow('Process', procValue);

        addRow('Path', this.report.procPath || 'Unknown');
        addRow('Identifier', b.CFBundleIdentifier || 'Unknown');
        addRow('Version', `${b.CFBundleShortVersionString || '?'} (${b.CFBundleVersion || '?'})`);
        addRow('Code Type', this.report.cpuType || 'Unknown');

        if (this.report.procRole) {
            addRow('Role', this.report.procRole);
        }

        const parentValue = document.createDocumentFragment();
        parentValue.append(this.report.parentProc || 'Unknown', ' [', this.createNumber(this.report.parentPid || 0), ']');
        addRow('Parent Process', parentValue);

        if (this.report.coalitionName) {
            const coalValue = document.createDocumentFragment();
            coalValue.append(this.report.coalitionName, ' [', this.createNumber(this.report.coalitionID || 0), ']');
            addRow('Coalition', coalValue);
        }

        addRow('Date/Time', this.report.captureTime || 'Unknown');

        if (this.report.procLaunch) {
            addRow('Launch Time', this.report.procLaunch);
        }

        if (this.report.modelCode) {
            addRow('Hardware Model', this.report.modelCode);
        }

        addRow('OS Version', `${os.train || 'Unknown'} (${os.build || 'Unknown'})`);

        if (os.releaseType) {
            addRow('Release Type', os.releaseType);
        }

        if (this.report.incident) {
            addRow('Incident ID', this.report.incident);
        }

        if (this.report.uptime !== undefined) {
            const uptimeValue = document.createDocumentFragment();
            uptimeValue.append(this.createNumber(this.report.uptime), ' seconds');
            addRow('Uptime', uptimeValue);
        }

        details.appendChild(grid);
        section.appendChild(details);
        return section;
    }

    formatException() {
        const ex = this.report.exception || {};
        const term = this.report.termination;

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');
        details.open = true;

        const summary = this.createElement('summary', null, 'Exception Information');
        details.appendChild(summary);

        const exceptionInfo = this.createDiv('exception-info');

        const exType = this.createDiv('exception-type');
        exType.textContent = ex.type || 'Unknown';
        if (ex.signal) {
            exType.textContent += ` (${ex.signal})`;
        }
        exceptionInfo.appendChild(exType);

        if (ex.codes) {
            exceptionInfo.appendChild(this.createDiv('exception-detail', `Codes: ${ex.codes}`));
        }

        if (ex.message) {
            exceptionInfo.appendChild(this.createDiv('exception-detail', `Message: ${ex.message}`));
        }

        if (term) {
            const termDetail = this.createDiv('exception-detail');
            termDetail.style.marginTop = '10px';
            const termFrag = document.createDocumentFragment();
            termFrag.append(
                'Termination: Namespace ',
                term.namespace || 'Unknown',
                ', Code ',
                this.createNumber(term.code || 0)
            );
            if (term.indicator) {
                termFrag.append(', ', term.indicator);
            }
            termDetail.appendChild(termFrag);
            exceptionInfo.appendChild(termDetail);

            if (term.byProc) {
                const procFrag = document.createDocumentFragment();
                procFrag.append('Terminating Process: ', term.byProc, ' [', this.createNumber(term.byPid || 0), ']');
                const procDetail = this.createDiv('exception-detail');
                procDetail.appendChild(procFrag);
                exceptionInfo.appendChild(procDetail);
            }
        }

        if (this.report.faultingThread !== undefined) {
            const faultDetail = this.createDiv('exception-detail');
            faultDetail.style.marginTop = '10px';
            const faultFrag = document.createDocumentFragment();
            faultFrag.append('Faulting Thread: ', this.createNumber(this.report.faultingThread));
            faultDetail.appendChild(faultFrag);
            exceptionInfo.appendChild(faultDetail);
        }

        details.appendChild(exceptionInfo);
        section.appendChild(details);
        return section;
    }

    formatASI() {
        const section = this.createDiv('crash-section');
        const details = this.createElement('details');
        details.open = true;

        const summary = this.createElement('summary', null, 'Application Specific Information');
        details.appendChild(summary);

        const grid = this.createDiv('info-grid');

        for (const [key, value] of Object.entries(this.report.asi)) {
            if (Array.isArray(value)) {
                value.forEach(v => {
                    grid.appendChild(this.createDiv('info-label', key + ':'));
                    grid.appendChild(this.createDiv('info-value', v));
                });
            } else {
                grid.appendChild(this.createDiv('info-label', key + ':'));
                grid.appendChild(this.createDiv('info-value', String(value)));
            }
        }

        details.appendChild(grid);
        section.appendChild(details);
        return section;
    }

    formatLastExceptionBacktrace() {
        const backtrace = this.report.lastExceptionBacktrace;
        if (!backtrace || backtrace.length === 0) return null;

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');

        const summary = this.createElement('summary', null, 'Last Exception Backtrace');
        details.appendChild(summary);

        const container = this.createDiv();
        container.style.marginTop = '15px';

        backtrace.forEach((frame, index) => {
            const imageInfo = this.report.usedImages[frame.imageIndex];
            const imageName = imageInfo ? imageInfo.name : 'Unknown';
            const address = (imageInfo?.base || 0) + frame.imageOffset;

            const stackFrame = this.createDiv('stack-frame');
            stackFrame.appendChild(this.createDiv('frame-index', String(index)));
            stackFrame.appendChild(this.createDiv('frame-image', imageName));

            const frameDetails = this.createDiv('frame-details');
            frameDetails.appendChild(this.createAddress(address));

            if (frame.symbol) {
                frameDetails.append(' ', this.createSymbol(frame.symbol));
                if (frame.symbolLocation !== undefined) {
                    const offset = this.createSpan('offset');
                    offset.append('+ ', this.createNumber(frame.symbolLocation));
                    frameDetails.append(' ', offset);
                }
            }

            stackFrame.appendChild(frameDetails);
            container.appendChild(stackFrame);
        });

        details.appendChild(container);
        section.appendChild(details);
        return section;
    }

    formatThreads() {
        const threads = this.report.threads || [];

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');
        details.open = true;

        const summary = this.createElement('summary', null, 'Threads');
        details.appendChild(summary);

        const threadList = this.createDiv('thread-list');

        threads.forEach((thread) => {
            const isCrashed = thread.triggered;

            const threadItem = this.createDiv(isCrashed ? 'thread-item crashed' : 'thread-item');
            const threadDetails = this.createElement('details');

            const threadSummary = this.createElement('summary', 'thread-header');
            const summaryFrag = document.createDocumentFragment();
            summaryFrag.append('Thread ', this.createNumber(thread.id));
            if (thread.name) {
                summaryFrag.append(' - ', thread.name);
            }
            if (isCrashed) {
                summaryFrag.append(' ⚠️ CRASHED');
            }
            threadSummary.appendChild(summaryFrag);
            threadDetails.appendChild(threadSummary);

            // Stack frames
            if (thread.frames && thread.frames.length > 0) {
                const framesContainer = this.createDiv();
                framesContainer.style.marginTop = '10px';

                thread.frames.forEach((frame, index) => {
                    const imageInfo = this.report.usedImages[frame.imageIndex];
                    const imageName = imageInfo ? imageInfo.name : 'Unknown';
                    const address = (imageInfo?.base || 0) + frame.imageOffset;

                    const stackFrame = this.createDiv('stack-frame');
                    stackFrame.appendChild(this.createDiv('frame-index', String(index)));
                    stackFrame.appendChild(this.createDiv('frame-image', imageName));

                    const frameDetails = this.createDiv('frame-details');
                    frameDetails.appendChild(this.createAddress(address));

                    if (frame.symbol) {
                        frameDetails.append(' ', this.createSymbol(frame.symbol));
                        if (frame.symbolLocation !== undefined) {
                            const offset = this.createSpan('offset');
                            offset.append('+ ', this.createNumber(frame.symbolLocation));
                            frameDetails.append(' ', offset);
                        }
                    }

                    stackFrame.appendChild(frameDetails);
                    framesContainer.appendChild(stackFrame);
                });

                threadDetails.appendChild(framesContainer);
            }

            // Thread state for crashed thread
            if (isCrashed && thread.threadState) {
                threadDetails.appendChild(this.formatThreadState(thread.threadState));
            }

            threadItem.appendChild(threadDetails);
            threadList.appendChild(threadItem);
        });

        details.appendChild(threadList);
        section.appendChild(details);
        return section;
    }

    formatThreadState(state) {
        if (!state) return null;

        const container = this.createDiv();
        container.style.marginTop = '15px';

        const header = this.createElement('h4');
        header.style.marginBottom = '10px';
        header.style.color = '#555';
        header.textContent = 'Register State';
        container.appendChild(header);

        const registersGrid = this.createDiv('registers');

        let registers = [];

        if (state.x) {
            for (let i = 0; i < state.x.length; i++) {
                registers.push({ name: 'x' + i, object: state.x[i] });
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
            const registerDiv = this.createDiv('register');

            registerDiv.appendChild(this.createDiv('register-name', reg.name + ':'));
            registerDiv.appendChild(this.createDiv('register-value', `0x${value.toString(16).padStart(16, '0')}`));

            if (reg.object.description) {
                registerDiv.appendChild(this.createDiv('register-desc', reg.object.description));
            }

            registersGrid.appendChild(registerDiv);
        });

        container.appendChild(registersGrid);
        return container;
    }

    formatBinaryImages() {
        const images = this.report.usedImages || [];

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');

        const summary = this.createElement('summary', null, 'Binary Images');
        details.appendChild(summary);

        const container = this.createDiv();
        container.style.marginTop = '15px';

        images.forEach((image) => {
            if (image.size === 0) return;

            const base = image.base || 0;
            const end = base + (image.size || 0) - 1;

            const binaryImage = this.createDiv('binary-image');

            const rangeDiv = this.createDiv('image-range');
            rangeDiv.appendChild(this.createAddress(base));
            rangeDiv.append(' - ');
            rangeDiv.appendChild(this.createAddress(end));
            binaryImage.appendChild(rangeDiv);

            binaryImage.appendChild(this.createDiv('image-name', image.name || '???'));

            const detailsDiv = this.createDiv('image-details');
            detailsDiv.appendChild(this.createSpan('image-arch', image.arch || 'unknown'));
            detailsDiv.append(' ');
            detailsDiv.appendChild(this.createSpan('image-uuid', `<${image.uuid || ''}>`));
            detailsDiv.append(' ');
            detailsDiv.appendChild(this.createSpan('image-path', image.path || '???'));

            binaryImage.appendChild(detailsDiv);
            container.appendChild(binaryImage);
        });

        details.appendChild(container);
        section.appendChild(details);
        return section;
    }

    formatVMSummary() {
        const section = this.createDiv('crash-section');
        const details = this.createElement('details');

        const summary = this.createElement('summary', null, 'VM Region Summary');
        details.appendChild(summary);

        const vmDiv = this.createDiv('vm-summary', this.report.vmSummary);

        details.appendChild(vmDiv);
        section.appendChild(details);
        return section;
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

            reportOutput.textContent = '';
            reportOutput.appendChild(formatted);
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
