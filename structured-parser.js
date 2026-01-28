"use strict";

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

        // External Modification Summary
        const extModsSection = this.formatExtMods();
        if (extModsSection) {
            container.appendChild(extModsSection);
        }

        // VM Summary
        if (this.report.vmSummary) {
            container.appendChild(this.formatVMSummary());
        }

        // Filtered Log
        if (this.report.filteredLog && this.report.filteredLog.length > 0) {
            container.appendChild(this.formatFilteredLog());
        }

        return container;
    }

    formatProcessInfo() {
        const bundleInfo = this.report.bundleInfo || {};
        const buildInfo = this.report.buildInfo || {};
        const storeInfo = this.report.storeInfo || {};
        const osVersion = this.report.osVersion || {};

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
        addRow('Identifier', bundleInfo.CFBundleIdentifier || 'Unknown');
        addRow('Version', `${bundleInfo.CFBundleShortVersionString || '?'} (${bundleInfo.CFBundleVersion || '?'})`);

        if (bundleInfo.DTAppStoreToolsBuild) {
            addRow('AppStoreTools', bundleInfo.DTAppStoreToolsBuild);
        }

        if (storeInfo.applicationVariant) {
            addRow('AppVariant', storeInfo.applicationVariant);
        }

        if (this.report.isBeta !== undefined) {
            addRow('Beta', this.report.isBeta ? 'YES' : 'NO');
        }

        // Build Info
        if (buildInfo.ProjectName && buildInfo.SourceVersion && buildInfo.BuildVersion) {
            addRow('Build Info', `${buildInfo.ProjectName}-${buildInfo.SourceVersion}~${buildInfo.BuildVersion}`);
        }

        const translatedLabel = this.report.translated ? 'Translated' : 'Native';
        addRow('Code Type', `${this.report.cpuType || 'Unknown'} (${translatedLabel})`);

        if (this.report.procRole) {
            addRow('Role', this.report.procRole);
        }

        const parentValue = document.createDocumentFragment();
        parentValue.append(this.report.parentProc || 'Unknown');
        if (this.report.parentPid !== undefined) {
            parentValue.append(' [', this.createNumber(this.report.parentPid), ']');
        }
        addRow('Parent Process', parentValue);

        if (this.report.coalitionName) {
            const coalValue = document.createDocumentFragment();
            coalValue.append(this.report.coalitionName);
            if (this.report.coalitionID !== undefined) {
                coalValue.append(' [', this.createNumber(this.report.coalitionID), ']');
            }
            addRow('Coalition', coalValue);
        }

        if (this.report.responsibleProc) {
            const respValue = document.createDocumentFragment();
            respValue.append(this.report.responsibleProc);
            if (this.report.responsiblePid !== undefined) {
                respValue.append(' [', this.createNumber(this.report.responsiblePid), ']');
            }
            addRow('Responsible Process', respValue);
        }

        if (this.report.userID !== undefined) {
            addRow('User ID', String(this.report.userID));
        }

        addRow('Date/Time', this.report.captureTime || 'Unknown');

        if (this.report.procLaunch) {
            addRow('Launch Time', this.report.procLaunch);
        }

        if (this.report.procStartAbsTime !== undefined) {
            addRow('Process Start (Absolute)', String(this.report.procStartAbsTime));
        }

        if (this.report.procExitAbsTime !== undefined) {
            addRow('Process Exit (Absolute)', String(this.report.procExitAbsTime));
        }

        if (this.report.modelCode) {
            addRow('Hardware Model', this.report.modelCode);
        }

        if (this.report.codeName) {
            addRow('Device Model', this.report.codeName);
        }

        addRow('OS Version', `${osVersion.train || 'Unknown'} (${osVersion.build || 'Unknown'})`);

        if (osVersion.releaseType) {
            addRow('Release Type', osVersion.releaseType);
        }

        if (this.report.basebandVersion) {
            addRow('Baseband Version', this.report.basebandVersion);
        }

        if (this.report.crashReporterKey) {
            addRow('Crash Reporter Key', this.report.crashReporterKey);
        }

        if (this.report.bootSessionUUID) {
            addRow('Boot Session UUID', this.report.bootSessionUUID);
        }

        if (this.report.sleepWakeUUID) {
            addRow('Sleep/Wake UUID', this.report.sleepWakeUUID);
        }

        if (storeInfo.deviceIdentifierForVendor) {
            addRow('Beta Identifier', storeInfo.deviceIdentifierForVendor);
        }

        if (this.report.systemID) {
            addRow('UDID', this.report.systemID);
        }

        if (this.report.incident) {
            addRow('Incident ID', this.report.incident);
        }

        if (this.report.uptime !== undefined) {
            const uptimeValue = document.createDocumentFragment();
            uptimeValue.append(this.createNumber(this.report.uptime), ' seconds');
            addRow('Uptime', uptimeValue);
        }

        if (this.report.wakeTime !== undefined) {
            const wakeValue = document.createDocumentFragment();
            wakeValue.append(this.createNumber(this.report.wakeTime), ' seconds');
            addRow('Time Since Wake', wakeValue);
        }

        if (this.report.sip !== undefined) {
            addRow('System Integrity Protection', this.report.sip);
        }

        if (this.report.developerMode !== undefined) {
            addRow('Developer Mode', this.report.developerMode ? 'enabled' : 'disabled');
        }

        if (this.report.appleIntelligenceStatus) {
            const aiStatus = this.report.appleIntelligenceStatus;
            const statusText = `${aiStatus.state || 'unknown'}${aiStatus.reasons ? ' (' + aiStatus.reasons.join(', ') + ')' : ''}`;
            addRow('Apple Intelligence', statusText);
        }

        if (this.report.deployVersion !== undefined) {
            addRow('Deploy Version', String(this.report.deployVersion));
        }

        if (this.report.throttleTimeout !== undefined) {
            addRow('Throttle Timeout', String(this.report.throttleTimeout));
        }

        if (this.report.codeSigningMonitor !== undefined) {
            addRow('Code Signing Monitor', String(this.report.codeSigningMonitor));
        }

        if (this.report.codeSigningID !== undefined) {
            addRow('Code Signing ID', this.report.codeSigningID || '(none)');
        }

        if (this.report.codeSigningTeamID !== undefined) {
            addRow('Code Signing Team ID', this.report.codeSigningTeamID || '(none)');
        }

        if (this.report.codeSigningFlags !== undefined) {
            addRow('Code Signing Flags', `0x${this.report.codeSigningFlags.toString(16)}`);
        }

        if (this.report.codeSigningValidationCategory !== undefined) {
            addRow('Code Signing Validation', String(this.report.codeSigningValidationCategory));
        }

        if (this.report.codeSigningTrustLevel !== undefined) {
            addRow('Code Signing Trust Level', String(this.report.codeSigningTrustLevel));
        }

        if (this.report.codeSigningAuxiliaryInfo !== undefined) {
            addRow('Code Signing Auxiliary', `0x${this.report.codeSigningAuxiliaryInfo.toString(16)}`);
        }

        if (this.report.bootProgressRegister !== undefined) {
            addRow('Boot Progress Register', this.report.bootProgressRegister);
        }

        if (this.report.wasUnlockedSinceBoot !== undefined) {
            addRow('Unlocked Since Boot', this.report.wasUnlockedSinceBoot ? 'YES' : 'NO');
        }

        if (this.report.isLocked !== undefined) {
            addRow('Currently Locked', this.report.isLocked ? 'YES' : 'NO');
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

        if (ex.subtype !== undefined) {
            exceptionInfo.appendChild(this.createDiv('exception-detail', `Subtype: ${ex.subtype}`));
        }

        if (ex.codes !== undefined) {
            exceptionInfo.appendChild(this.createDiv('exception-detail', `Codes: ${ex.codes}`));
        }

        if (ex.message) {
            exceptionInfo.appendChild(this.createDiv('exception-detail', `Message: ${ex.message}`));
        }

        if (term) {
            const termDetail = this.createDiv('exception-detail spaced');
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

        if (this.report.vmRegionInfo) {
            const vmDetail = this.createDiv('exception-detail spaced');
            vmDetail.style.whiteSpace = 'pre-wrap';
            vmDetail.textContent = `VM Region Info: ${this.report.vmRegionInfo}`;
            exceptionInfo.appendChild(vmDetail);
        }

        if (this.report.instructionByteStream) {
            const instDetail = this.createDiv('exception-detail spaced');
            const inst = this.report.instructionByteStream;
            const instFrag = document.createDocumentFragment();
            instFrag.append('Instruction Bytes:');
            if (inst.beforePC) {
                instFrag.append('\n  Before PC: ', inst.beforePC);
            }
            if (inst.atPC) {
                instFrag.append('\n  At PC: ', inst.atPC);
            }
            instDetail.appendChild(instFrag);
            exceptionInfo.appendChild(instDetail);
        }

        if (this.report.faultingThread !== undefined) {
            const faultDetail = this.createDiv('exception-detail spaced');
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

        const container = this.createDiv('section-container');

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
            if (isCrashed) {
                threadDetails.open = true;
            }

            const threadSummary = this.createElement('summary', 'thread-header');
            const summaryFrag = document.createDocumentFragment();
            summaryFrag.append('Thread ', this.createNumber(thread.id));
            if (thread.name) {
                summaryFrag.append(' - ', thread.name);
            }
            if (thread.queue) {
                summaryFrag.append(' (', thread.queue, ')');
            }
            if (isCrashed) {
                summaryFrag.append(' ⚠️ CRASHED');
            }
            threadSummary.appendChild(summaryFrag);
            threadDetails.appendChild(threadSummary);

            // Stack frames
            if (thread.frames && thread.frames.length > 0) {
                const framesContainer = this.createDiv('frames-container');

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

        const container = this.createDiv('thread-state-container');

        const header = this.createElement('h4', 'thread-state-header');

        let registers = [];

        switch (state.flavor) {
            case 'ARM_THREAD_STATE64':
                header.textContent = 'ARM Thread State (64-bit)';

                if (state.x) {
                    for (let i = 0; i < state.x.length; i++) {
                        registers.push({ name: 'x' + i, object: state.x[i] });
                    }
                }
                const namedRegs = [
                    'fp', 'lr', 'sp', 'pc', 'cpsr',
                    'far', 'esr'
                ];
                namedRegs.forEach(regName => {
                    if (state[regName]) {
                        registers.push({ name: regName, object: state[regName] });
                    }
                });
                break;

            case 'x86_THREAD_STATE':
                header.textContent = 'X86 Thread State (64-bit)';

                const x86Regs = [
                    'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'rip', 'rflags', 'cr2'
                ];

                x86Regs.forEach(regName => {
                    if (state[regName]) {
                        const displayName = regName === 'rflags' ? 'rfl' : regName;
                        registers.push({ name: displayName, object: state[regName] });
                    }
                });
                break;

            default:
                header.textContent = 'Register State';
        }

        container.appendChild(header);

        const registersGrid = this.createDiv('registers');

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

        const container = this.createDiv('section-container');

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

    formatExtMods() {
        const extMods = this.report.extMods;
        if (!extMods) return null;

        const section = this.createDiv('crash-section');
        const details = this.createElement('details');

        const summary = this.createElement('summary', null, 'External Modification Summary');
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

        // Calls made by other processes targeting this process
        if (extMods.targeted) {
            const targetedFrag = document.createDocumentFragment();
            targetedFrag.appendChild(this.createDiv(null, 'Calls made by other processes targeting this process:'));
            if (extMods.targeted.task_for_pid !== undefined) {
                targetedFrag.appendChild(this.createDiv(null, `  task_for_pid: ${extMods.targeted.task_for_pid}`));
            }
            if (extMods.targeted.thread_create !== undefined) {
                targetedFrag.appendChild(this.createDiv(null, `  thread_create: ${extMods.targeted.thread_create}`));
            }
            if (extMods.targeted.thread_set_state !== undefined) {
                targetedFrag.appendChild(this.createDiv(null, `  thread_set_state: ${extMods.targeted.thread_set_state}`));
            }
            addRow('Targeted', targetedFrag);
        }

        // Calls made by this process
        if (extMods.caller) {
            const callerFrag = document.createDocumentFragment();
            callerFrag.appendChild(this.createDiv(null, 'Calls made by this process:'));
            if (extMods.caller.task_for_pid !== undefined) {
                callerFrag.appendChild(this.createDiv(null, `  task_for_pid: ${extMods.caller.task_for_pid}`));
            }
            if (extMods.caller.thread_create !== undefined) {
                callerFrag.appendChild(this.createDiv(null, `  thread_create: ${extMods.caller.thread_create}`));
            }
            if (extMods.caller.thread_set_state !== undefined) {
                callerFrag.appendChild(this.createDiv(null, `  thread_set_state: ${extMods.caller.thread_set_state}`));
            }
            addRow('Caller', callerFrag);
        }

        // Calls made by all processes on this machine
        if (extMods.system) {
            const systemFrag = document.createDocumentFragment();
            systemFrag.appendChild(this.createDiv(null, 'Calls made by all processes on this machine:'));
            if (extMods.system.task_for_pid !== undefined) {
                systemFrag.appendChild(this.createDiv(null, `  task_for_pid: ${extMods.system.task_for_pid}`));
            }
            if (extMods.system.thread_create !== undefined) {
                systemFrag.appendChild(this.createDiv(null, `  thread_create: ${extMods.system.thread_create}`));
            }
            if (extMods.system.thread_set_state !== undefined) {
                systemFrag.appendChild(this.createDiv(null, `  thread_set_state: ${extMods.system.thread_set_state}`));
            }
            addRow('System', systemFrag);
        }

        details.appendChild(grid);
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

    formatFilteredLog() {
        const section = this.createDiv('crash-section');
        const details = this.createElement('details');

        const summary = this.createElement('summary', null, 'Filtered log messages');
        details.appendChild(summary);

        const logDiv = this.createDiv('filtered-log');
        logDiv.textContent = this.report.filteredLog.join('\n');

        details.appendChild(logDiv);
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
