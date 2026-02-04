// IPS Crash Report Parser - Core Logic
// This file contains the pure parsing and formatting logic, shared between browser and CLI

export class IPSParser {
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

        // External Modification Summary
        if (this.report.extMods) {
            output += this.formatExtMods();
            output += '\n';
        }

        // VM Summary
        if (this.report.vmSummary) {
            output += 'VM Region Summary:\n';
            output += this.report.vmSummary;
            output += '\n';
        }

        // Filtered Log
        if (this.report.filteredLog && this.report.filteredLog.length > 0) {
            output += 'Filtered log messages:\n';
            output += this.report.filteredLog.join('\n');
            output += '\n\n';
        }

        return output;
    }

    formatHeader() {
        const bundleInfo = this.report.bundleInfo || {};
        const buildInfo = this.report.buildInfo || {};
        const storeInfo = this.report.storeInfo || {};
        const osVersion = this.report.osVersion || {};

        let header = '';
        header += `Process:             ${this.report.procName || 'Unknown'} [${this.report.pid || 0}]\n`;
        header += `Path:                ${this.report.procPath || 'Unknown'}\n`;
        header += `Identifier:          ${bundleInfo.CFBundleIdentifier || 'Unknown'}\n`;
        header += `Version:             ${bundleInfo.CFBundleShortVersionString || '?'} (${bundleInfo.CFBundleVersion || '?'})\n`;

        if (bundleInfo.DTAppStoreToolsBuild) {
            header += `AppStoreTools:       ${bundleInfo.DTAppStoreToolsBuild}\n`;
        }

        if (storeInfo.applicationVariant) {
            header += `AppVariant:          ${storeInfo.applicationVariant}\n`;
        }

        if (this.report.isBeta !== undefined) {
            header += `Beta:                ${this.report.isBeta ? 'YES' : 'NO'}\n`;
        }

        // Build Info
        if (buildInfo.ProjectName && buildInfo.SourceVersion && buildInfo.BuildVersion) {
            header += `Build Info:          ${buildInfo.ProjectName}-${buildInfo.SourceVersion}~${buildInfo.BuildVersion}\n`;
        }

        const translatedLabel = this.report.translated ? 'Translated' : 'Native';
        header += `Code Type:           ${this.report.cpuType || '???'} (${translatedLabel})\n`;

        if (this.report.procRole) {
            header += `Role:                ${this.report.procRole}\n`;
        }

        header += `Parent Process:      ${this.report.parentProc || 'Unknown'}`;
        if (this.report.parentPid !== undefined) {
            header += ` [${this.report.parentPid}]`;
        }
        header += '\n';

        if (this.report.coalitionName) {
            header += `Coalition:           ${this.report.coalitionName}`;
            if (this.report.coalitionID !== undefined) {
                header += ` [${this.report.coalitionID}]`;
            }
            header += '\n';
        }

        if (this.report.responsibleProc) {
            header += `Responsible Process: ${this.report.responsibleProc}`;
            if (this.report.responsiblePid !== undefined) {
                header += ` [${this.report.responsiblePid}]`;
            }
            header += '\n';
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

        if (this.report.codeName) {
            header += `Device Model:        ${this.report.codeName}\n`;
        }

        header += `OS Version:          ${osVersion.train || 'Unknown'} (${osVersion.build || 'Unknown'})\n`;

        if (osVersion.releaseType) {
            header += `Release Type:        ${osVersion.releaseType}\n`;
        }

        if (this.report.basebandVersion) {
            header += `Baseband Version:    ${this.report.basebandVersion}\n`;
        }

        header += `\n`;

        if (storeInfo.deviceIdentifierForVendor) {
            header += `Beta Identifier:     ${storeInfo.deviceIdentifierForVendor}\n`;
        }

        if (this.report.systemID) {
            header += `UDID:                ${this.report.systemID}\n`;
        }

        if (this.report.crashReporterKey) {
            header += `Crash Reporter Key:  ${this.report.crashReporterKey}\n`;
        }

        header += `Incident Identifier: ${this.report.incident || this.metadata.incident_id || 'Unknown'}\n`;
        header += `\n`;

        if (this.report.sleepWakeUUID) {
            header += `Sleep/Wake UUID:       ${this.report.sleepWakeUUID}\n`;
            header += `\n`;
        }

        if (this.report.uptime !== undefined) {
            header += `Time Awake Since Boot: ${this.report.uptime} seconds\n`;
        }

        if (this.report.wakeTime !== undefined) {
            header += `Time Since Wake:       ${this.report.wakeTime} seconds\n`;
        }

        if (this.report.uptime !== undefined || this.report.wakeTime !== undefined) {
            header += `\n`;
        }

        // System Integrity Protection
        if (this.report.sip !== undefined) {
            header += `System Integrity Protection: ${this.report.sip}\n`;
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

        if (ex.subtype !== undefined) {
            output += `Exception Subtype: ${ex.subtype}\n`;
        }

        if (ex.codes !== undefined) {
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

        // VM Region Info
        if (this.report.vmRegionInfo) {
            output += `\n\n`;
            output += `VM Region Info: ${this.report.vmRegionInfo}`;
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
            output += ':';

            // Add dispatch queue if present
            if (thread.queue) {
                output += `:  Dispatch queue: ${thread.queue}`;
            }
            output += '\n';

            // Stack frames
            if (thread.frames && thread.frames.length > 0) {
                thread.frames.forEach((frame, index) => {
                    const imageInfo = this.report.usedImages[frame.imageIndex];
                    const imageName = imageInfo?.name || '???';
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

        let threadStateTitle = '';
        let registers = [];
        let additionalInfo = '';

        switch (state.flavor) {
            case 'ARM_THREAD_STATE64':
                threadStateTitle = 'ARM Thread State (64-bit)';

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
                threadStateTitle = 'X86 Thread State (64-bit)';

                // x86_64 register order matching Apple's format
                const x86Regs = [
                    'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'rip', 'rflags', 'cr2'
                ];

                x86Regs.forEach(regName => {
                    if (state[regName]) {
                        // Map 'rflags' to 'rfl' for display
                        const displayName = regName === 'rflags' ? 'rfl' : regName;
                        registers.push({ name: displayName, object: state[regName] });
                    }
                });

                // Additional x86 fields
                if (state.cpu !== undefined) {
                    additionalInfo += `\nLogical CPU:     ${state.cpu.value}\n`;
                }
                if (state.err !== undefined) {
                    additionalInfo += `Error Code:      0x${state.err.value.toString(16).padStart(8, '0')}`;
                    if (state.err.description) {
                        additionalInfo += ` ${state.err.description}`;
                    }
                    additionalInfo += '\n';
                }
                if (state.trap !== undefined) {
                    additionalInfo += `Trap Number:     ${state.trap.value}`;
                    if (state.trap.description) {
                        additionalInfo += ` ${state.trap.description}`;
                    }
                    additionalInfo += '\n';
                }
                break;

            default:
                return '';
        }

        let output = `\nThread ${threadNum} crashed with ${threadStateTitle}:\n`;

        // Format registers in groups of 4
        for (let i = 0; i < registers.length; i += 4) {
            const line = registers.slice(i, i + 4).map((reg) => {
                const value = reg.object.value || 0;
                let build = `  ${reg.name.padStart(4, ' ')}: 0x${value.toString(0x10).padStart(16, '0')}`;
                if (reg.object.description) {
                    build += ` ${reg.object.description}`;
                }
                return build;
            }).join('');
            output += line + '\n';
        }

        output += additionalInfo;
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

    formatExtMods() {
        const extMods = this.report.extMods;
        if (!extMods) return '';

        let output = '\nExternal Modification Summary:\n';

        // Calls made by other processes targeting this process
        if (extMods.targeted) {
            output += '  Calls made by other processes targeting this process:\n';
            if (extMods.targeted.task_for_pid !== undefined) {
                output += `    task_for_pid: ${extMods.targeted.task_for_pid}\n`;
            }
            if (extMods.targeted.thread_create !== undefined) {
                output += `    thread_create: ${extMods.targeted.thread_create}\n`;
            }
            if (extMods.targeted.thread_set_state !== undefined) {
                output += `    thread_set_state: ${extMods.targeted.thread_set_state}\n`;
            }
        }

        // Calls made by this process
        if (extMods.caller) {
            output += '  Calls made by this process:\n';
            if (extMods.caller.task_for_pid !== undefined) {
                output += `    task_for_pid: ${extMods.caller.task_for_pid}\n`;
            }
            if (extMods.caller.thread_create !== undefined) {
                output += `    thread_create: ${extMods.caller.thread_create}\n`;
            }
            if (extMods.caller.thread_set_state !== undefined) {
                output += `    thread_set_state: ${extMods.caller.thread_set_state}\n`;
            }
        }

        // Calls made by all processes on this machine
        if (extMods.system) {
            output += '  Calls made by all processes on this machine:\n';
            if (extMods.system.task_for_pid !== undefined) {
                output += `    task_for_pid: ${extMods.system.task_for_pid}\n`;
            }
            if (extMods.system.thread_create !== undefined) {
                output += `    thread_create: ${extMods.system.thread_create}\n`;
            }
            if (extMods.system.thread_set_state !== undefined) {
                output += `    thread_set_state: ${extMods.system.thread_set_state}\n`;
            }
        }

        return output;
    }
}
