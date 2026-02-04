#!/usr/bin/env jsc

// IPS Crash Report Parser - CLI Version

import { IPSParser } from './ips-parser-core.js';

// CLI Implementation
function main(args) {
    // Show usage if no arguments
    if (args.length === 0) {
        print("Usage: jsc -m cli-parser.js -- <input.ips>");
        print("");
        print("Convert Apple crash report (.ips) to plain text format.");
        print("The -m flag is required to enable ES6 module support.");
        print("");
        print("Examples:");
        print("  jsc -m cli-parser.js -- crash.ips");
        print("  jsc -m cli-parser.js -- crash.ips > crash.txt");
        quit(1);
    }

    const inputFile = args[0];

    // Read input file
    let content;
    try {
        content = readFile(inputFile);
    } catch (error) {
        print(`Error: Cannot read file '${inputFile}': ${error.message}`);
        quit(1);
    }

    // Parse and format
    let formatted;
    try {
        const parser = new IPSParser(content);
        parser.parse();
        formatted = parser.formatReport();
    } catch (error) {
        print(`Error: ${error.message}`);
        quit(1);
    }

    // Output to stdout
    print(formatted);
    quit(0);
}

// Run main - pass global arguments (available in jsc after --)
// arguments is only defined if CLI params are passed
const cliArgs = (typeof arguments !== 'undefined') ? arguments : [];
main(cliArgs);
