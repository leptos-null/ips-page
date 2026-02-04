import { IPSParser } from './ips-parser-core.js';

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
