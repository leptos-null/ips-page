"use strict";

function processOnClick() {
    const textInputElm = document.getElementById("ips_text_input");
    const textOutputElm = document.getElementById("ips_output");

    const inputText = textInputElm.innerText;
    const firstLineBreak = inputText.indexOf("\n");

    let inputHead = "";
    let inputTail = "";
    if (firstLineBreak == -1) {
        inputHead = inputText;
    } else {
        inputHead = inputText.slice(0, firstLineBreak);
        inputTail = inputText.slice(firstLineBreak);
    }

    try {
        const parsed = JSON.parse(inputTail);
        const prettyPrint = JSON.stringify(parsed, null, 4);
        textOutputElm.innerText = prettyPrint;
    } catch (error) {
        if (inputTail.trim().length > 0) {
            textOutputElm.innerText = inputTail;
        } else {
            textOutputElm.innerText = inputHead;
        }
    }
}
