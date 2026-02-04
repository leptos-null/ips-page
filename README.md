# ips-page

A web-based tool to parse and display Apple crash reports (`.ips` files) in a human-readable format.

Currently, this repo provides two ways to view a given `.ips` file:

- Plain text, similar to the output in Apple's `Console.app`: <https://leptos-null.github.io/ips-page/text>
- A structured view, with semantic highlighting: <https://leptos-null.github.io/ips-page/structured>

## Local Development

Since this project uses ES6 modules, you'll need to run a local web server to view the pages (modules don't work with `file://` URLs).

Start a local server:
```bash
python3 -m http.server 8000
```

Then open:
- Plain text view: http://localhost:8000/text.html
- Structured view: http://localhost:8000/structured.html

## Command Line Usage

You can also convert `.ips` files to plain text from the command line using JavaScriptCore:

```bash
jsc -m cli-parser.js -- crash.ips > crash.txt
```

This uses the same parser core as the web version, ensuring consistent output.

---

IPS files: https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report

Much of the code in this repo is written by [Claude Code](https://claude.com/product/claude-code). The commits in this repo are intentionally segmented to isolate the authors appropriately.
