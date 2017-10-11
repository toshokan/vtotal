# vtotal
A small text-based/command-line utility to send files to VirusTotal, manage response codes, and return results when ready. 

## Dependencies
This program is written in C and depends on libcurl for networking.

## Usage
Use `vtotal scan [filename]` to scan a file and add its id to the list to check.
Use `vtotal results list` to list previously scanned files and view results.
