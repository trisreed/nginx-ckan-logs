# NGiИX Log File Analysis for CKAN

This script is used to determine common search queries on a CKAN instance 
behind an NGiИX web server.

## Usage

`python3 log.py <INPUT_FILE> <OUTPUT_FILE>`

* `<INPUT_FILE>`: Path to an NGiИX log in `access.log` default format;
* `<OUTPUT_FILE>`: Path to write the output of the analysis.

## Maintenance
Program maintained by Tristan Reed, GitHub username `trisreed`. Free to use 
under GPLv3. Code suffers from many bugs, use at own risk, also ignore my 
awful commit history.