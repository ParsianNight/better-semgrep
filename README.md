

**SAST Report Analyzer**

This Python script provides functionalities to analyze Static Application Security Testing (SAST) reports, particularly focused on managing and comparing vulnerabilities discovered over time. It is designed to streamline the vulnerability review process by automating the identification of new vulnerabilities, updating a known vulnerabilities database, and optionally removing old vulnerabilities.

**Features:**

1. **Compare Mode:** Compare new SAST reports with an existing database of known vulnerabilities. Unique vulnerabilities are filtered and detailed reports are generated for further review.

2. **Automatic Database Update:** Automatically add IDs of unique vulnerabilities discovered in new reports to the existing vulnerabilities database. This feature can be disabled if needed.

3. **Remove Mode:** Remove old vulnerabilities from the existing database by their ID. Useful for ensuring that previously identified vulnerabilities are retested against newer code changes.

4. **Flexible Usage:** Supports command-line arguments for specifying operation mode (compare, add, or remove), paths to input and output files, and options for managing the update of the vulnerabilities database.

**How to Use:**

1. **Compare Mode:** Run the script in compare mode by specifying the SAST report file and an output file path. Optionally, use the `--disable-update-vulns` flag to prevent automatic updating of the vulnerabilities database.

2. **Add Mode:** Add new vulnerability IDs manually to the existing vulnerabilities database using the `add` mode along with the vulnerability ID.

3. **Remove Mode:** Remove old vulnerability IDs from the existing vulnerabilities database using the `remove` mode along with the vulnerability ID.

**Dependencies:**

- Python 3.x
- argparse (for parsing command-line arguments)

**Usage Example:**

```bash
python sast_report_analyzer.py compare sast_report.json --output filtered_report.json --disable-update-vulns Y
```

**Note:** Ensure the paths to SAST reports and the known vulnerabilities file are correctly specified.

This script is a valuable tool for security teams and developers to efficiently manage and track vulnerabilities identified through SAST analysis.

