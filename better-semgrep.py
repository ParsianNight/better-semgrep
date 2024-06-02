import json
import argparse

class SASTReportAnalyzer:
    def __init__(self, known_vuln_file, mode):
        self.known_vuln_file = known_vuln_file
        self.mode = mode

        self.known_vuln_ids = self.load_known_vuln_ids()

    def load_known_vuln_ids(self):
        
        try:
            with open(self.known_vuln_file, 'r') as f:
                return set(json.load(f))
            print()
        except FileNotFoundError:
            if self.mode == "remove" :
                print(f"Error: {self.known_vuln_file} not found. Specify a valid path")
                exit(1) 
            print("old vulnerabilites file doesn't exist, if it's not your first time running this\nMake sure you are passing the right path to --known-vulns.\n\n")
            return set()

    def save_known_vuln_ids(self):
        with open(self.known_vuln_file, 'w') as f:
            json.dump(list(self.known_vuln_ids), f)

    def compare(self, sast_report_file, output_file, update_known_vuln):
        # Load the SAST report
        with open(sast_report_file, 'r') as f:
            report = json.load(f)

        # Filter unique vulnerabilities
        unique_vulns = [vuln for vuln in report['vulnerabilities'] if vuln['id'] not in self.known_vuln_ids]

        # Add IDs of unique vulnerabilities to the known_vuln_ids set
        for vuln in unique_vulns:
            self.known_vuln_ids.add(vuln['id'])
        
        # Save unique vulnerabilities to the output file
        with open(output_file, 'w') as f:
            json.dump({'vulnerabilities': unique_vulns}, f, indent=4)

        print(f"Filtered report saved to {output_file} with {len(unique_vulns)} unique vulnerabilities.")

        # Save updated known vulnerability IDs back to the known vulnerabilities file
        if(update_known_vuln == "true"):
            self.save_known_vuln_ids()  
            

    def remove_known_vuln(self, vuln_id):
        if vuln_id in self.known_vuln_ids:
            self.known_vuln_ids.remove(vuln_id)
            self.save_known_vuln_ids()
            print(f"Removed vulnerability {vuln_id} from the known list.")
        else:
            print(f"Vulnerability {vuln_id} not found in the known list.")
            
    def add_known_vuln(self, vuln_id):
        if vuln_id not in self.known_vuln_ids:
            self.known_vuln_ids.add(vuln_id)
            self.save_known_vuln_ids()
            print(f"Added vulnerability {vuln_id} to the known list.")
        else:
            print(f" vuln {vuln_id} already on list.")            

def main():
    parser = argparse.ArgumentParser(description='SAST Report Analyzer')
    parser.add_argument('mode', choices=['compare', 'add', 'remove'], help='Operation mode: compare, add, or remove')
    parser.add_argument('sast_report', help='Path to the SAST report file')
    parser.add_argument('--output', help='Path to save the filtered report (for compare mode)')
    parser.add_argument('--known-vulns', default='known_vulns.json', help='Path to the known vulnerabilities file')
    parser.add_argument('--vuln-id', help='SHA256 ID of the vulnerability to remove (for remove mode)')
    parser.add_argument('--disable-update-vulns',choices=['Y', 'N'], help='when using compare, get a report without adding new vulnerabities ids to your local vuln db.')

    args = parser.parse_args()

    analyzer =  SASTReportAnalyzer(args.known_vulns,args.mode)
    if args.mode == 'compare':
        if not args.output:
            print("Error: Output file path is required for compare mode.")
            return
        if args.disable_update_vulns == 'Y':
            analyzer.compare(args.sast_report, args.output, "false")
        else:
            analyzer.compare(args.sast_report, args.output, "true")
    elif args.mode == 'add':
        if not args.vuln_id:
            print("Error: Vulnerability ID is required for add mode.")
            return
        analyzer.add_known_vuln(args.vuln_id)
    elif args.mode == 'remove':
        if not args.vuln_id:
            print("Error: Vulnerability ID is required for remove mode.")
            return
        analyzer.remove_known_vuln(args.vuln_id)

if __name__ == '__main__':
    main()
