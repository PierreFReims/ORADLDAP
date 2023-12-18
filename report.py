class VulnerabilityReport:
    def __init__(self):
        self.vulnerabilities = []

    def add_vulnerability(self, level=None, vulnerability_id=None, title=None, description=None, recommendation=None):
        vulnerability = {
            'level': level,
            'id': vulnerability_id,
            'title': title,
            'description': description,
            'recommendation': recommendation
        }
        self.vulnerabilities.append(vulnerability)

    def generate_report(self, output_file='render/report.html'):
            # Open the output file for writing
            with open(output_file, 'w') as file:
                # Write the HTML header
                file.write('<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<link href="./bootstrap.min.css" rel="stylesheet">\n<body>\n')
                #    
                # Write a heading for the report
                file.write('<h1>Vulnerability Report</h1>\n')

                # Write the vulnerabilities as an ordered list
                file.write('<ol>\n')
                for vulnerability in self.vulnerabilities:
                    file.write(f'<li>\n')
                    file.write(f'<h1>description de la vulnérabilité</h1>\n')
                    file.write(f'<p>{vulnerability["description"]}</p>\n')
                    file.write(f'<h1>recommandation</h1>\n')
                    file.write(f'<p> {vulnerability["recommendation"]}<p>\n')
                    file.write('</li>\n')
                file.write('</ol>\n')
                # Write the HTML footer
                file.write('</body>\n</html>\n')
