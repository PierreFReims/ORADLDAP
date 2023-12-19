class Vulnerability:
    def __init__(self, title, description, recommendation):
        self.title = title
        self.description = description
        self.recommendation = recommendation

class VulnerabilityReport:
    def __init__(self, suffix=None):
        self.suffix = suffix
        self.vulnerabilities = []

    def add_vulnerability(self, level=None, vulnerability_id=None, title=None, description=None, recommendation=None):
        vulnerability = Vulnerability(title, description, recommendation)
        self.vulnerabilities.append(vulnerability)

    def generate_report(self, output_file='render/report.html'):
        with open(output_file, 'w') as file:
            self.write_html_header(file)
            self.write_report_heading(file)
            self.write_vulnerabilities(file)
            self.write_html_footer(file)

    def write_html_header(self, file):
        file.write('<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<link href="./bootstrap.min.css" rel="stylesheet">\n<body>\n')
        file.write('<style> .hidden { display: none; } </style>\n')

    def write_report_heading(self, file):
        file.write('<h1 class="text-center">Rapport de securite</h1>\n')
        if self.suffix is not None:
            file.write('<p class="text-center">{0}</p>\n'.format(self.suffix))

    def write_vulnerabilities(self, file):
        for idx, vulnerability in enumerate(self.vulnerabilities, start=1):
            file.write('<div class="p-5 mb-4 bg-body-tertiary rounded-3">\n')
            self.write_section(file, 'Title', vulnerability.title, idx)
            self.write_section(file, 'Details', f'{vulnerability.description}<br>{vulnerability.recommendation}', idx)
            file.write('</div>\n')

        # Write JavaScript to toggle visibility
        file.write('<script>\n')
        file.write('function toggleVisibility(idx) {\n')
        file.write('  var detailsDiv = document.getElementById("details_" + idx);\n')
        file.write('  detailsDiv.style.display = (detailsDiv.style.display === "none") ? "block" : "none";\n')
        file.write('}\n')
        file.write('</script>\n')

    def write_section(self, file, heading, content, idx):
        file.write(f'<h2 onclick="toggleVisibility({idx})" style="cursor: pointer;">{heading}</h2>\n')
        file.write(f'<div id="details_{idx}" class="hidden">\n')
        file.write(f'  <p>{content}</p>\n')
        file.write('</div>\n')

    def write_html_footer(self, file):
        file.write('</body>\n</html>\n')