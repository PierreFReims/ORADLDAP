class Vulnerability:
    def __init__(self,level, id, title, description, recommendation):
        self.level= level
        self.id = id
        self.title = title
        self.description = description
        self.recommendation = recommendation

class VulnerabilityReport:
    def __init__(self, suffix=None):
        self.suffix = suffix
        self.vulnerabilities = []

    def add_vulnerability(self, level=None, id=None, title=None, description=None, recommendation=None):
        vulnerability = Vulnerability(level, id, title, description, recommendation)
        self.vulnerabilities.append(vulnerability)

    def generate_report(self, output_file='render/report.html'):
        with open(output_file, 'w') as file:
            self.write_html_header(file)
            self.write_report_heading(file)
            self.write_vulnerabilities(file)
            self.write_html_footer(file)

    def write_html_header(self, file):
        file.write('<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<link href="./bootstrap.min.css" rel="stylesheet">\n<meta charset="utf-8"><body>\n')
        file.write('<style> .hidden { display: none; } </style>\n')

    def write_report_heading(self, file):
        file.write('<h1 class="text-center">Rapport de sécurité</h1>\n')
        if self.suffix is not None:
            file.write('<p class="text-center">{0}</p>\n'.format(self.suffix))

    def write_vulnerabilities(self, file):
        file.write("""<table class="table table-bordered table-light">
  <thead>
    <tr>
      <th scope="col">Niveau</th>
      <th scope="col">Titre</th>
      <th scope="col">id</th>
    </tr>
  </thead>
  <tbody>""")
        for vuln in self.vulnerabilities:
            # Use unique IDs for rows and data
            row_id = f'vulnRow{vuln.id}'
            description_row_id = f'descriptionRow{vuln.id}'
            recommendation_row_id = f'recommendationRow{vuln.id}'

            file.write(f'<tr class="table-danger" onclick="toggleDetails(\'{row_id}\', \'{description_row_id}\', \'{recommendation_row_id}\')">'
                    f'<th scope="row">{vuln.level}</th><td>{vuln.title}</td><td>{vuln.id}</td>'
                    f'</tr>')

            # Add JavaScript to toggle visibility of the hidden rows
            file.write(f'<tr id="{description_row_id}" class="table-secondary" style="display: none;"><td colspan=5><div><h2>Description de la Vulnérabilité</h2><p>{vuln.description}</p></div></td></tr>')
            file.write(f'<tr id="{recommendation_row_id}" class="table-primary" style="display: none;"><td colspan=5><div><h2>Recomandation</h2><p>{vuln.recommendation}</p></div></td></tr>')
        file.write('<script>'
               'function toggleDetails(rowId, descriptionRowId, recommendationRowId) {'
               'var descriptionRow = document.getElementById(descriptionRowId);'
               'var recommendationRow = document.getElementById(recommendationRowId);'
               'descriptionRow.style.display = (descriptionRow.style.display === "none") ? "table-row" : "none";'
               'recommendationRow.style.display = (recommendationRow.style.display === "none") ? "table-row" : "none";'
               '}'
               '</script>')

        file.write('</tbody></table>')

    def write_html_footer(self, file):
        file.write('</body>\n</html>\n')