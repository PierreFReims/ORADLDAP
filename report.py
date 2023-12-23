import sys
import json


class Vulnerability:
    def __init__(self,level, id, title, description, recommendation):
        self.level= level
        self.id = id
        self.title = title
        self.description = description
        self.recommendation = recommendation
    
    def display(self):
        print('ID: ',self.id)
        print('LEVEL: ',self.level)
        print('TITLE: ',self.title)
        print('DESCRIPTION: ',self.description)
        print('RECOMMANDATION:',self.recommendation)

class VulnerabilityReport:
    def __init__(self, suffix=None, strategy=None):
        self.strategy = strategy
        self.suffix = suffix
        self.all_vulnerabilities = self.load_vulnerabilities_from_assets("assets/vulnerabilities.json")
        self.vulnerabilities = []

    def add_vulnerability(self, vulnerability_id):
        vulnerability = self.get_vulnerability_by_id(vulnerability_id)
        v = Vulnerability(vulnerability['level'], vulnerability['id'],vulnerability['title'], vulnerability['description'], vulnerability['recommendation'])
        
        self.vulnerabilities.append(v)

    def generate_report(self, output_file='render/report.html'):
        with open(output_file, 'w') as file:
            self.write_html_header(file)
            self.write_report_heading(file)
            self.write_vulnerabilities(file)
            self.write_html_footer(file)

    def write_html_header(self, file):
        file.write('<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<link href="./style.css" rel="stylesheet"><link href="./bootstrap.min.css" rel="stylesheet">\n<meta name="viewport" content="width=device-width, initial-scale=1.0"><meta charset="utf-8"><body>\n')
        file.write('<style> .hidden { display: none; } </style>\n')

    def write_report_heading(self, file):
        file.write("""<nav class="navbar">
  <a class="navbar-brand">
    <img src="./anfsi_logo.jpeg" width="30" height="30" class="d-inline-block align-top rounded ms-2" alt="">
    <span class="text_navbar" >Points de contrôle OpenLDAP</span>
  </a>
</nav>""")
        file.write('<h1 class="text-center">Rapport de sécurité</h1>\n')
        file.write('<div class="container-fluid">')
        if self.suffix is not None:
            file.write('<p>Naming Context: <span>{0}</span></p>\n'.format(self.suffix))
        if self.strategy:
            file.write('<p>Execution Strategy: <span>{0}</span></p>'.format(self.strategy))
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
            row_id = f'vulnRow{vuln.id}'
            description_row_id = f'descriptionRow{vuln.id}'
            recommendation_row_id = f'recommendationRow{vuln.id}'

            file.write(f'<tr class="table-danger" onclick="toggleDetails(\'{row_id}\', \'{description_row_id}\', \'{recommendation_row_id}\')">'
                    f'<th scope="row"><span class="level_{vuln.level} align-middle">{vuln.level}</span></th><td class="text-danger align-middle">{vuln.title}</td><td class="text-danger align-middle">{vuln.id}</td>'
                    f'</tr>')
            # Write Vulnerability description
            file.write(f'<tr id="{description_row_id}" class="table-light" style="display: none;"><td colspan=5><div><h4>Description de la Vulnérabilité</h4><p>{vuln.description}</p></div></td></tr>')
            
            # Write Vulnerability recommendation(s)
            file.write(f'<tr id="{recommendation_row_id}" class="table-primary" style="display: none;"><td colspan=5><div><h4>Recommandation</h4>')
            for recommendation in vuln.recommendation:
                file.write(f'<span><p>{recommendation}</p></span>')
            file.write('</div></td></tr>')
        
        file.write('</tbody></table>')
        file.write('</div>')
        file.write('<script>'
               'function toggleDetails(rowId, descriptionRowId, recommendationRowId) {'
               'var descriptionRow = document.getElementById(descriptionRowId);'
               'var recommendationRow = document.getElementById(recommendationRowId);'
               'descriptionRow.style.display = (descriptionRow.style.display === "none") ? "table-row" : "none";'
               'recommendationRow.style.display = (recommendationRow.style.display === "none") ? "table-row" : "none";'
               '}'
               '</script>')

    def write_html_footer(self, file):
        file.write('</body>\n</html>\n')

    def get_vulnerability_by_id(self, vulnerability_id):
        for vulnerability in self.all_vulnerabilities:
            if vulnerability.get('id') == vulnerability_id:
                return vulnerability
        return None
    
    def load_vulnerabilities_from_assets(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as json_file:
                data = json.load(json_file)
                return data.get("vulnerabilities", [])
        except FileNotFoundError:
            print(f"Error: File not found - {file_path}")
            return []
        except json.JSONDecodeError:
            print(f"Error: Failed to decode JSON from file - {file_path}")
            return []