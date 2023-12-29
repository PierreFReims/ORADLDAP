document.addEventListener('DOMContentLoaded', function () {
    // Load the data from the JSON file
    fetch('../ldap_data.json')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('network');
            const visData = {
                nodes: new vis.DataSet(data.nodes),
                edges: new vis.DataSet(data.edges),
            };
            var options = {};
            const network = new vis.Network(container, visData, options);
        })
        .catch(error => console.error('Error loading LDAP data:', error));
});

