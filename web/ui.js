document.addEventListener('DOMContentLoaded', function() {
	var req = new XMLHttpRequest();
	req.open('POST', 'http://localhost:8080/start', true)
	req.onreadystatechange = function() {
		if(req.readyState == 4) {
			res = JSON.parse(req.responseText);
			console.log('Got session ' + res.id)
			window.begin_session(res.id)
		}
	}
	req.send(null);

	window.v = new Vue({
		'el': '#container',
		data: { 'contracts': [], 'code': [], 'selectedContract': null, 'cfg': [] },
		'methods': {
			selectContract: function(address, ev) {
				ev.stopPropagation();
				this.selectedContract = address;
				make_request(window.session_id, 'disassemble', {addr: address}, function(dis) {
					v.code = [];
					for(var line of dis) {
						v.code.push({pc: line[0], instr: line[1]});
					}
				});
				make_request(window.session_id, 'cfg', {addr: address}, function(cfg) {
					v.cfg = cfg;
				});
			}
		},
		"components": {
			"cfg-view": {
				"template": '<div class="graph" id="graph"></div>',
				props: ['cfg'],
				mounted: function() {
					this.cy = cytoscape({
						container: this.$el,
						style: [
							{
								selector: 'node',
								style: {
									'background-color': '#666',
									'label': 'data(content)',
									'width': 'label',
									'height': 'label',
									'shape': 'rectangle',
									'text-valign': 'center',
									'text-halign': 'center',
									'text-wrap': 'wrap',
									'text-max-width': '1000px',
									'padding': '16px',
									'background-opacity': 0.2
								}
							},

							{
								selector: 'edge',
								style: {
									'label': 'data(content)',
									'text-wrap': 'wrap',
									'text-max-width': '1000px',
									'curve-style': 'bezier',
									'width': 3,
									'line-color': '#ccc',
									'target-arrow-color': '#ccc',
									'target-arrow-shape': 'triangle',
									'source-endpoint': '180deg',
									'target-endpoint': '0deg',
								}
							}
						],
					});
				},
				watch: {
					cfg: function(val) {
						this.cy.json({elements: val});
						l = this.cy.layout({'name': 'cose'});
						l.run();
					},
				},
			}
		}
	})
})

function make_request(id, path, data, cb) {
	var req = new XMLHttpRequest()
	req.open('POST', 'http://localhost:8080/' + id + '/' + path, true)
	req.setRequestHeader('Content-type', 'application/json')
	req.onreadystatechange = function() {
		if(req.readyState == 4) {
			var res = JSON.parse(req.responseText)
			cb(res)
		}
	}
	req.send(JSON.stringify(data))
}

function begin_session(id) {
	console.log('Session ' + id)
	window.session_id = id;
	make_request(id, 'state', {}, function(o) {
		v.contracts = []
		for(addr in o) {
			v.contracts.push({address: addr})
		}
	})
}
