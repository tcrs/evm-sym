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
document.addEventListener('DOMContentLoaded', function() {
	window.vue = new Vue({
		'el': '#container',
		data: { 'contracts': [], 'code': [], 'selectedContract': null, 'cfg': [], 'session': null },
		mounted: function() {
			var v = this;
			var req = new XMLHttpRequest();
			req.open('POST', 'http://localhost:8080/start', true)
			req.onreadystatechange = function() {
				if(req.readyState == 4) {
					res = JSON.parse(req.responseText);
					v.session = res.id;
				}
			}
			req.send(null);
		},
		watch: {
			'session': function(session_id) {
				console.log('Session ' + session_id)
				if(session_id === null) {
					this.contracts = [];
				}
				else {
					var v = this;
					make_request(session_id, 'contracts', {}, function(o) {
						v.contracts = []
						for(var i = 0; i < o.length; i += 1) {
							v.contracts.push({address: o[i]})
						}
					})
				}
			},
			'selectedContract': function(address) {
				var v = this;
				make_request(v.session, 'disassemble', {addr: address}, function(dis) {
					v.code = [];
					for(var line of dis) {
						v.code.push({pc: line[0], instr: line[1]});
					}
				});
				make_request(v.session, 'cfg', {addr: address}, function(cfg) {
					v.cfg = cfg;
				});
			},
		},
		'methods': {
			selectContract: function(address, ev) {
				ev.stopPropagation();
				this.selectedContract = address;
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
						l = this.cy.layout({
							'name': 'breadthfirst',
							'directed': true,
							'nodeDimensionsIncludeLabels': true,
						});
						l.run();
					},
				},
			}
		}
	})
})
