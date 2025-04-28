var ANALYSE_APPS = "analyseApps";
var KEY_DETAILS = "keyDetails";
var finalData = {};
var BROWSER = (chrome || browser);
let previousHeight=null;
(function() {
	var su = {
		finalHtml: '',
		globalVars: '',
		fontFamily: '',
		_self: '',
		contentExceeded: false,
		init: function() {
			this.addEventListener();
			this.getAPIKey();
			_self = this;
			this.initialise();
		},
		initialise: function(){
			BROWSER.runtime.onMessage.addListener((request,sender,sendResponse) => {
				if(request.id === "popupClick") {
					this.createIframe();
				}
			})
		},
		getAPIKey: function() {
			//console.log(location)
			if (location.hostname === "whatruns.com" || location.hostname === "localhost") {
				var pathname = location.pathname;
				if (pathname.indexOf("dashboard") !== -1 || pathname.indexOf("search") !== -1) {
					try {
						var apiKey = document.getElementById('wrs_api_key').value;
						var email = document.getElementById('wrs_email').value;
						if (apiKey.trim().length > 0 && email.trim().length > 0) {
							BROWSER.runtime.sendMessage({
								id: KEY_DETAILS,
								subject: {
									api_key: apiKey,
									email: email
								}
							});
						}
					} catch (e) {}
				}
			}
		},
		addEventListener: function() {
			var scriptEl, divEl, html = document.documentElement.outerHTML;
			try {
				divEl = document.createElement('div');
				divEl.setAttribute('id', 'divScriptsUsed');
				divEl.setAttribute('style', 'display: none');

				scriptEl = document.createElement('script');

				scriptEl.setAttribute('id', 'globalVarsDetection');
				scriptEl.setAttribute('src', chrome.runtime.getURL('js/wrs_env.js'));

				divEl.addEventListener('globalVarsEvent', (function(event) {
					var jsonStr = event.target.childNodes[0].nodeValue;
					try {
						var jsonObj = JSON.parse(jsonStr);
						globalVars = jsonObj.environmentVars;
						fontFamily = jsonObj.fontFamily;
					} catch (e) {
						console.log(e);
					}
					document.documentElement.removeChild(divEl);
					document.documentElement.removeChild(scriptEl);

					var finalData = {
						html: html,
						parsedHtml: _self.processHTML(html),
						globalVars: JSON.stringify(globalVars),
						fontFamily: fontFamily,
						href: location.href
					}
					BROWSER.runtime.sendMessage({
						id: ANALYSE_APPS,
						subject: finalData
					});

				}), true);

				document.documentElement.appendChild(divEl);
				document.documentElement.appendChild(scriptEl);

			} catch (e) {
				console.log(e);
			}
		},
		processHTML: function (html) {
			try {
				var $doc = new DOMParser().parseFromString(html, "text/html");
				$doc = _self.traverse($doc);
				var scripts = '';
				var nodes = $doc.getElementsByTagName("script");
				for (index = nodes.length - 1; index >= 0; index--) {
					var src = nodes[index].getAttribute("src");
					if (src) scripts += nodes[index].outerHTML;
					nodes[index].parentNode.removeChild(nodes[index]);
				}
				var element = $doc.getElementsByTagName('input');
				for (index = element.length - 1; index >= 0; index--) {
					element[index].parentNode.removeChild(element[index]);
				}
				html = $doc.documentElement.outerHTML.trim();
				html = html.replace(/\s{2,}/g, ' ');
				if (html.length > 30000) {
					html = html.substring(0, 19000) + html.substring(html.length - 10000, html.length);
				}
				html += scripts;
			} catch (e) {
				console.log(e);
			}
			return html;
		},
		traverse: function (node) {
			try {
				if (node.firstChild) {
					this.traverse(node.firstChild);
				}
				if (node.nodeType === 3) {
					if (node.nodeValue !== '') {
						node.nodeValue = '';
					}
				}
				if (node.nextSibling) {
					this.traverse(node.nextSibling);
				}
			} catch (e) {
				console.log(e);
			}
			return node;
		},
		createIframe: function () {
			const existingIframe=document.getElementById("whatruns-iframe-container-701");
			if(existingIframe) existingIframe.remove();

			const style = document.createElement('style');
			style.textContent = `
				.whatruns-iframe-container-701 {
					position: fixed;
					top: 10px;
					right: 10px;
					z-index: 99999999999;
					width: 460px;
					height: 287px;
					padding: 0px;
					margin: 0px;
					background: white;
					border-radius: 10.6px;
					box-shadow: 0px 1.8px 14px 0.6px rgba(0, 0, 0, 0.20);
					max-height: 500px;
					}

					.whatruns-iframe-container-701 iframe {
					padding: 0px;
					margin: 0px;
					width: 100% ;
					height: 100%;
					border: 0px;
					border-radius: 8px;
					}	
				`;
			document.head.appendChild(style);

			const mainDiv=document.createElement("div");
			mainDiv.id="whatruns-iframe-container-701"
			mainDiv.className="whatruns-iframe-container-701"
			const iframe= document.createElement("iframe");
			iframe.src=BROWSER.runtime.getURL("popup.html");
			iframe.id="whatruns-iframe-701"
			mainDiv.appendChild(iframe);
			document.body.appendChild(mainDiv);

			document.addEventListener("click",this.iframeClose);

			window.addEventListener('message', function(event) {
				if(event.data.iframeContent) {
					previousHeight=event.data.iframeContent;
				}
				
			if (event.data.type === 'adjustHeight') {
				const container = document.getElementById("whatruns-iframe-container-701");
				if (container) {
					if (event.data.height !== "previousHeight") {
						container.style.height = event.data.height + 'px';
					} else {
						container.style.height = previousHeight + 'px';
					}
				}
			}
			});
			
		},
		iframeClose: function (e) {
			const iframeContainer = document.getElementById("whatruns-iframe-container-701");
			if(!iframeContainer.contains(e.target)) {
				iframeContainer.remove();
			}
			document.removeEventListener('click', su.handleOutsideClick)
		}
	}

	su.init();

}());
