import { 
	BROWSER, DOMAIN_NAME, ANALYSE_APPS, 
	GET_DETECTED_APPS, GET_NOTIFICATION_MESSAGE,
	GET_HOST_NAME, GET_SITE_DATA, KEY_DETAILS, FORM,
	GET_SITE_APPS, ANALYSE_SITE_DATA, ANALYSE_BULK_SITE_DATA,
	SITE_DATA_SYNC_LIMIT, IG_CHECK_STORES, IG_GET_STORES_DATA,
	IG_SYNC_LIMIT, IG_QUEUE_DOMAIN, IG_SYNC_TIME_LIMIT,
	EXCLUDED_DOMAINS, INITIATE_DATA_SDK, PROCESS_DATA_SDK,
	SEND_DATA_SDK, COLLECT_SDK_DATA, PROCESS_DATA_SDK_CAPTIFY,
	SEND_CHECKOUT_DATA_SDK, COLLECT_SDK_CHECKOUT_DATA, REVIEW_FEATURE_DATA
} from './global.constants.es6.js';

var tab, responseHeadersCache = {},
	tabData = {},
	tabResponseData = {};
var finalData = {};
var _this = null;
var hostname = '';
var invalidDomains = ["localhost", "127.0.0.1", "0.0.0.0", "newtab"];
var loginKey = "login_session";
var emailExcludedDomains = [];
(function () {
	var s = {
		commonTechs: null,
		init: function () {
			_this = s;
			// this.addContentScripts();
			this.addChromeListeners();
			this.initListener();
		},
		addContentScripts: function () {
			// Run content script
			var callback = tabs => {

				tabs.forEach(tab => {
					if (tab.url.match(/^https?:\/\//)) {
						browser.tabs.executeScript(tab.id, {
							file: 'js/content.js'
						});
					}
				})
			};

			try {
				BROWSER.tabs.query({})
					.then(callback)
					.catch(error => console.log(error));
			} catch (e) {
				BROWSER.tabs.query({}, callback);
			}
		},
		initListener: function() {
			BROWSER.action.onClicked.addListener(() => {
				BROWSER.tabs.query({active:true, currentWindow:true},(tabs) => {
					const url= tabs[0].url;
					BROWSER.tabs.sendMessage(tabs[0].id,{id:"popupClick", url});
				})
			}
			)
		},
		addChromeListeners: function () {
			BROWSER.webRequest.onCompleted.addListener(function (details) {
				var tabId = details.tabId;
				var url = _this.beautifyURL(details.url);
				_this.removeCurrentResponse(tabId);
				if (details.tabId != "undefined") {
					_this.removeTabData(details.tabId);
				}
				hostname = _this.getRootHostName(url);
				_this.getSiteAppsFromServer(details.tabId, _this.getRawHostName(url), url);
				// _this.invokeSiteAppAnalyser(_this.getRawHostName(url), url);
				var currentResponseHeaders = {}
				if (typeof details.responseHeaders != "undefined") {
					var responseHeadersArr = details.responseHeaders;
					responseHeadersArr.forEach(function (key) {
						currentResponseHeaders[key.name.toLowerCase()] = key.value || '' + key.binaryValue;
					});
					if (responseHeadersCache.length > 10) _this.resetHeadersCache();
					if (responseHeadersCache[url] === undefined) {
						responseHeadersCache[url] = {};
					}
					Object.keys(currentResponseHeaders).forEach(function (key) {
						responseHeadersCache[url][key] = currentResponseHeaders[key];
					});
				}

			}, {
				urls: ['http://*/*', 'https://*/*'],
				types: ['main_frame']
			}, ['responseHeaders']);

			BROWSER.runtime.onMessage.addListener(function (request, sender, sendResponse) {
				if (typeof request.id != "undefined") {
					if (request.id == ANALYSE_APPS) {
						tab = sender.tab;
						var tabId = sender.tab.id;
						let href = _this.beautifyURL(tab.url);
						hostname = _this.getRootHostName(href);
						if (responseHeadersCache[href] !== undefined) {
							request.subject.responseHeaders = responseHeadersCache[href];
						} else request.subject.responseHeaders = {};
						var title = "Please enter a website on your browser address bar";
						var tabId = tab.id;
						if (hostname != null) {
							title = "What runs " + hostname;
						}
						BROWSER.action.setTitle({
							"title": "What runs " + hostname,
							"tabId": tabId
						});

						_this.analyseSiteApps(tabId, _this.getRawHostName(href), hostname, href, request.subject, _this.processData);

					} else if (request.id == GET_DETECTED_APPS) {
						var tab = request.tab;
						var tabId = tab.id;
						if (tabData[tabId]) {
							var response = {
								tabTechs: tabData[tabId]
							}
							sendResponse(response);
						} else {

							let href = _this.beautifyURL(tab.url);
							sendResponse(_this.getUrlDetails(href));
						}
					} else if (request.id == GET_HOST_NAME) {
						tab = request.tab;
						let href = _this.beautifyURL(tab.url);
						sendResponse(_this.getUrlDetails(href));
					} else if (request.id == GET_SITE_DATA) {
						var tab = request.tab;
						var tabId = tab.id;
						var responseData = {};
						if (tabData[tabId] && typeof tabData[tabId] != "undefined") {
							responseData['data'] = tabData[tabId];
						} else {
							responseData['msg'] = "Data Not Available";
						}
						sendResponse(responseData);
					} else if (request.id == GET_NOTIFICATION_MESSAGE) {
						tab = sender.tab;
						var tabId = sender.tab.id;
						var responseData = (typeof tabData[tabId] != "undefined" && tabData[tabId] != null) ? tabData[tabId] : tabResponseData[tabId];
						sendResponse(responseData);
					} else if (request.id == KEY_DETAILS) {
						_this.setUserDetails(request.subject);
						return true;
					} else if (request.id == FORM) {
						var formDetails = request.subject;
						_this.postFormData(formDetails.url, formDetails.data, function (response) {
							sendResponse(response);
						})
						return true;
					} else if (request.id == IG_CHECK_STORES) {
						let tab = sender.tab;
						let href = _this.beautifyURL(tab.url);
            			_this.checkAndProcessIGStore(href, request.data)
					} else if (request.id == INITIATE_DATA_SDK) {
						let tabId = sender.tab.id;
						let href = _this.beautifyURL(sender.tab?.url);
						_this.initiateDataSDK(href, tabId)
					} else if (request.id == SEND_DATA_SDK) {
						_this.sendDataToServer(request.data)
					} else if (request.id == SEND_CHECKOUT_DATA_SDK) {
						_this.sendCheckoutDataToServer(request.data)
					} else if (request.id == "reviewData") {
						_this.reviewFeatureData(request.data)
					}
				}
			});

			BROWSER.tabs.onRemoved.addListener(function (tabId) {
				tabData[tabId] = null;
				tabData[tabId] = null;
			});

			BROWSER.runtime.setUninstallURL(DOMAIN_NAME + 'uninstall');


		},
		sendCheckoutDataToServer: async function name(data) {
			try {
				await _this.makeRequest({
					type: "POST",
					url: COLLECT_SDK_CHECKOUT_DATA,
					reqBody: data
				});
			} catch (e) {
				console.log(e)
			}
		},
		sendDataToServer: async function name(data) {
			try {
				await _this.makeRequest({
					type: "POST",
					url: COLLECT_SDK_DATA,
					reqBody: data
				});
			} catch (e) {
				console.log(e)
			}
		},
		initiateDataSDK: async function (href, tabId) {
			BROWSER.tabs.sendMessage( tabId, {
				id: PROCESS_DATA_SDK_CAPTIFY,
				data: {}
			}, function (response) { return true });
			try {
				function hasMatch(inputString, regexPattern) {
					const regex = new RegExp(regexPattern);
					return regex.test(inputString);
				}
				// get tab data
				const tabData = tabResponseData[tabId];
				if (tabData && tabData.response) {
					const tabResp = this.strToJson(tabData.response);
					if (tabResp && tabResp?.dom_data && tabResp?.dom_data?.page_regex
						&& tabResp?.dom_data?.page_regex.length > 0) {
						const pageDoms = tabResp?.dom_data?.dom_regex || []
						for (const p_regex of tabResp?.dom_data?.page_regex) {
							const pageSlug = p_regex?.slug;
							const isMatch = hasMatch(href, p_regex?.regex);
							if (isMatch && pageDoms.length > 0) {
								// send message back to data_sdk to process doms
								BROWSER.tabs.sendMessage( tabId, {
									id: PROCESS_DATA_SDK,
									data: { matchPage: pageSlug, doms: pageDoms, rawData: tabResp }
								}, function (response) { });
							}
						}
					}
				}
				// get dome fields
				// match page_regex
				// call content script to collect data and call back

			} catch (e) {
				console.log(e)
			}
		},
    /**
     * Check IG store ot not
     */
    checkAndProcessIGStore: async function (href, storeData) {
      try {
        let CurrentUrl = storeData.url;
        let bypassSyncRestriction = false;
        let domainData = _this.getUrlDetails(href);
        let dateNow = new Date();
        let storeList = await _this.getLocalStorageItem2('IGStores');
        let lastServerSyncStr = (await _this.getLocalStorageItem2('IGLastServerSync')) || null;
        let lastServerSync =  lastServerSyncStr ? new Date(lastServerSyncStr): null;
        let syncTimeOutSec = IG_SYNC_TIME_LIMIT * 60;
        if (lastServerSync && lastServerSync !== null) {
          let dif = dateNow.getTime() - lastServerSync.getTime();
          let lastSync = Math.abs(dif/1000);
          if (lastSync >= syncTimeOutSec) bypassSyncRestriction = true;
        } else bypassSyncRestriction = true;
        if (Array.isArray(storeList)) {
          let dataString = await _this.getLocalStorageItem2('IGStoreSyncDate');
          let lastSyncDate = dataString ? new Date(dataString): null;
          let diffDays = dateNow.getDate() - lastSyncDate.getDate(); 
          if (diffDays > 3) storeList = await _this.syncIGStores();
        } else storeList = await _this.syncIGStores();
        if (storeList.includes(domainData.rawhostname)) {
          let IGProdData = await _this.getLocalStorageItem2('igProdData');
          if (IGProdData && IGProdData.url_array && IGProdData.url_array.length >0) {
            let lookup = IGProdData.url_array.filter(pData => pData.url == CurrentUrl);
            if (lookup.length <= 0)
            IGProdData["url_array"] = [...IGProdData.url_array, storeData]
            if (IGProdData.url_array.length >= IG_SYNC_LIMIT || bypassSyncRestriction === true) {
              // perform api cal to ig and clear the localstorage
              // send product details
              await _this.makeRequest({
                type: "POST",
                url: IG_QUEUE_DOMAIN,
                reqBody: IGProdData
              });
              _this.setLocalStorageItem2("IGLastServerSync", dateNow.toString());
              _this.removeLocalStorageItem2('igProdData');
            } else {
              _this.setLocalStorageItem2('igProdData', IGProdData);
            }
          } else {
            IGProdData =  { url_array: [storeData] }
            _this.setLocalStorageItem2('igProdData', IGProdData);
          }
        }
      } catch (e) {
        console.log(e)
      }
    },
    syncIGStores: async function() {
      let storesList = [];
      try {
        let storesListResp = await _this.makeRequest({
          type: 'GET', url: IG_GET_STORES_DATA
        });
        if (storesListResp && storesListResp.status === 200) {
          _this.setLocalStorageItem2("IGStores", storesListResp.stores);
          _this.setLocalStorageItem2("IGStoreSyncDate", new Date().toString());
          storesList = storesListResp.stores;
        }
      } catch (e) {
        console.log(e)
      }
      return storesList;
    },
    setLocalStorageItem2: function(key, value) {
      return chrome.storage.local.set({[key]: value});
    },
    getLocalStorageItem2: function(key) {
      return new Promise((resolve) => {
        return chrome.storage.local.get(key, data => {
          return resolve(data[key]||null);
        });
      });
    },
    removeLocalStorageItem2: function(key) {
      return new Promise((resolve) => {
        return chrome.storage.local.remove(key, data => {
          return resolve(data||null);
        });
      });
    },
    makeRequest: async function(params) {
      let { type='GET', url, headers={}, reqBody={} } = params;
      let response = {status: 599, msg: "Error"}
      try {
        // add content type to headers
        if (!("Content-Type" in headers))
          headers['Content-Type'] = 'application/json';
        let fetchData = {
            method: type,
            body: JSON.stringify(reqBody),
            headers: headers,
        }
        // remove body for GET
        if (type === 'GET')
          delete fetchData['body'];
        // meke request
        await fetch(url, fetchData)
        .then(res => res.json())
        .then(json => {response = json;})
        .catch(err => {
          console.log(err);
          response.msg = err;
        });
      } catch (e) {
        console.log(3);
        response.msg = e.toString();
        return;
      }
      return response;
    },
		invokeSiteAppAnalyser: function (rawhostname, href, data) {
			if (!_this.isValidDomain(rawhostname) || rawhostname === undefined) return false;
			var newData = _this.getUrlDetails(href, rawhostname);
			_this.getUserDetails(function (item) {
				newData = _this.appendUserDetails(newData, item);
				try {
					if (typeof data === "undefined") data = {};
					Object.keys(newData).forEach(function (key) {
						data[key] = newData[key];
					});
					_this.getLocalStorageItem("syncSiteData", async function (sitesData) {
						var parsedSiteData = (sitesData.hasOwnProperty("syncSiteData")) ? _this.parseJsonStr(sitesData["syncSiteData"]) : {};
						var keyLength = (typeof parsedSiteData != "undefined" && parsedSiteData != null) 
							? Object.keys(parsedSiteData).length : 0;
						if (data.hasOwnProperty("rawhostname")){
							let newKey = data["rawhostname"];
							parsedSiteData[newKey] = data
							var dataString = JSON.stringify(parsedSiteData)
							await _this.storeDataInLocal({ "syncSiteData": dataString });
							if (keyLength >= SITE_DATA_SYNC_LIMIT) {
								fetch(ANALYSE_BULK_SITE_DATA, {
									method: 'POST',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify({ site_data: dataString })
								}).then(response => {
									_this.removeLocalStorageItem("syncSiteData");
								})
							}
						}
					});
				} catch (e) {
					console.log(e);
				}
			});
		},
		getSiteAppsFromServer: function (tabId, rawhostname, href, data) {
			// verify domain
			if (!_this.isValidDomain(rawhostname) || rawhostname === undefined) return false;
			// do nothing if the domain is an excluded domain
			if (EXCLUDED_DOMAINS.indexOf(rawhostname) > -1) return false;
			var newData = _this.getUrlDetails(href, rawhostname);
			_this.getUserDetails(function (item) {
				newData = _this.appendUserDetails(newData, item);
				try {
					fetch(GET_SITE_APPS, {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: 'data=' + encodeURIComponent(JSON.stringify(newData))
					}).then(response => {
						if (response.ok) {
							return response.text();
						} else {
							throw new Error('Network response was not ok.');
						}
					}).then(responseText => {
						try {
						  if (typeof data === "undefined") data = {};
						  Object.keys(newData).forEach(function(key) { data[key] = newData[key]});
						  _this.getSiteAppsCallBack(tabId, responseText, rawhostname, hostname, href, data);
						} catch (e) {
						  console.log(e);
						}
					}).catch(error => {
						console.log('getSiteAppsFromServer error:', error);
					});
				} catch (e) {
					console.log(e);
				}
			});
		},
		appendUserDetails: function (newData, item) {
			try {
				Object.keys(item).forEach(function (key) {
					newData[key] = btoa(item[key]);
				});
				newData['encode'] = true;
			} catch (e) {
				console.log(e);
			}
			return newData;
		},
		getUserDetails: function (cb) {
			_this.getLocalStorageItem(loginKey, function (item) {
				var returnData = {};
				try {
					var data = (item.hasOwnProperty(loginKey)) ? _this.parseJsonStr(item[loginKey]) : {};
					var email = (typeof data.email != "undefined") ? data.email : null;
					var api_key = (typeof data.api_key != "undefined") ? data.api_key : null;
					if (email && api_key) {
						returnData['email'] = email;
						returnData['api_key'] = api_key;
					}
				} catch (e) {
					console.log(e);
				}
				cb(returnData);
			});
		},
		postFormData: function (url, data, callback) {
			fetch(url, {
				method: 'POST',
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: new URLSearchParams(data)
			})
			.then(response => response.json())
			.then(data => {callback(data)})
			.catch(error => {console.error('postFormData error:', error)});
		},
		parseJsonStr: function (str) {
			try {
				return JSON.parse(str);
			} catch (e) {}
			return null;
		},
		setUserDetails: function (data) {
			var itemData = {
				"login_session": JSON.stringify(data)
			};
			_this.storeDataInLocal(itemData);

		},
		storeDataInLocal: function (data) {
			BROWSER.storage.local.set(data);
		},
		removeLocalStorageItem: function (data) {
			BROWSER.storage.local.remove(data);
		},
		getLocalStorageItem: function (key, callback) {
			BROWSER.storage.local.get(key, callback);
		},
		getSiteAppsCallBack: function (tabId, response, rawhostname, hostname, href, data) {
			try {
				let currentResponse = {
					response: response,
					data: data
				};
				tabResponseData[tabId] = currentResponse;
			} catch (e) {
				console.log(e);
			}
		},
		analyseSiteApps: function (tabId, rawhostname, hostname, href, data, callback, retry = false) {
			try {
				if (tabResponseData[tabId] != null) {
					var finalData = {};
					Object.keys(data).forEach(function (key) {
						finalData[key] = data[key];
					});
					var currentTabResponse = tabResponseData[tabId];
					var responseData = currentTabResponse.data;
					if (responseData != null) {
						Object.keys(responseData).forEach(function (key) {
							finalData[key] = data[key];
						});
					}
					if (typeof currentTabResponse.response != "undefined") {
						var originalResponse = currentTabResponse.response;
						originalResponse = this.strToJson(originalResponse);
						if (typeof originalResponse.apps != "undefined") {
							var apps = originalResponse.apps;
							apps = (typeof apps === "string") ? this.strToJson(apps) : apps;
							if (typeof apps === "object") finalData['response'] = apps;
						}
					}
					callback(tabId, tabResponseData[tabId].response, rawhostname, hostname, href, finalData);
				} else if (retry !== true){
					// add a 3 sec delay and call again
					// sometimes the server will take some time to respons to api call
					// this should run only once if the data get delayed
					// setTimeout(() => {
					// 	_this.analyseSiteApps(tabId, rawhostname, hostname, href, data, callback, true);
					// }, 3000);
				}
			} catch (e) {
				console.log(e);
			}

		},
		strToJson: function (str) {
			try {
				return JSON.parse(str) || {};
			} catch (e) {
				console.log(e);
			}
			return {};
		},
		analyseSiteDataFromServer: function (tabId, rawhostname, hostname, href, data) {
			_this.beautifyAndStoreData(tabId, rawhostname, hostname, href, data);
			if (tabData[tabId] && typeof tabData[tabId] != "undefined") {
				data = tabData[tabId];
			}
			try {
				fetch(ANALYSE_SITE_DATA, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: 'data=' + encodeURIComponent(JSON.stringify(data))
				}).then(response => {
					if (response.ok) {
					  return response.text();
					} else {
					  throw new Error('Network response was not ok.');
					}
				}).then(responseText => {
					try {
					  s.processResponseData(tabId, responseText, hostname, data.fontFamily, href);
					} catch (e) {
					  console.error('Error processing response data:', e);
					}
				}).catch(error => {
				console.error('analyseSiteDataFromServer error:', error);
				});
			} catch (e) {
				console.log(e);
			}
		},

		beautifyAndStoreData: function (tabId, rawhostname, hostname, href, data) {
			try {
				data.hostname = hostname;
				data.rawhostname = rawhostname;
				data.url = href;
				data.html = data.parsedHtml;
				tabData[tabId] = data;
			} catch (e) {
				console.log(e);
			}
		},
		postData: function (type, url, data, callback) {
			fetch(url, {
				method: type,
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: new URLSearchParams(data)
			})
			.then(response => response.json())
			.then(data => {callback(data)})
			.catch(error => {console.error('postFormData error:', error)});
		},
		removeGetParams: function (url) {
			try {
				return url.split("?")[0];
			} catch (e) {
				console.log(e);
			}
			return url;
		},
		processData: function (tabId, response, rawhostname, hostname, href, data) {
			try {
				response = (typeof response === "object") ? response : JSON.parse(response) || {};
				if (response.status) {
					_this.processResponseData(tabId, response, hostname, data.fontFamily, href);
				} else {
					_this.analyseSiteDataFromServer(tabId, rawhostname, hostname, href, data);
				}
				_this.beautifyAndStoreData(tabId, rawhostname, hostname, href, data);
			} catch (e) {
				console.log(e);
			}
		},
		processResponseData: function (tabId, response, hostname, fontFamily, href) {
			try {
				var res = response;
				if (typeof response != "object") var res = JSON.parse(response) || {};
				if (typeof res.apps != "undefined") res = JSON.parse(res.apps) || {};
				else res = {};

				var urlDetails = _this.getUrlDetails(href);
				var data = {
					hostname: hostname,
				}
				if (typeof tabData[tabId] != "undefined") {
					var currentTabData = tabData[tabId] || {};
					Object.keys(currentTabData).forEach(function (key) {
						data[key] = currentTabData[key];
					});
				}
				Object.keys(urlDetails || {}).forEach(function (key) {
					data[key] = urlDetails[key];
				});
				if (Object.keys(res || {}).length > 0) {
					data['response'] = res;
				}
				if (typeof fontFamily != "undefined") {
					data.fontFamily = fontFamily;
				}

				tabData[tabId] = data;
				_this.removeCurrentResponse(tabId);

			} catch (e) {
				console.log(e);
			}
		},
		removeTabData: function (tabId) {
			try {

				if (tabData[tabId]) {
					tabData[tabId] = null;
				}
				if (tabData[tabId]) tabData[tabId] = null;
				_this.removeCurrentResponse(tabId);
			} catch (e) {}
		},
		removeCurrentResponse: function (tabId) {
			try {
				tabResponseData[tabId] = null;
			} catch (e) {
				console.log(e);
			}
		},
		resetHeadersCache: function () {
			responseHeadersCache = {};
		},
		beautifyURL: function (url) {
			try {
				return url.replace(/#.*$/, '');
			} catch (e) {}
			return url;
		},
		getRootHostName: function (url) {
			var rawHostName = _this.getRawHostName(url);
			rawHostName = _this.removeWWWFromString(rawHostName);
			try {
				var TLDs = ["ac", "ad", "ae", "aero", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "arpa", "as", "asia", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "biz", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cat", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "com", "coop", "cr", "cu", "cv", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "edu", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gov", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "info", "int", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jobs", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mil", "mk", "ml", "mm", "mn", "mo", "mobi", "mp", "mq", "mr", "ms", "mt", "mu", "museum", "mv", "mw", "mx", "my", "mz", "na", "name", "nc", "ne", "net", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "org", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "pro", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "st", "su", "sv", "sy", "sz", "tc", "td", "tel", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tp", "tr", "travel", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xn--0zwm56d", "xn--11b5bs3a9aj6g", "xn--3e0b707e", "xn--45brj9c", "xn--80akhbyknj4f", "xn--90a3ac", "xn--9t4b11yi5a", "xn--clchc0ea0b2g2a9gcd", "xn--deba0ad", "xn--fiqs8s", "xn--fiqz9s", "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--g6w251d", "xn--gecrj9c", "xn--h2brj9c", "xn--hgbk6aj7f53bba", "xn--hlcj6aya9esc7a", "xn--j6w193g", "xn--jxalpdlp", "xn--kgbechtv", "xn--kprw13d", "xn--kpry57d", "xn--lgbbat1ad8j", "xn--mgbaam7a8h", "xn--mgbayh7gpa", "xn--mgbbh1a71e", "xn--mgbc0a9azcg", "xn--mgberp4a5d4ar", "xn--o3cw4h", "xn--ogbpf8fl", "xn--p1ai", "xn--pgbs0dh", "xn--s9brj9c", "xn--wgbh1c", "xn--wgbl6a", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--yfro4i67o", "xn--ygbi2ammx", "xn--zckzah", "xxx", "ye", "yt", "za", "zm", "zw"].join()
				var parts = rawHostName.split('.');
				if (parts[0] === 'www' && parts[1] !== 'com') {
					parts.shift()
				}
				var extension = [];
				var ln = parts.length,
					i = ln,
					minLength = parts[parts.length - 1].length,
					part;
				// iterate backwards
				while (part = parts[--i]) {
					extension.push(part);
					// stop when we find a non-TLD part
					if (i === 0 || i < ln - 2 || part.length < minLength || TLDs.indexOf(part) < 0) {
						if (extension.length > 1)
							return extension.reverse().join(".");
					}
				}

			} catch (e) {
				console.log(e);
			}
			return rawHostName;
		},
		isValidDomain: function (domainName) {
			try {
				if (invalidDomains.indexOf(domainName) >= 0) return false;
			} catch (e) {
				console.log(e);
			}
			return true;
		},
		getRawHostName: function (url) {
			try {
				var uri = new URL(url);
				return _this.removeWWWFromString(uri.hostname);
			} catch (e) {
				console.log(e);
			}
			return null;
		},
		getUrlDetails: function (url, rawhostname) {
			var urlDetails = {};
			try {
				if (typeof rawhostname == "undefined" || rawhostname == null) rawhostname = _this.getRawHostName(url);
				rawhostname = _this.removeWWWFromString(rawhostname);
				urlDetails['rawhostname'] = rawhostname;
				if (_this.isIpAddress(rawhostname)) {
					urlDetails['hostname'] = rawhostname;
				} else {
					var rootHostName = _this.getRootHostName(url);
					urlDetails['hostname'] = rootHostName;
					if (rawhostname != rootHostName) {
						urlDetails['subdomain'] = _this.getSubDomain(rawhostname);
					}
				}
				urlDetails['url'] = _this.removeGetParams(url);
			} catch (e) {
				console.log(e);
			}
			return urlDetails;
		},
		getSubDomain: function (hostname) {
			try {
				var parts = hostname.split('.');
				return parts[0];
			} catch (e) {
				console.log(e);
			}
		},
		isIpAddress: function (hostname) {
			try {
				var ip = hostname.split(".");

				if (ip.length != 4) {
					return false;
				}

				//Check Numbers
				for (var c = 0; c < 4; c++) {
					//Perform Test
					if (isNaN(parseFloat(ip[c])) || !isFinite(ip[c]) || ip[c] < 0 || ip[c] > 255 || ip[c].indexOf(" ") !== -1 || ip[c].match(/^-\d+$/)) {

						return false;
					}
				}

			} catch (e) {}
			return true;
		},
		removeWWWFromString: function (hostname) {
			try {
				var parts = hostname.split('.');
				var firstPart = parts[0].toLowerCase();
				if (firstPart === 'www' && parts[1] !== 'com') {
					parts.shift()
				}
				return parts.join(".");
			} catch (e) {
				console.log(e);
			}
			return hostname;
		},
		getAllEmails: function (html) {
			try {
				var emails = html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi);
				return this.filterEmails(emails);

			} catch (e) {
				console.log(e);
			}
			return null;
		},
		filterEmails: function (emails) {
			var newEmails = [];
			try {
				if (emails == null) return newEmails;
				for (var i = 0; i < emails.length; i++) {
					try {
						var email = emails[i];
						if (!this.hasImageExntesion(email)) {
							if (email.substr(-1) == ".") email = email.slice(0, -1);
							if (newEmails.indexOf(email) === -1) newEmails.push(email);
						}
					} catch (e) {
						console.log(e);
					}
				}

			} catch (e) {
				console.log(e);
			}
			return newEmails;
		},
		hasImageExntesion: function (email) {
			try {
				return (/\.(gif|jpg|jpeg|tiff|png)$/i).test(email)
			} catch (e) {
				console.log(e);
			}
			return false;
		},
		reviewFeatureData: function(data) {
			try {
				fetch(REVIEW_FEATURE_DATA, {
					method: 'POST',
					headers: {'Content-Type': 'application/json'},
					body: JSON.stringify(data)
				})
			} catch (err) {
				console.log("Failed to send review data", err);
			}
		}
	};
	s.init();
})();
