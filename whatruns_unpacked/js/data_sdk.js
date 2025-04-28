var INITIATE_DATA_SDK = "initiateDataSDK";
var PROCESS_DATA_SDK_CAPTIFY = "processDataSDKCaptify";
var PROCESS_DATA_SDK = "processDataSDK";
var SEND_DATA_SDK = "sendDataFromSDK";
var SEND_CHECKOUT_DATA_SDK = "sendCheckoutDataFromSDK";
var BROWSER = (chrome || browser);
(function() {
	var dataSDK = {
    self: '',
		init: function() {
      self = dataSDK;
			this.addEventListener();
		},
		addEventListener: function() {
      this.initiateGrabPageData();
      // Listen for messages from the background script
      chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
        // Access the data sent from the background script
        const { id, data } = message;
        if (id === PROCESS_DATA_SDK_CAPTIFY) {
          self.processDataAndSendCaptify(data).then(() => sendResponse({ success: true }));
          return true;
        } else if (id === PROCESS_DATA_SDK) {
          self.processDataAndSend(data).then(() => sendResponse({ success: true }));
          return true;
        }
      });
    },
    processDataAndSend: async function(params) {
      try {
        const pagePath = window.location.href;
        const { matchPage, doms: domFields = [] } = params;
        const domData = [
          { name: "title", value: document ? document.title : "" },
          { name: "referrer", value: document ? document.referrer : "" },
          { name: "language", value: navigator ? navigator.language : "" },
        ]
        for (const dom of domFields) {
          if (dom.is_parent === true) {
            let dataToPush = this.getXpathElementForChildDoms(dom);
            domData.push({ name: dom?.slug, child_data: dataToPush })
          } else {
            let matchingString = ""
            if (dom.source === "dom")
              matchingString = this.getElementStringValue(dom)
            else if (dom.source === "url") {
              const newRegex = new RegExp(dom?.regex);
              const match = pagePath.match(newRegex);
              if (match) matchingString = match[1];
            }
            // prepare data
            if (matchingString) domData.push({ name: dom?.slug, value: matchingString })
          }
        }
        // prepare page data
        const pageData = { 
          entry_type: matchPage, 
          url: pagePath, 
          data: domData,
          uuid: await this.getUUID(), // generate uuid for installation and send
          plugin_version: chrome.runtime.getManifest().version
        }
        var message = { id: SEND_CHECKOUT_DATA_SDK, data: pageData };
        this.sendMessageToChrome(message, response => { });
      } catch (error) {
        console.log(error)
      }
    },
    processDataAndSendCaptify: async function() {
      try {
        const pagePath = window.location.href;
        const pageData = { 
          url: pagePath, 
          title: document ? document.title : "",
          referrer: document.referrer || "",
          uuid: await this.getUUID(), // generate uuid for installation and send
          plugin_version: chrome.runtime.getManifest().version
        }
        var message = { id: SEND_DATA_SDK, data: pageData };
        this.sendMessageToChrome(message, response => { });
      } catch (error) {
        console.log(error)
      }
    },
    getElementStringValue: function (obj, sourceNode = null) {
      var val = null;
      try {
        if (obj.xpath) {
          var el = this.getXpathElement(obj.xpath, sourceNode);
          if (el) {
            if (obj.attribute) val = el.getAttribute(obj.attribute);
            else val = this.getElementValue($(el));
          } else if (obj.attr_source === "parent" && sourceNode && sourceNode.getAttribute) {
            val = sourceNode.getAttribute(obj.attribute)
          }
        } else if (obj.element) {
          if (obj.attribute) val = $(obj.element).attr(obj.attribute);
          else val = this.getElementValue($(obj.element));
        }
      } catch (e) {
        console.log(e);
      }
      return val;
    },
    getXpathElement: function (str, sourceNode) {
      try {
        // to do xpath inside the source node if source node is provided
        // to do this add . before the xpath
        if (sourceNode !== null) str = "." + str
        let query = document.evaluate(
          str,
          null || sourceNode ||document,
          null,
          XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
          null
        );
        let results = [];
        for (let i = 0, length = query.snapshotLength; i < length; ++i) {
          results.push(query.snapshotItem(i));
        }
        return results.length > 0 ? results[0] : null;
      } catch (e) {
        console.log(e);
      }
      return null;
    },
    getElementValue: function (el) {
      let val = null;
      try {
        val = el.__proto__.constructor === window.HTMLInputElement
          ? el.val().trim()
          : el.text().trim();
      } catch (e) {
        console.log(e);
      }
      return val;
    },
    getXpathElementForChildDoms: function (dom) {
      let childData = []
      try {
        let query = document.evaluate(
          dom.xpath,
          null || document,
          null,
          XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
          null
        );
        for (let i = 0, length = query.snapshotLength; i < length; ++i) {
          let sourceNode = query.snapshotItem(i);
          if (sourceNode) {
            let childItems = {}
            for (const childDom of dom.child_doms) {
              let matchingString = this.getElementStringValue(childDom, sourceNode)
              childItems[childDom?.slug || "key"] = matchingString
            }
            childData.push(childItems)
          }
        }
      } catch (e) {
        console.log(e);
      }
      return childData;
    },
    initiateGrabPageData: async function() {
      try {
        var message = { id: INITIATE_DATA_SDK };
        let __self = this;
        setTimeout(function () {
          __self.sendMessageToChrome(message, response => {});
        }, 2000);
      } catch (error) {
        console.log("data_sdk [initiateGrabPageData] error: ", error);
      }
    },
    sendMessageToChrome: function (message, callback) {
      BROWSER.runtime.sendMessage(message, function (response) {
        if (callback) callback(response);
      });
    },
    setLocalStorageItem: function(key, value) {
      return BROWSER.storage.local.set({[key]: value});
    },
    getLocalStorageItem: function(key) {
      return new Promise((resolve) => {
        return BROWSER.storage.local.get(key, data => {
          return resolve(data[key]||null);
        });
      });
    },
    getUUID: async function() {
      let uuid = await this.getLocalStorageItem("wrs_session_uuid");
      if (uuid) return uuid
      let newUUID = this.generateUUID();
      this.setLocalStorageItem("wrs_session_uuid", newUUID);
      return newUUID
    },
    generateUUID: function () {
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
  
      array[6] = (array[6] & 0x0f) | 0x40;
      array[8] = (array[8] & 0x3f) | 0x80;
  
      return [...array].map((b, i) => 
        (i === 4 || i === 6 || i === 8 || i === 10 ? '' : '') + b.toString(16).padStart(2, '0')
      ).join('');
    }
	}
  dataSDK.init();
}());
