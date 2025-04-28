var IG_CHECK_STORES = "checkIGStore";
var BROWSER = (chrome || browser);
(function() {
	var igConnect = {
    self: '',
		init: function() {
      self = igConnect;
			this.addEventListener();
		},
		addEventListener: function() {
      this.grabProductData();
		},
    /**
     * Function that grab product details and send to IG service
     */
    grabProductData: async function() {
      try {
        let CurrentUrl = window.location.href;
        let pageData = {
          title: $("title").text(),
          url: CurrentUrl,
          src_set: []
        }
        // get images inside page
        let pattern = new RegExp(`(http)?s?:?(\/\/[^"']*\(?:jpg|jpeg|webp))`);
        let imageCount = 0;
        $("div").each((i, e) => {
          if (imageCount === 5) return false;
          if (!!$(e).attr("style")) {
            let matchArray = $(e).attr("style").match(pattern);
            if (!!matchArray && matchArray.length > 0) {
              pageData.src_set.push({ url: matchArray[0] });
              imageCount++;
            }
          }
        });
        $("img").each((i, e) => {
          if (imageCount === 10) return false;
          if (!!$(e).attr("src")) {
            let matchArray = $(e).attr("src").match(pattern);
            if (!!matchArray && matchArray.length > 0) {
              pageData.src_set.push({ url: matchArray[0] });
              imageCount++;
            }
          }
        });
        $("img").each((i, e) => {
          if (!!pattern.test($(e).attr("src"))) {
            pageData.src_set.push({ url: $(e).attr("src") });
            imageCount++;
            if (imageCount === 15) return false;
          }
        });
        if (pageData.src_set.length >0) {
          BROWSER.runtime.sendMessage({
            id: IG_CHECK_STORES,
            data: pageData
          });
        }
      } catch (error) {
        console.log("ig_connect [grabProductData] error: ", error);
      }
    },
	}

	igConnect.init();

}());
