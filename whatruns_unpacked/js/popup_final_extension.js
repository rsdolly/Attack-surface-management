var email = null,
	api_key = null,
	followingSites = [],
	lastContainer = '';
var loginKey = "login_session",
	followingSitesKey = "following_sites";
var defaultText = "Do you know what runs a website? Visit whatruns.com";

$(document).ready(function (e) {
	var popupExt = {
		current: '',
		init: function () {
			current = popupExt;
			// this.applyBrowserTheme();
			this.applyTheme();
			this.setGlobalItems();
			this.initClickEvents();
			//this.initTooltip();
			this.initSubmitEvents();
		},
		setGlobalItems: function () {
			try {
				var sendMessage = function (tabs) {
					BROWSER.runtime.sendMessage({
						id: GET_HOST_NAME,
						tab: tabs[0]
					}, function (res) {
						currentHostName = current.getCurrentHostName(res);
						current.getLocalStorageItem(loginKey, function (item) {
							var data = (item.hasOwnProperty(loginKey)) ? current.parseJsonStr(item[loginKey]) : {};
							email = (typeof data.email != "undefined") ? data.email : null;
							api_key = (typeof data.api_key != "undefined") ? data.api_key : null;
							current.getLocalStorageItem(followingSitesKey, function (item) {
								followingSites = (item.hasOwnProperty(followingSitesKey)) ? current.parseJsonStr(item[followingSitesKey]) : [];
								current.enableHeaderButtons();
							});
						});
						current.checkCookiePolicy();
					});
				}
				self.tabQuery(sendMessage);
			} catch (e) { }
		},
		checkCookiePolicy: function () {
			let keyname = 'cookie_policy';
			current.getLocalStorageItem(keyname, function (item) {
				if (item && item[keyname]) $('.cookie-policy').addClass('hide');
				else $('.cookie-policy').removeClass('hide');
			});
		},
		getCurrentHostName: function (data) {
			try {
				var hostname = data.hostname;
				if (invalidDomains.indexOf(hostname) >= 0 || hostname == "newtab") return "";
				if (typeof data.rawhostname != "undefined") return data.rawhostname;
				else if (typeof data.tabTechs.rawhostname != "undefined") return data.tabTechs.rawhostname;
				else if (typeof data.hostname != "undefined") return data.hostname;
				else if (typeof data.tabTechs.hostname != "undefined") return data.tabTechs.hostname;
			} catch (e) {
				console.log(e);
			}
			return "";
		},
		setData: function (data) {
			try {
				BROWSER.storage.local.set(data);
			} catch (e) { }
		},
		getLocalStorageItem: function (key, callback) {
			BROWSER.storage.local.get(key, callback);
		},
		adjustIframeHeight: function() {
			setTimeout(function() {
				let height = $(".slideDown").height() + 80
				window.parent.postMessage({
					type: 'adjustHeight',
					height: height
				}, '*');
			}, 50);
		},
		enableHeaderButtons: function () {
			followingSites = (followingSites instanceof Array) ? followingSites : JSON.parse(followingSites);
			if (followingSites.indexOf(currentHostName) !== -1) {
				$('.user-already-following').addClass("active");
			} else {
				$('.user-follow').addClass("active");
			}
			if (followingSites.length > 0) {
				$('.user-following').addClass("active");
			}
			$('.wahtruns-dark, wahtruns-white').addClass("active")
			$('.share-url').addClass("active");
			current.updateUserFollowingTitleToolTip("Following " + followingSites.length + " Sites");
		},
		updateUserFollowingTitleToolTip: function (title) {
			$('.user-following').attr("title", title);
		},
		initClickEvents: function () {
			this.initFollowEvent();
			this.initFollowingEvent();
			this.initBackEvent();
			this.initSigninEvent();
			this.initSignupEvent();
			this.initShareEvent();
			this.initShareFacebookEvent();
			this.initShareEmailEvent();
			this.initUnFollowEvent();
			this.removeCookieBanner();
			this.writeReview();
			this.removeReviewPopup();
			this.showReviewPopup();
			this.changeTheme();
		},
		changeTheme: function() {
			$(".btn-dark").click(function () {
				localStorage.setItem("theme", "dark");
				popupExt.applyTheme();
			})
			$(".btn-white").click(function () {
				localStorage.setItem("theme", "light");
				popupExt.applyTheme();
			})
			
		},
		applyBrowserTheme: function () {
			var browserTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
			 if ( browserTheme ==="dark") {
				document.body.classList.add("whatruns-dark-mode");
				$(".whatruns-dark").hide()
				$(".whatruns-white").show()
			}
		},
		applyTheme: function() {
			let theme = localStorage.getItem("theme");
			if(theme === "dark") {
				document.body.classList.add("whatruns-dark-mode");
				$(".whatruns-dark").hide()
				$(".whatruns-white").show()
			} else if (theme === "light") {
				document.body.classList.remove("whatruns-dark-mode");
				$(".whatruns-dark").show()
				$(".whatruns-white").hide()
			} 
		},
		reviewPopupData: function(action) {
			var reviewTheme = $('.whatruns-review-container').attr('data-unique-id');
			BROWSER.runtime.sendMessage({
				id: "reviewData",
				data: {theme: reviewTheme, action: action}
			})
		},
		writeReview: function() {
			$('.whatruns-review-button').click(() => {
				$('.whatruns-review-container').addClass("hide")
				window.open("https://chromewebstore.google.com/detail/WhatRuns/cmkdbmfndkfgebldhnkbfhlneefdaaip/reviews?hl=en", "_blank");
				this.reviewPopupData("write_review")
				localStorage.setItem("write_a_review", true)
			})
		},
		reviewPopupDesign: function () {
			var n = Math.floor(Math.random() * 3) + 1
			if( n === 1) {
				$('.whatruns-review-logo').attr("src", "/images/review_img1.svg")
				$('.whatruns-review-rating').attr("src", "/images/rating1.svg")
				$('.whatruns-review-wrap div').html("WhatRuns made you feel like a hacking genius?")
				$('.whatruns-review-wrap p').html("We promise we won’t tell the Feds!")
				$('.whatruns-review-container').attr('data-unique-id', 'review-1')
			} else if( n === 2) {
				$('.whatruns-review-logo').attr("src", "/images/review_img2.svg")
				$('.whatruns-review-rating').attr("src", "/images/rating.svg")
				$('.whatruns-review-wrap div').html("Love uncovering website secrets?")
				$('.whatruns-review-wrap p').html("Keep the magic alive—your support means everything!")
				$('.whatruns-review-container').attr('data-unique-id', 'review-2')
			} else if (n === 3) {
				$('.whatruns-review-logo').attr("src", "/images/review_img3.svg")
				$('.whatruns-review-rating').attr("src", "/images/rating1.svg")
				$('.whatruns-review-wrap div').html("Unmasked cool tech with WhatRuns?")
				$('.whatruns-review-wrap p').html("Keep the magic alive—your support means everything!")
				$('.whatruns-review-container').attr('data-unique-id', 'review-3')
			}
		},
		showReviewPopup: function () {
			this.reviewPopupDesign();	
			var currentDate= new Date().getTime();
			var storeDate = Number(localStorage.getItem("reviewLaterDate"));
			var writeReview = localStorage.getItem("write_a_review")
			
			if (!writeReview) {
				if(storeDate) {
					var days = (currentDate - storeDate)/ (1000*60*60*24);
					if(days >= 10) {
						$('.whatruns-review-container').removeClass("hide")
					}
				} else {
						var clicked = Number(localStorage.getItem("extensionClick")) || 0;
						clicked++;
						localStorage.setItem("extensionClick",clicked)
	
						var startDate = Number(localStorage.getItem("startDate"))
						if(!startDate) {
							startDate = Number(localStorage.setItem("startDate", new Date().getTime()))
						}
						var daysSinceStart= (currentDate - startDate)/ (1000*60*60*24);
	
						if(daysSinceStart >= 2 && clicked >= 5) {
							$('.whatruns-review-container').removeClass("hide")
							localStorage.setItem("extensionClick",0)
						}
				}
			}
			
		},
		removeReviewPopup: function () {
			$(".whatruns-later-button").click(() => {
				$('.whatruns-review-container').addClass("hide");
				var currentDate = new Date().getTime();
				localStorage.setItem("reviewLaterDate", currentDate);
				this.reviewPopupData("maybe_later")
			})
		},
		removeCookieBanner: function () {
			$('.cookie-policy-inner span.close').click(function (e) {
				$(this).closest('.cookie-policy').remove();
				var itemData = {
					"cookie_policy": 'hide'
				}
				current.setData(itemData);
			});
		},
		initSubmitEvents: function () {
			this.formSubmit();
			this.sendEmail();
		},
		initFollowEvent: function () {
			$('.btn-follow').click(function (e) {
				if (followingSites.length < 10) current.isLoggedIn();
			});
		},
		initFollowingEvent: function () {
			$('.btn-following').click(function (e) {
				if (followingSites.length > 0) {
					current.getFollowingSites();
				}
			});
		},
		initBackEvent: function () {
			var _this=this;
			$('.btn-back').click(function (e) {
				$('.header-btn, .container').removeClass("active");
				_this.adjustIframeHeight("previousHeight");
				if (current.isValidUser()) {
					$('.user-following').addClass("active");
				} else {
					$('.user-follow').addClass("active");
				}
				if (lastContainer.trim().length > 0) {
					$('.back').addClass("active");
					$(lastContainer).addClass('active');
					lastContainer = '';
				} else {
					$('.current-app-info, .share-url').addClass("active");
				}
				if (followingSites.indexOf(currentHostName) > -1) $('.user-already-following').addClass("active");
				else $('.user-follow').addClass("active");
				if ($('.container').hasClass("newtab-text")) $('.user-following').addClass("active");
			});
		},
		initSigninEvent: function () {
			$('.btn-signin').click(function (e) {
				current.showSignInForm();
			});
		},
		initSignupEvent: function () {
			$('.btn-signup').click(function (e) {
				current.showSignUPForm();
			});
		},
		initShareEvent: function () {
			$('.btn-share').click(function (e) {
				current.showShareURLForm();
				
			});
			$('.btn-share-dark').click(function (e) {
				current.showShareURLForm();
				
			});

		},
		initShareFacebookEvent: function () {
			$('.share-facebook').click(function (e) {
				var url = encodeURIComponent($('.share-url-original').val());
				window.open("https://www.facebook.com/sharer/sharer.php?u=" + url, "myWindowName", "width=600, height=600");
				return false;
			});
		},
		initShareEmailEvent: function () {
			$('.share-email').click(function (e) {
				lastContainer = '.share-container';
				current.showShareEmailForm();
			});
		},
		initUnFollowEvent: function () {
			$(document).on("click", '.btn-unfollow', function (e) {
				var followingSiteName = $(this).closest('.list').find('.following-sitename').val();
				$(this).closest('.list').remove();
				current.updateUnFollowSite(followingSiteName);
			});
		},
		showSignInForm: function () {
			$('.container, .header-btn').removeClass("active");
			$('.signin, .back').addClass("active");
			this.adjustIframeHeight()
		},
		showSignUPForm: function () {
			$('.container').removeClass("active")
			$('.signup').addClass("active")
			this.adjustIframeHeight()
		},
		showShareEmailForm: function () {
			$('.container').removeClass("active");
			$('.email-share-container').addClass("active");
			this.adjustIframeHeight()
		},
		showShareURLForm: function () {
			$('.container, .share-url').removeClass("active");
			$('.share-container').addClass("active");
			this.adjustIframeHeight()
			$('.back').addClass("active");
			$('.user-follow').removeClass("active")
			var twitterUrl = "https://twitter.com/share?text=" + encodeURIComponent(defaultText) + "&via=whatruns";
			if (currentHostName.trim().length > 0) {
				var url = DOMAIN_NAME + "website/" + encodeURIComponent(currentHostName);
				$('.share-url-original').val(url);
				var text = "Do you know what runs " + currentHostName + "?";
				var twitterUrl = "https://twitter.com/share?url=" + encodeURIComponent(url) + "&text=" + encodeURIComponent(text) + "&via=whatruns";
			}
			$('.twitter-share-href').attr("href", twitterUrl);
		},
		isLoggedIn: function () {
			try {

				if (current.isValidUser()) {
					if (followingSites.indexOf(currentHostName) <= -1) {
						followingSites.push(currentHostName);
						var itemData = {
							"following_sites": JSON.stringify(followingSites)
						}
						current.setData(itemData);
						current.followSite();
					} else {
						current.getFollowingSites();
					}
				} else {
					current.showSignInForm();
				}
			} catch (e) { }
		},
		followSite: function () {
			try {

				$.ajax({
					type: "POST",
					url: DOMAIN_NAME + "api/follow",
					data: "email=" + email + "&hostname=" + currentHostName,
					success: function (response) {
						//appendNewFollowingSite();
						current.getFollowingSites();
					}
				});
			} catch (e) { }
		},
		getFollowingSites: function () {
			try {
				if (email && api_key) {
					if ($('.following-sites-list').is(':empty')) {
						var data = current.getUserCredentials();
						$.ajax({
							type: "POST",
							data: data,
							url: DOMAIN_NAME + "api/get_following",
							success: function (response) {
								current.appendFollowingSites(response);
							}
						});
					} else {
						current.showFollowingSites();
					}
				}
			} catch (e) {
				console.log(e);
			}
		},
		appendFollowingSites: function (response) {

			try {
				if (typeof response != "undefined") {
					if (typeof response.following_sites != "undefined") {
						$('.following-sites-list').empty();
						var following_sites = response.following_sites;
						Object.keys(following_sites).forEach(function (siteName) {
							var siteDetectedApps = (typeof following_sites[siteName] === "object") ? following_sites[siteName] : JSON.parse(following_sites[siteName]);
							current.appendAppDetails(siteDetectedApps, siteName, response.days);
						});
						current.showFollowingSites();
					}
				}

			} catch (e) {
				console.log(e);
			}
		},
		showFollowingSites: function () {
			setTimeout(function () {
				current.showBackButton();
				$('.container').removeClass("active")
				$('.following').addClass("active");
			}, 500);
		},
		showBackButton: function () {
			$('.header-btn').removeClass("active");
			$('.back').addClass("active");
		},
		appendAppDetails: function (detectedSiteApps, hostname, daysDiff) {
			try {
				var list = $('<div class="list"></div>');
				var headerEl = $('<div class="following-heading"><div class="following-hostname inline">' + hostname + '</div><div class="inline unfollow"></div><input type="hidden" class="hide following-sitename" value="' + hostname + '"></div>');
				var unfollowEl = $('<button class="btn btn-sm btn-gray sm-1 btn-unfollow">Unfollow</button>');
				$(list).append($(headerEl));
				$(list).find('.unfollow').append($(unfollowEl));
				for (var time in detectedSiteApps) {
					var apps = detectedSiteApps[time];
					var totalApps = [];
					Object.keys(apps).forEach(function (categoryName) {
						try {
							var arr = apps[categoryName];
							for (var i in arr) {
								var techJson = arr[i];
								if (totalApps.indexOf(techJson.name) <= -1) {
									totalApps.push(techJson.name);
									var date = current.getDateFormat(techJson.latestDetectedTime);
									var imageUrl = "https://www.whatruns.com/images/icons/" + techJson.icon;
									var imgEl = $('<div class="app-body inline"><div class="image"><a href="' + techJson.website + '" target="_blank"  data-toggle="tooltip" data-placement="bottom" title="' + techJson.name + ' <br/> Last Detected: ' + date + '"><img src="' + imageUrl + '"></a></div><div class="border-bottom-green" ></div></div>');
									$(list).append($(imgEl));
								}
							}
						} catch (e) {
							console.log(e);
						}
					});
				}
				$('.following-sites-list').append($(list));
			} catch (e) {
				console.log(e);
			}
		},
		updateUnFollowSite: function (followingSiteName) {
			if (current.isValidUser()) {
				var data = {
					email: email,
					api_key: api_key,
					hostname: followingSiteName
				}
				$.ajax({
					type: "POST",
					data: data,
					url: DOMAIN_NAME + "api/unfollow",
					success: function (response) {
						var index = followingSites.indexOf(followingSiteName);
						if (index > -1) {
							followingSites.splice(index, 1);
							var itemData = {
								following_sites: JSON.stringify(followingSites)
							}
							current.setData(itemData);
							current.updateUserFollowingTitleToolTip("Following " + followingSites.length + " Sites");
						}
					}
				})
			}
		},
		formSubmit: function () {
			$('.form').on("submit", function (e) {
				e.preventDefault();
				//var data = $(this).serialize();
				var data = {};
				$.each($(this).serializeArray(), function () {
					data[this.name] = btoa(this.value);
				});
				data['encode'] = true;
				var method = $(this).attr("method");
				var url = DOMAIN_NAME + $(this).attr("url");
				var formData = {
					data: data,
					method: method,
					url: url
				};
				var $this = $(this);
				BROWSER.runtime.sendMessage({
					id: "form",
					subject: formData
				}, function (response) {
					if (response.status != 200) {
						$this.find('.result').addClass("error");
						$this.find('.result').text(response.msg);
					} else {
						if (typeof response.api_key != "undefined") current.setLoginData(response);
					}
				});
			});
		},
		setLoginData: function (res) {
			try {
				email = res.email;
				api_key = res.api_key;
				var itemData = {
					email: email,
					api_key: api_key
				}
				var data = {
					"login_session": JSON.stringify(itemData),
					"following_sites": JSON.stringify(followingSites)
				}
				this.setData(data);
				this.appendNewFollowingSite();
			} catch (e) {
				console.log(e);
			}
		},
		appendNewFollowingSite: function () {
			try {
				this.showBackButton();
				this.appendAppDetails(detectedApps, currentHostName);
				if (followingSites.indexOf(currentHostName) <= -1) {
					followingSites.push(currentHostName);
					var itemData = {
						"following_sites": JSON.stringify(followingSites)
					}
					this.setData(itemData);
				}
				this.showFollowingSites();
				$('.user-follow').removeClass("active");
				$('.back').addClass("active");
				this.updateUserFollowingTitleToolTip("Following " + followingSites.length + " Sites");
			} catch (e) { }
		},
		sendEmail: function () {
			$('#email-share-form').on('submit', function (e) {
				e.preventDefault();
				var $this = $(this);
				$(this).find('.result').empty();
				var btnEl = $(this).find('.share-email-submit');
				var text = $(btnEl).text();
				$(btnEl).empty();
				$(btnEl).append('Sending...');
				// $(btnEl).append('<i class="fa fa-spinner fa-spin fa-fw" aria-hidden="true"></i>');
				$.ajax({
					type: "POST",
					data: $(this).serialize() + "&domain=" + currentHostName,
					url: DOMAIN_NAME + "share/email",
					success: function (res) {
						$(btnEl).empty();
						if (res.status == 200) {
							$(btnEl).append('<img src="images/Tick.png" style="max-width:10px;"><span style="margin-left:5px;">Sent</span>');
							setTimeout(function () {
								$(btnEl).empty();
								$(btnEl).append(text);
							}, 1000);
						} else {
							$(btnEl).append(text);
							$this.find('.result').text(res.msg);
						}
					}
				})
			});
		},
		getUserCredentials: function () {
			var userCredentials = "email=" + btoa(email) + "&api_key=" + btoa(api_key);
			userCredentials += "&encode=true";
			userCredentials += "&domains=" + JSON.stringify(followingSites);
			return userCredentials;
		},
		parseJsonStr: function (str) {
			try {
				return JSON.parse(str);
			} catch (e) { }
		},
		getDateFormat: function (timestamp) {
			try {
				var date = new Date(parseInt(timestamp));
				var month = current.getMonthName(date);
				return month + " " + date.getFullYear();
			} catch (e) { }
			return "";
		},
		getMonthName: function (d) {
			try {
				var monthNames = ["January", "February", "March", "April", "May", "June",
					"July", "August", "September", "October", "November", "December"
				];
				return monthNames[d.getMonth()];
			} catch (e) { }
		},
		isValidUser: function () {
			try {
				return (email && api_key && email.trim().length > 0 && api_key.trim().length > 0);
			} catch (e) {

			}
			return false;
		}
	}
	popupExt.init();
	$('body').tooltip({
		selector: '[data-toggle=tooltip]',
		html: true
	});

});