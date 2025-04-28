var DOMAIN_NAME = "https://www.whatruns.com/";
// var DOMAIN_NAME = "http://localhost:4004/";
var SHOPPER_DOMAIN = "https://www.shopper.com/";
var BROWSER = (chrome || browser);
var ANALYSE_APPS = "analyseApps"; //Dependency on Content.js file
var GET_DETECTED_APPS = "getDetectedApps"; //Dependecy on notification.js file
var GET_NOTIFICATION_MESSAGE = "getNotificationMessage"; // Dependecy
var GET_HOST_NAME = "getHostName";
var SET_DATA = "setData";
var GET_DATA = "getData";
var GET_TECHS = "get_techs";
var GET_SITE_DATA = "get_site_data";
var KEY_DETAILS = "keyDetails";
var FORM = "form";
var GET_SITE_APPS = DOMAIN_NAME + "api/v1/get_site_apps";
var COLLECT_SDK_DATA = DOMAIN_NAME + "api/v1/collect_data";
var COLLECT_SDK_CHECKOUT_DATA = DOMAIN_NAME + "api/v1/collect_checkout_data";
var ANALYSE_SITE_DATA = DOMAIN_NAME + "api/v1/analysite_site_data";
var REVIEW_FEATURE_DATA = DOMAIN_NAME + "api/v1/ext_review";
var ANALYSE_BULK_SITE_DATA = DOMAIN_NAME + "api/v1/analyse_bulk_site_data";
var GET_SITE_APPS_BY_DATA = DOMAIN_NAME + "api/v1/get_site_apps_by_data";
var ANALYSE_EMAILS = DOMAIN_NAME + "api/v1/analyse_emails";
var invalidDomains = ["localhost", "127.0.0.1", "0.0.0.0"];
var NO_APPS_FOUND = " I feel lost, maybe there's nothing to be found ; ) ";
var SITE_DATA_SYNC_LIMIT = 30;
// Image grabber
var IG_CHECK_STORES = "checkIGStore";
var IG_GET_STORES_DATA = DOMAIN_NAME + "api/v1/get_ig_stores";
var IG_SYNC_LIMIT = 10;
var IG_QUEUE_DOMAIN = SHOPPER_DOMAIN + "image_grabber/api/v1/ext/queue";
var IG_SYNC_TIME_LIMIT = 30; // minutes
var EXCLUDED_DOMAINS = [
  "google.com", "facebook.com", "youtube.com", "twitter.com",
  "instagram.com", "baidu.com", "yahoo.com", "whatsapp.com"
]
var INITIATE_DATA_SDK = "initiateDataSDK";
var PROCESS_DATA_SDK = "processDataSDK";
var PROCESS_DATA_SDK_CAPTIFY = "processDataSDKCaptify";
var SEND_DATA_SDK = "sendDataFromSDK";
var SEND_CHECKOUT_DATA_SDK = "sendCheckoutDataFromSDK";
