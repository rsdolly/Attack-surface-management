export const DOMAIN_NAME = "https://www.whatruns.com/";
// export const DOMAIN_NAME = "http://localhost:4004/";
export const SHOPPER_DOMAIN = "https://www.shopper.com/";
export const BROWSER = (chrome || browser);
export const ANALYSE_APPS = "analyseApps"; //Dependency on Content.js file
export const GET_DETECTED_APPS = "getDetectedApps"; //Dependecy on notification.js file
export const GET_NOTIFICATION_MESSAGE = "getNotificationMessage"; // Dependecy
export const GET_HOST_NAME = "getHostName";
export const SET_DATA = "setData";
export const GET_DATA = "getData";
export const GET_TECHS = "get_techs";
export const GET_SITE_DATA = "get_site_data";
export const KEY_DETAILS = "keyDetails";
export const FORM = "form";
export const GET_SITE_APPS = DOMAIN_NAME + "api/v1/get_site_apps";
export const COLLECT_SDK_DATA = DOMAIN_NAME + "api/v1/collect_data";
export const COLLECT_SDK_CHECKOUT_DATA = DOMAIN_NAME + "api/v1/collect_checkout_data";
export const ANALYSE_SITE_DATA = DOMAIN_NAME + "api/v1/analysite_site_data";
export const ANALYSE_BULK_SITE_DATA = DOMAIN_NAME + "api/v1/analyse_bulk_site_data";
export const GET_SITE_APPS_BY_DATA = DOMAIN_NAME + "api/v1/get_site_apps_by_data";
export const ANALYSE_EMAILS = DOMAIN_NAME + "api/v1/analyse_emails";
export const REVIEW_FEATURE_DATA = DOMAIN_NAME + "api/v1/ext_review";
export const invalidDomains = ["localhost", "127.0.0.1", "0.0.0.0"];
export const NO_APPS_FOUND = " I feel lost, maybe there's nothing to be found ; ) ";
export const SITE_DATA_SYNC_LIMIT = 30;
// Image grabber
export const IG_CHECK_STORES = "checkIGStore";
export const IG_GET_STORES_DATA = DOMAIN_NAME + "api/v1/get_ig_stores";
export const IG_SYNC_LIMIT = 10;
export const IG_QUEUE_DOMAIN = SHOPPER_DOMAIN + "image_grabber/api/v1/ext/queue";
export const IG_SYNC_TIME_LIMIT = 30; // minutes
export const EXCLUDED_DOMAINS = [
  "google.com", "facebook.com", "youtube.com", "twitter.com",
  "instagram.com", "baidu.com", "yahoo.com", "whatsapp.com"
]
export const INITIATE_DATA_SDK = "initiateDataSDK";
export const PROCESS_DATA_SDK = "processDataSDK";
export const PROCESS_DATA_SDK_CAPTIFY = "processDataSDKCaptify";
export const SEND_DATA_SDK = "sendDataFromSDK";
export const SEND_CHECKOUT_DATA_SDK = "sendCheckoutDataFromSDK";
