import re

# JavaScript Library Map
js_library_map = [
    (re.compile(r'jquery(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'jQuery'),
    (re.compile(r'bootstrap(?:[-._]v?[\d.]+)?(?:\.bundle)?(?:\.min)?\.js', re.I), 'Bootstrap'),
    (re.compile(r'angular(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'AngularJS'),
    (re.compile(r'react(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'React'),
    (re.compile(r'vendor(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'Vendor.js'),
    (re.compile(r'vue(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'Vue.js'),
    (re.compile(r'next(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'Next.js'),
    (re.compile(r'nuxt(?:[-._]v?[\d.]+)?(?:\.min)?\.js', re.I), 'Nuxt.js'),
]


# Programming Language Patterns
language_patterns = [
    (re.compile(r"php/?([\d.]+)?", re.IGNORECASE), "PHP"),
    (re.compile(r"python/?([\d.]+)?", re.IGNORECASE), "Python"),
    (re.compile(r"wsgi|werkzeug", re.IGNORECASE), "Python"),
    (re.compile(r"ruby/?([\d.]+)?", re.IGNORECASE), "Ruby"),
    (re.compile(r"rails/?([\d.]+)?", re.IGNORECASE), "Ruby on Rails"),
    (re.compile(r"node\.js/?([\d.]+)?", re.IGNORECASE), "Node.js"),
    (re.compile(r"express/?([\d.]+)?", re.IGNORECASE), "Node.js"),
    (re.compile(r"java/?([\d.]+)?", re.IGNORECASE), "Java"),
    (re.compile(r"JSP|Servlet", re.IGNORECASE), "Java"),
    (re.compile(r"\.net|asp\.net", re.IGNORECASE), ".NET"),
    (re.compile(r"perl/?([\d.]+)?", re.IGNORECASE), "Perl"),
    (re.compile(r"coldfusion|cfmx", re.IGNORECASE), "ColdFusion"),
    (re.compile(r"go/?([\d.]+)?", re.IGNORECASE), "Go"),
    (re.compile(r"rust/?([\d.]+)?", re.IGNORECASE), "Rust"),
]
# Analytics Patterns
analytics_patterns = [
    (re.compile(r'googletagmanager\.com/gtm\.js', re.I), 'Google Tag Manager'),
    (re.compile(r'google-analytics\.com', re.I), 'Google Analytics'),
    (re.compile(r'googletagservices\.com', re.I), 'Google Tag Services'),
    (re.compile(r'connect\.facebook\.net', re.I), 'Facebook Pixel'),
    (re.compile(r'stats\.wp\.com', re.I), 'WordPress Stats'),
    (re.compile(r'matomo\.js', re.I), 'Matomo'),
    (re.compile(r'yandex\.ru/metrika', re.I), 'Yandex Metrica')
]

# CDN Patterns
cdn_patterns = [
    (re.compile(r'cloudflare\.com', re.I), "Cloudflare"),
    (re.compile(r'akamai\.net', re.I), "Akamai"),
    (re.compile(r'akamaihd\.net', re.I), "Akamai"),
    (re.compile(r'cdn.jsdelivr.net', re.I), "jsDelivr"),
    (re.compile(r'fastly\.net', re.I), "Fastly"),
    (re.compile(r'stackpathcdn\.com', re.I), "StackPath"),
    (re.compile(r'cdn\.stackpath\.net', re.I), 'StackPath'),
    (re.compile(r'StackPath'), 'StackPath'),
    (re.compile(r'maxcdn\.bootstrapcdn\.com', re.I), "BootstrapCDN"),
    (re.compile(r'bootstrapcdn\.com', re.I), "BootstrapCDN"),
    (re.compile(r'maxcdn\.bootstrapcdn\.com', re.I), "BootstrapCDN"),
    (re.compile(r'googleapis\.com', re.I), "Google Cloud CDN"),
    (re.compile(r'ajax\.googleapis\.com', re.I), "Google APIs"),
    (re.compile(r'ajax\.libs\.com', re.I), "CDNJS"),
    (re.compile(r'azureedge\.net', re.I), "Azure CDN"),
    (re.compile(r'cloudfront\.net', re.I), "Amazon CloudFront"),
    (re.compile(r'netdna-cdn\.com', re.I), "MaxCDN"),
    (re.compile(r'cachefly\.net', re.I), "CacheFly"),
    (re.compile(r'\.s3-[a-z0-9\-]+\.amazonaws\.com', re.I), "Amazon S3"),
    (re.compile(r'(?:https?:)?//unpkg\.com', re.I), "unpkg CDN")
]

# Database Patterns
database_patterns = [
    (re.compile(r"MySQL server version", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*?error", re.I), "PostgreSQL"),
    (re.compile(r"SQLite/JDBCDriver", re.I), "SQLite"),
    (re.compile(r"Microsoft SQL Server", re.I), "MSSQL"),
    (re.compile(r"ORA-\d+", re.I), "Oracle DB"),
    (re.compile(r"MongoDB.*?error", re.I), "MongoDB"),
]

framework_patterns = [
    # JavaScript frameworks
    (re.compile(r'angular(\.js)?', re.I), 'AngularJS'),
    (re.compile(r'react(-dom)?(\.js)?', re.I), 'React'),
    (re.compile(r'veu[e]?\.(min\.)?js', re.I), 'Vue.js'),
    (re.compile(r'ember(\.min)?\.js', re.I), 'Ember.js'),
    (re.compile(r'next(\.min)?\.js', re.I), 'Next.js'),
    (re.compile(r'nuxt(\.min)?\.js', re.I), 'Nuxt.js'),
    (re.compile(r'svelte(\.min)?\.js', re.I), 'Svelte'),
    (re.compile(r'htmx(\.min)?\.js', re.I), 'HTMX'),

    # Backend frameworks via headers, cookies, or known paths
    (re.compile(r'django', re.I), 'Django'),
    (re.compile(r'laravel', re.I), 'Laravel'),
    (re.compile(r'rails', re.I), 'Ruby on Rails'),
    (re.compile(r'express', re.I), 'Express.js'),
    (re.compile(r'flask', re.I), 'Flask'),
    (re.compile(r'asp\.net', re.I), 'ASP.NET'),
    (re.compile(r'spring', re.I), 'Spring'),

    # Generic detection hints
    (re.compile(r'/wp-content/plugins/', re.I), 'WordPress'),
    (re.compile(r'_framework', re.I), 'ASP.NET WebForms'),
]

# Security Header Detection
security_headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection"
]

# SSL/TLS Info (to be extracted via ssl module, not regex)
ssl_info_fields = [
    "issuer", "subject", "notBefore", "notAfter", "version", "serialNumber", "signatureAlgorithm"
]

# Authentication Detection Patterns
auth_patterns = [
    (re.compile(r'Authorization', re.IGNORECASE), "Token-based Auth (Header)"),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-_]+\.*[A-Za-z0-9\-_]*\.?[A-Za-z0-9\-_]*'), "JWT Detected"),
    (re.compile(r'auth|login|sign[\-_]?in', re.IGNORECASE), "Login-related Script/Form"),
    (re.compile(r'basic realm="[^"]+"', re.IGNORECASE), "Basic Auth"),
    (re.compile(r'csrf|xsrf', re.IGNORECASE), "CSRF Protection"),
    (re.compile(r'accounts\.google\.com/o/oauth2', re.IGNORECASE), "Google OAuth"),
    (re.compile(r'apis\.google\.com/js/platform\.js', re.IGNORECASE), "Google Sign-In Script")
    
]

ssl_tls_patterns = [
    # Issuer / Certificate Authority
    (re.compile(r"Let's Encrypt", re.I), "Let's Encrypt CA"),
    (re.compile(r"Cloudflare.*", re.I), "Cloudflare CA"),
    (re.compile(r"Amazon.*", re.I), "Amazon Certificate Authority"),
    (re.compile(r"Google Trust.*", re.I), "Google Trust Services"),
    (re.compile(r"GoDaddy.*", re.I), "GoDaddy CA"),

    # TLS Versions
    (re.compile(r"TLSv1\.3", re.I), "TLS 1.3"),
    (re.compile(r"TLSv1\.2", re.I), "TLS 1.2"),
    (re.compile(r"TLSv1\.1", re.I), "Deprecated TLS 1.1"),
    (re.compile(r"TLSv1$", re.I), "Deprecated TLS 1.0"),

    # Weak Signature Algorithms
    (re.compile(r"sha1", re.I), "Weak Signature Algorithm (SHA-1)"),
    (re.compile(r"md5", re.I), "Weak Signature Algorithm (MD5)"),

    # Strong Signature Algorithms
    (re.compile(r"sha256", re.I), "Strong Signature Algorithm (SHA-256)"),
    (re.compile(r"sha384", re.I), "Strong Signature Algorithm (SHA-384)"),
]

cms_patterns = [
    # Pattern to match, (CMS name, version extraction regex)
    (re.compile(r'wordpress', re.I), ('WordPress', re.compile(r'wordpress[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'wp-content|wp-includes', re.I), ('WordPress', re.compile(r'(\d+\.\d+(\.\d+)?)', re.I))),
    (re.compile(r'joomla', re.I), ('Joomla', re.compile(r'joomla[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'drupal', re.I), ('Drupal', re.compile(r'drupal[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'wix\.com', re.I), ('Wix', None)),
    (re.compile(r'squarespace', re.I), ('Squarespace', None)),
    (re.compile(r'sitefinity', re.I), ('Sitefinity', re.compile(r'sitefinity[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'magento', re.I), ('Magento', re.compile(r'magento[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'shopify', re.I), ('Shopify', None)),
    (re.compile(r'typo3', re.I), ('TYPO3', re.compile(r'typo3[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
    (re.compile(r'contao', re.I), ('Contao', re.compile(r'contao[-/]?(\d+\.\d+(\.\d+)?)?', re.I))),
]

backend_api = [
    "/api/","/api/v1/","/api/v2/","/rest/", "/soap/", "/jsonrpc","/xmlrpc", "/graphql", "/wp-json/", "/admin/api/", "/internal-api/", "/public-api/","/data-api/", "/v1/", "/rpc/", "x-api-key", "Bearer ", "/openapi.json", "/swagger.json", "/actuator", "/health"
]

dev_tools = [
    "webpack",
    "babel", 
    "gulp", 
    "grunt", 
    "parcel", 
    "vite", 
    "esbuild", 
    "rollup", 
    "browserify", 
    "create-react-app", 
    "next.config.js", 
    "vite.config.js", 
    "webpack.config.js", 
    "tsconfig.json", 
    "node_modules", 
    "devServer", 
    "sourceMappingURL",
    "__vite_ping",
]
