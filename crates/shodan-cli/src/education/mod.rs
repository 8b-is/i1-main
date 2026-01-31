//! Educational features: explanations, tips, and learning resources.

use colored::Colorize;

/// Command explanation builder.
pub struct Explain {
    #[allow(dead_code)]
    title: String,
    description: String,
    api_call: Option<String>,
    credit_cost: Option<String>,
    what_happens: Vec<String>,
    learn_more: Option<String>,
}

impl Explain {
    fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            description: String::new(),
            api_call: None,
            credit_cost: None,
            what_happens: Vec::new(),
            learn_more: None,
        }
    }

    fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    fn api(mut self, endpoint: &str) -> Self {
        self.api_call = Some(endpoint.to_string());
        self
    }

    fn credits(mut self, cost: &str) -> Self {
        self.credit_cost = Some(cost.to_string());
        self
    }

    fn step(mut self, step: &str) -> Self {
        self.what_happens.push(step.to_string());
        self
    }

    fn cheet(mut self, path: &str) -> Self {
        self.learn_more = Some(format!("https://cheet.is/{}", path));
        self
    }

    /// Print the explanation to stdout.
    pub fn print(&self) {
        println!();
        println!("{}", "=== What This Does ===".bold().cyan());
        println!("{}", self.description);
        println!();

        if !self.what_happens.is_empty() {
            println!("{}", "How it works:".bold());
            for (i, step) in self.what_happens.iter().enumerate() {
                println!("  {}. {}", i + 1, step);
            }
            println!();
        }

        if let Some(api) = &self.api_call {
            println!("{} {}", "API Call:".bold(), api.dimmed());
        }

        if let Some(cost) = &self.credit_cost {
            println!("{} {}", "Credit Cost:".bold(), cost);
        }

        if let Some(url) = &self.learn_more {
            println!();
            println!("{} {}", "Learn more:".bold(), url.cyan().underline());
        }

        println!();
        println!("{}", "=== Results ===".bold().cyan());
        println!();
    }

    // ========================================================================
    // Factory methods for each command
    // ========================================================================

    pub fn myip() -> Self {
        Self::new("My IP")
            .description("Shows your public IP address as seen by Shodan's servers.")
            .api("GET /tools/myip")
            .credits("Free - no credits used")
            .cheet("shodan/tools/myip")
    }

    pub fn host(ip: &str) -> Self {
        Self::new("Host Lookup")
            .description(&format!("Retrieves all available information about the host {}.", ip))
            .api(&format!("GET /shodan/host/{}", ip))
            .credits("1 query credit")
            .step("Queries Shodan's database for the IP")
            .step("Returns open ports, services, and banners")
            .step("Includes geolocation, organization, and ASN")
            .step("Lists any known vulnerabilities (CVEs)")
            .cheet("shodan/host/lookup")
    }

    pub fn search(query: &str) -> Self {
        // Parse query to explain filters
        let mut explanation = Self::new("Search")
            .description("Searches Shodan's database for hosts matching your query.")
            .api("GET /shodan/host/search")
            .credits("1 query credit per page");

        // Add query breakdown
        let parts: Vec<&str> = query.split_whitespace().collect();
        for part in parts {
            if let Some((filter, value)) = part.split_once(':') {
                let filter_desc = match filter {
                    "port" => format!("port:{} - Hosts with port {} open", value, value),
                    "country" => format!("country:{} - Located in {}", value, country_name(value)),
                    "org" => format!("org:{} - Organization contains '{}'", value, value),
                    "product" => format!("product:{} - Running {} software", value, value),
                    "net" => format!("net:{} - In network range {}", value, value),
                    "os" => format!("os:{} - Operating system is {}", value, value),
                    "asn" => format!("asn:{} - In autonomous system {}", value, value),
                    _ => format!("{}:{} - Filter by {}", filter, value, filter),
                };
                explanation = explanation.step(&filter_desc);
            }
        }

        explanation.cheet("shodan/search/filters")
    }

    pub fn count(_query: &str) -> Self {
        Self::new("Count")
            .description("Counts results matching your query WITHOUT using query credits.")
            .api("GET /shodan/host/count")
            .credits("Free - no credits used!")
            .step("Counts matching hosts in Shodan's database")
            .step("Returns total count and facet aggregations")
            .step("Does NOT return actual host data")
            .cheet("shodan/search/count")
    }

    pub fn account_profile() -> Self {
        Self::new("Account Profile")
            .description("Shows your Shodan account information.")
            .api("GET /account/profile")
            .credits("Free")
            .cheet("shodan/account")
    }

    pub fn account_credits() -> Self {
        Self::new("API Credits")
            .description("Shows your API usage and remaining credits.")
            .api("GET /api-info")
            .credits("Free")
            .step("Query credits are used for search/host lookups")
            .step("Scan credits are used for on-demand scans")
            .step("Credits reset monthly based on your plan")
            .cheet("shodan/account/credits")
    }

    pub fn dns_domain(domain: &str) -> Self {
        Self::new("Domain Info")
            .description(&format!("Retrieves DNS records and subdomains for {}.", domain))
            .api(&format!("GET /dns/domain/{}", domain))
            .credits("1 query credit")
            .step("Queries Shodan's passive DNS database")
            .step("Returns A, AAAA, MX, NS, TXT, SOA, CNAME records")
            .step("Lists discovered subdomains")
            .cheet("shodan/dns/domain")
    }

    pub fn dns_resolve() -> Self {
        Self::new("DNS Resolve")
            .description("Resolves hostnames to IP addresses.")
            .api("GET /dns/resolve")
            .credits("Free")
            .cheet("shodan/dns/resolve")
    }

    pub fn dns_reverse() -> Self {
        Self::new("Reverse DNS")
            .description("Finds hostnames that resolve to given IP addresses.")
            .api("GET /dns/reverse")
            .credits("Free")
            .cheet("shodan/dns/reverse")
    }

    pub fn scan_ports() -> Self {
        Self::new("Monitored Ports")
            .description("Lists all ports that Shodan's crawlers continuously monitor.")
            .api("GET /shodan/ports")
            .credits("Free")
            .cheet("shodan/scan/ports")
    }

    pub fn scan_protocols() -> Self {
        Self::new("Scan Protocols")
            .description("Lists available protocols for on-demand scanning.")
            .api("GET /shodan/protocols")
            .credits("Free")
            .cheet("shodan/scan/protocols")
    }

    pub fn scan_request(target: &str) -> Self {
        Self::new("Request Scan")
            .description(&format!("Requests an on-demand scan of {}.", target))
            .api("POST /shodan/scan")
            .credits("1 scan credit per IP")
            .step("Submits target to Shodan's scanning queue")
            .step("Scan runs within minutes")
            .step("Results appear in normal search after completion")
            .cheet("shodan/scan/request")
    }

    pub fn scan_list() -> Self {
        Self::new("List Scans")
            .description("Lists your active and recent on-demand scans.")
            .api("GET /shodan/scans")
            .credits("Free")
            .cheet("shodan/scan/list")
    }

    pub fn scan_status() -> Self {
        Self::new("Scan Status")
            .description("Gets the status of a specific scan.")
            .api("GET /shodan/scan/{id}")
            .credits("Free")
            .cheet("shodan/scan/status")
    }

    pub fn alert_list() -> Self {
        Self::new("List Alerts")
            .description("Lists all your network monitoring alerts.")
            .api("GET /shodan/alert/info")
            .credits("Free")
            .cheet("shodan/alerts")
    }

    pub fn alert_create() -> Self {
        Self::new("Create Alert")
            .description("Creates a new network monitoring alert.")
            .api("POST /shodan/alert")
            .credits("Free (alerts included in plan)")
            .step("Monitors specified IP ranges for changes")
            .step("Triggers on new services, vulnerabilities, etc.")
            .step("Can notify via email, Slack, webhooks")
            .cheet("shodan/alerts/create")
    }

    pub fn alert_get() -> Self {
        Self::new("Get Alert")
            .description("Gets details of a specific alert.")
            .api("GET /shodan/alert/{id}/info")
            .credits("Free")
            .cheet("shodan/alerts")
    }

    pub fn alert_delete() -> Self {
        Self::new("Delete Alert")
            .description("Deletes an alert.")
            .api("DELETE /shodan/alert/{id}")
            .credits("Free")
            .cheet("shodan/alerts")
    }

    pub fn alert_triggers() -> Self {
        Self::new("Alert Triggers")
            .description("Lists available trigger types for alerts.")
            .api("GET /shodan/alert/triggers")
            .credits("Free")
            .step("Triggers define when alerts fire")
            .step("Examples: new_service, ssl_expired, vuln_changed")
            .cheet("shodan/alerts/triggers")
    }

    pub fn defend_status() -> Self {
        Self::new("Defense Status")
            .description("Shows current blocking configuration.")
            .step("Lists blocked countries")
            .step("Lists blocked IPs and AS numbers")
            .step("Shows whitelisted IPs")
            .cheet("security/geoblock/status")
    }

    pub fn geoblock_add(countries: &[String]) -> Self {
        let names: Vec<String> = countries.iter().map(|c| country_name(c)).collect();

        Self::new("Geo-Block Countries")
            .description(&format!("Blocks all traffic from: {}", names.join(", ")))
            .step("Downloads IP ranges from ipdeny.com")
            .step("Creates firewall rules to block those ranges")
            .step("Whitelisted IPs are never blocked")
            .step("Export rules with 'defend export'")
            .cheet("security/geoblock/nftables")
    }

    pub fn defend_ban(target: &str, is_asn: bool) -> Self {
        if is_asn {
            Self::new("Block AS Number")
                .description(&format!("Blocks all IP ranges belonging to AS{}", target.trim_start_matches("AS")))
                .step("AS numbers identify network operators")
                .step("Blocking an ASN blocks thousands of IPs")
                .step("Useful for blocking entire hosting providers")
                .cheet("security/asn/blocking")
        } else {
            Self::new("Block IP/Network")
                .description(&format!("Blocks {}", target))
                .step("Adds to blocklist")
                .step("Will be included in exported firewall rules")
                .cheet("security/firewall/blocking")
        }
    }

    pub fn defend_export(format: &str) -> Self {
        Self::new("Export Rules")
            .description(&format!("Generates {} firewall rules from your block configuration.", format))
            .step("Combines country blocks, IP blocks, and ASN blocks")
            .step("Outputs rules you can apply to your firewall")
            .step("Whitelisted IPs are included as allow rules")
            .cheet(&format!("security/firewall/{}", format))
    }
}

/// Get country name from code.
fn country_name(code: &str) -> String {
    match code.to_lowercase().as_str() {
        "cn" => "China".to_string(),
        "ru" => "Russia".to_string(),
        "us" => "United States".to_string(),
        "ro" => "Romania".to_string(),
        "pl" => "Poland".to_string(),
        "kz" => "Kazakhstan".to_string(),
        "ua" => "Ukraine".to_string(),
        "vn" => "Vietnam".to_string(),
        "br" => "Brazil".to_string(),
        "in" => "India".to_string(),
        "kr" => "South Korea".to_string(),
        "de" => "Germany".to_string(),
        "fr" => "France".to_string(),
        "gb" | "uk" => "United Kingdom".to_string(),
        "jp" => "Japan".to_string(),
        "nl" => "Netherlands".to_string(),
        "th" => "Thailand".to_string(),
        "id" => "Indonesia".to_string(),
        _ => code.to_uppercase(),
    }
}
