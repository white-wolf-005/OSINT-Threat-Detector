import {
    AnalysisReport,
    CorrelatedAnalytics,
    CveDescriptor,
    HibpBreachRecord,
    IpApiTelemetry,
    OtxTelemetry,
    PillarBreakdown,
    PortRiskProfile,
    RiskLevel,
    ShodanIdbTelemetry,
    SourceResultItem,
} from "./types.js";

interface PortCatalogEntry {
    service: string;
    protocol: "TCP" | "UDP" | "TCP/UDP";
    severity: "SAFE" | "MODERATE" | "HIGH" | "CRITICAL";
    rationale: string;
}

export class ThreatAnalyticsEngine {
    private static readonly PORT_CATALOG: Record<number, PortCatalogEntry> = {
        21: { service: "FTP", protocol: "TCP", severity: "HIGH", rationale: "Cleartext file transfer protocol susceptible to credential interception" },
        22: { service: "SSH", protocol: "TCP", severity: "MODERATE", rationale: "Remote administration interface targeted by automated brute-force botnets" },
        23: { service: "Telnet", protocol: "TCP", severity: "CRITICAL", rationale: "Unencrypted legacy shell access exposing full session traffic" },
        25: { service: "SMTP", protocol: "TCP", severity: "MODERATE", rationale: "Mail transfer relay potentially abused for spoofing if misconfigured" },
        53: { service: "DNS", protocol: "TCP/UDP", severity: "SAFE", rationale: "Domain Name System resolver or authoritative nameserver" },
        80: { service: "HTTP", protocol: "TCP", severity: "SAFE", rationale: "Unencrypted web traffic endpoint" },
        110: { service: "POP3", protocol: "TCP", severity: "MODERATE", rationale: "Legacy mail retrieval protocol" },
        135: { service: "MS-RPC", protocol: "TCP", severity: "HIGH", rationale: "Windows RPC endpoint mapper frequently targeted in lateral movement" },
        139: { service: "NetBIOS", protocol: "TCP", severity: "HIGH", rationale: "Legacy Windows session service exposing host metadata" },
        443: { service: "HTTPS", protocol: "TCP", severity: "SAFE", rationale: "TLS-encrypted web application service" },
        445: { service: "SMB", protocol: "TCP", severity: "CRITICAL", rationale: "Server Message Block exposed to WAN; high risk of wormable exploits" },
        1433: { service: "MSSQL", protocol: "TCP", severity: "CRITICAL", rationale: "Microsoft SQL Server database port directly accessible from internet" },
        3306: { service: "MySQL", protocol: "TCP", severity: "HIGH", rationale: "Relational database listener exposed outside internal network" },
        3389: { service: "RDP", protocol: "TCP", severity: "CRITICAL", rationale: "Remote Desktop Protocol frequently exploited by ransomware affiliates" },
        5432: { service: "PostgreSQL", protocol: "TCP", severity: "HIGH", rationale: "PostgreSQL database listener exposed to public reconnaissance" },
        5900: { service: "VNC", protocol: "TCP", severity: "CRITICAL", rationale: "Virtual Network Computing graphical remote desktop exposure" },
        6379: { service: "Redis", protocol: "TCP", severity: "CRITICAL", rationale: "In-memory key-value store often targeted for unauthenticated RCE" },
        8080: { service: "HTTP-Alt", protocol: "TCP", severity: "MODERATE", rationale: "Secondary web proxy or application server management port" },
        8443: { service: "HTTPS-Alt", protocol: "TCP", severity: "SAFE", rationale: "Alternative TLS web service or control panel" },
        9200: { service: "Elasticsearch", protocol: "TCP", severity: "CRITICAL", rationale: "Search cluster REST API prone to data exfiltration if unauthenticated" },
        27017: { service: "MongoDB", protocol: "TCP", severity: "CRITICAL", rationale: "NoSQL document store exposed to public network interface" },
    };

    public static evaluatePort(port: number): PortRiskProfile {
        const match: PortCatalogEntry | undefined = ThreatAnalyticsEngine.PORT_CATALOG[port];
        if (match) {
            return {
                port: port,
                service: match.service,
                protocol: match.protocol,
                severity: match.severity,
                rationale: match.rationale,
            };
        }
        return {
            port: port,
            service: "Custom/Unknown",
            protocol: "TCP",
            severity: port < 1024 ? "MODERATE" : "SAFE",
            rationale: "Non-standard or application-specific network service port",
        };
    }

    public static parseCveList(vulns: string[]): CveDescriptor[] {
        return vulns.map((rawCve: string): CveDescriptor => {
            const normalized: string = rawCve.toUpperCase().trim();
            const parts: string[] = normalized.split("-");
            const parsedYear: number = parts.length >= 2 ? parseInt(parts[1] || "2020", 10) : 2020;
            const year: number = Number.isNaN(parsedYear) ? 2020 : parsedYear;
            const estimatedSeverity: "HIGH" | "CRITICAL" | "MODERATE" =
                year >= 2022 ? "CRITICAL" : year >= 2018 ? "HIGH" : "MODERATE";

            return {
                cveId: normalized,
                year: year,
                estimatedSeverity: estimatedSeverity,
            };
        });
    }

    public static correlate(report: AnalysisReport): CorrelatedAnalytics {
        let shodanData: ShodanIdbTelemetry | null = null;
        let ipApiData: IpApiTelemetry | null = null;
        let otxData: OtxTelemetry | null = null;
        let hibpData: HibpBreachRecord[] | null = null;

        report.results.forEach((item: SourceResultItem): void => {
            if (item.error || !item.data) {
                return;
            }
            if (item.source === "Shodan IDB" && !Array.isArray(item.data)) {
                shodanData = item.data as ShodanIdbTelemetry;
            } else if (item.source === "IP-API" && !Array.isArray(item.data)) {
                ipApiData = item.data as IpApiTelemetry;
            } else if (item.source === "AlienVault OTX" && !Array.isArray(item.data)) {
                otxData = item.data as OtxTelemetry;
            } else if (item.source === "HaveIBeenPwned" && Array.isArray(item.data)) {
                hibpData = item.data as HibpBreachRecord[];
            }
        });

        const rawPorts: number[] = shodanData ? (shodanData as ShodanIdbTelemetry).ports || [] : [];
        const rawVulns: string[] = shodanData ? (shodanData as ShodanIdbTelemetry).vulns || [] : [];

        const portProfiles: PortRiskProfile[] = rawPorts.map((p: number): PortRiskProfile =>
            ThreatAnalyticsEngine.evaluatePort(p)
        );
        const cveDescriptors: CveDescriptor[] = ThreatAnalyticsEngine.parseCveList(rawVulns);

        const highRiskPorts: PortRiskProfile[] = portProfiles.filter(
            (p: PortRiskProfile): boolean => p.severity === "CRITICAL" || p.severity === "HIGH"
        );

        const networkFindings: string[] = [];
        let networkImpact: number = 0;

        if (rawPorts.length > 0) {
            networkFindings.push(String(rawPorts.length) + " open port(s) indexed by Shodan InternetDB");
        } else {
            networkFindings.push("Zero exposed ports detected in passive scan");
        }

        if (highRiskPorts.length > 0) {
            networkImpact += Math.min(highRiskPorts.length * 15, 45);
            const names: string = highRiskPorts
                .map((p: PortRiskProfile): string => String(p.port) + "/" + p.service)
                .join(", ");
            networkFindings.push("High-risk administrative/DB services: " + names);
        }

        if (cveDescriptors.length > 0) {
            networkImpact += Math.min(cveDescriptors.length * 12, 50);
            networkFindings.push(String(cveDescriptors.length) + " unpatched CVE identifier(s) associated with host");
        }

        const feedFindings: string[] = [];
        let feedImpact: number = 0;

        if (otxData) {
            const pulses: number = (otxData as OtxTelemetry).pulses_found || 0;
            if (pulses > 0) {
                feedImpact += Math.min(pulses * 8, 45);
                feedFindings.push("Referenced in " + String(pulses) + " AlienVault OTX threat intelligence pulse(s)");
            } else {
                feedFindings.push("Zero active threat pulses in AlienVault OTX");
            }
        }

        if (hibpData) {
            const count: number = (hibpData as HibpBreachRecord[]).length;
            if (count > 0) {
                feedImpact += Math.min(count * 15, 90);
                feedFindings.push("Identity exposed in " + String(count) + " verified credential breach dataset(s)");
            } else {
                feedFindings.push("Zero credential leaks found in HaveIBeenPwned");
            }
        }

        if (feedFindings.length === 0) {
            feedFindings.push("No external threat feed hits recorded");
        }

        const infraFindings: string[] = [];
        let infraImpact: number = 0;

        if (ipApiData) {
            const telemetry: IpApiTelemetry = ipApiData as IpApiTelemetry;
            infraFindings.push("ASN: " + (telemetry.as || "N/A") + " (" + (telemetry.isp || "Unknown ISP") + ")");
            infraFindings.push("Geolocation: " + (telemetry.city || "Unknown") + ", " + (telemetry.country || "Unknown"));
            if (telemetry.proxy) {
                infraImpact += 20;
                infraFindings.push("Flagged as anonymizing Proxy / VPN / Tor exit node");
            }
            if (telemetry.hosting) {
                infraImpact += 10;
                infraFindings.push("Classified as cloud datacenter / dedicated hosting range");
            }
        } else if (report.type === "email") {
            infraFindings.push("Identity-level target; BGP/ASN telemetry not applicable");
        } else {
            infraFindings.push("Infrastructure telemetry unavailable for target");
        }

        const pillars: PillarBreakdown[] = [
            {
                title: "Network Attack Surface",
                scoreImpact: Math.min(networkImpact, 60),
                maxImpact: 60,
                statusLabel: networkImpact >= 25 ? "ELEVATED" : "NOMINAL",
                findings: networkFindings,
            },
            {
                title: "Threat Feeds & Breaches",
                scoreImpact: Math.min(feedImpact, 60),
                maxImpact: 60,
                statusLabel: feedImpact >= 20 ? "COMPROMISED" : "CLEAN",
                findings: feedFindings,
            },
            {
                title: "BGP & Hosting Posture",
                scoreImpact: Math.min(infraImpact, 30),
                maxImpact: 30,
                statusLabel: infraImpact >= 15 ? "ANONYMIZED" : "STANDARD",
                findings: infraFindings,
            },
        ];

        const riskLevel: RiskLevel = report.risk_level || ThreatAnalyticsEngine.computeRisk(report.threat_score);
        const executiveSummary: string = ThreatAnalyticsEngine.buildSummary(
            report,
            riskLevel,
            portProfiles.length,
            cveDescriptors.length
        );

        return {
            riskLevel: riskLevel,
            portProfiles: portProfiles,
            cveDescriptors: cveDescriptors,
            pillars: pillars,
            executiveSummary: executiveSummary,
        };
    }

    private static computeRisk(score: number): RiskLevel {
        if (score >= 75) {
            return "CRITICAL";
        }
        if (score >= 45) {
            return "HIGH";
        }
        if (score >= 20) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private static buildSummary(
        report: AnalysisReport,
        riskLevel: RiskLevel,
        openPortCount: number,
        cveCount: number
    ): string {
        if (report.type === "email") {
            return (
                "Target email indicator " +
                report.target +
                " evaluated at " +
                riskLevel +
                " risk (Score: " +
                String(report.threat_score) +
                "/100)."
            );
        }
        const resolvedNote: string = report.resolved_ip ? " (Resolved IPv4: " + report.resolved_ip + ")" : "";
        return (
            "Target " +
            report.target +
            resolvedNote +
            " classified as " +
            riskLevel +
            " risk (" +
            String(report.threat_score) +
            "/100) with " +
            String(openPortCount) +
            " open port(s) and " +
            String(cveCount) +
            " known CVE exposure(s)."
        );
    }
}