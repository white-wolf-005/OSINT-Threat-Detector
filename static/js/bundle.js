"use strict";
(() => {
    class IOCValidator {
        static refangIndicator(rawInput) {
            const trimmed = rawInput.trim();
            let processed = trimmed
                .replace(/\[\.\]/g, ".")
                .replace(/\(\.\)/g, ".")
                .replace(/\[dot\]/gi, ".")
                .replace(/\[@\]/g, "@")
                .replace(/\[at\]/gi, "@")
                .replace(/^hxxps:\/\//i, "https://")
                .replace(/^hxxp:\/\//i, "http://");
            if (processed.startsWith("http://") || processed.startsWith("https://")) {
                try {
                    const parsedUrl = new URL(processed);
                    processed = parsedUrl.hostname;
                } catch {
                    processed = processed.replace(/^https?:\/\//i, "").split("/")[0] || processed;
                }
            } else if (processed.includes("/") && !processed.includes("@")) {
                processed = processed.split("/")[0] || processed;
            }
            if (processed.includes(":") && !processed.includes("@")) {
                const parts = processed.split(":");
                if (parts.length === 2 && /^\d+$/.test(parts[1] || "")) {
                    processed = parts[0] || processed;
                }
            }
            const finalClean = processed.toLowerCase().trim();
            return {
                cleaned: finalClean,
                wasModified: finalClean !== trimmed.toLowerCase(),
            };
        }
        static isPrivateOrReservedIpv4(ip) {
            const octets = ip.split(".").map((part) => parseInt(part, 10));
            if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) {
                return false;
            }
            const first = octets[0] ?? 0;
            const second = octets[1] ?? 0;
            if (first === 0 || first === 10 || first === 127) return true;
            if (first === 100 && second >= 64 && second <= 127) return true;
            if (first === 169 && second === 254) return true;
            if (first === 172 && second >= 16 && second <= 31) return true;
            if (first === 192 && second === 168) return true;
            if (first >= 224) return true;
            return false;
        }
        static inspect(rawInput) {
            if (!rawInput || rawInput.trim().length < 3) {
                return {
                    isValid: false,
                    normalizedTarget: "",
                    detectedCategory: "invalid",
                    isPrivateNetwork: false,
                    wasDefanged: false,
                    advisoryMessage: "Enter an IPv4 address, domain name, or email indicator.",
                };
            }
            const refanged = IOCValidator.refangIndicator(rawInput);
            const cleaned = refanged.cleaned;
            const wasModified = refanged.wasModified;
            if (IOCValidator.IPV4_REGEX.test(cleaned)) {
                const isPrivate = IOCValidator.isPrivateOrReservedIpv4(cleaned);
                if (isPrivate) {
                    return {
                        isValid: false,
                        normalizedTarget: cleaned,
                        detectedCategory: "IPv4",
                        isPrivateNetwork: true,
                        wasDefanged: wasModified,
                        advisoryMessage: "RFC1918 / Reserved IPv4 detected. External OSINT requires a public routable IP.",
                    };
                }
                return {
                    isValid: true,
                    normalizedTarget: cleaned,
                    detectedCategory: "IPv4",
                    isPrivateNetwork: false,
                    wasDefanged: wasModified,
                    advisoryMessage: wasModified
                        ? "Refanged IOC to public IPv4: " + cleaned
                        : "Valid public IPv4 indicator ready for BGP, Shodan & OTX reconnaissance.",
                };
            }
            if (IOCValidator.EMAIL_REGEX.test(cleaned)) {
                return {
                    isValid: true,
                    normalizedTarget: cleaned,
                    detectedCategory: "email",
                    isPrivateNetwork: false,
                    wasDefanged: wasModified,
                    advisoryMessage: wasModified
                        ? "Refanged IOC to Email: " + cleaned
                        : "Valid email identity ready for credential breach reconnaissance.",
                };
            }
            if (IOCValidator.DOMAIN_REGEX.test(cleaned)) {
                return {
                    isValid: true,
                    normalizedTarget: cleaned,
                    detectedCategory: "domain",
                    isPrivateNetwork: false,
                    wasDefanged: wasModified,
                    advisoryMessage: wasModified
                        ? "Extracted and refanged hostname: " + cleaned
                        : "Valid domain indicator ready for DNS resolution, Shodan & OTX reconnaissance.",
                };
            }
            return {
                isValid: false,
                normalizedTarget: cleaned,
                detectedCategory: "invalid",
                isPrivateNetwork: false,
                wasDefanged: wasModified,
                advisoryMessage: "Unrecognized IOC format. Expected public IPv4, registered domain, or email.",
            };
        }
    }
    IOCValidator.IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    IOCValidator.EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}$/;
    IOCValidator.DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$/;

    class ThreatAnalyticsEngine {
        static evaluatePort(port) {
            const match = ThreatAnalyticsEngine.PORT_CATALOG[port];
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
        static parseCveList(vulns) {
            return vulns.map((rawCve) => {
                const normalized = rawCve.toUpperCase().trim();
                const parts = normalized.split("-");
                const parsedYear = parts.length >= 2 ? parseInt(parts[1] || "2020", 10) : 2020;
                const year = Number.isNaN(parsedYear) ? 2020 : parsedYear;
                const estimatedSeverity = year >= 2022 ? "CRITICAL" : year >= 2018 ? "HIGH" : "MODERATE";
                return { cveId: normalized, year: year, estimatedSeverity: estimatedSeverity };
            });
        }
        static correlate(report) {
            let shodanData = null;
            let ipApiData = null;
            let otxData = null;
            let hibpData = null;
            report.results.forEach((item) => {
                if (item.error || !item.data) return;
                if (item.source === "Shodan IDB" && !Array.isArray(item.data)) shodanData = item.data;
                else if (item.source === "IP-API" && !Array.isArray(item.data)) ipApiData = item.data;
                else if (item.source === "AlienVault OTX" && !Array.isArray(item.data)) otxData = item.data;
                else if (item.source === "HaveIBeenPwned" && Array.isArray(item.data)) hibpData = item.data;
            });
            const rawPorts = shodanData ? shodanData.ports || [] : [];
            const rawVulns = shodanData ? shodanData.vulns || [] : [];
            const portProfiles = rawPorts.map((p) => ThreatAnalyticsEngine.evaluatePort(p));
            const cveDescriptors = ThreatAnalyticsEngine.parseCveList(rawVulns);
            const highRiskPorts = portProfiles.filter((p) => p.severity === "CRITICAL" || p.severity === "HIGH");
            const networkFindings = [];
            let networkImpact = 0;
            if (rawPorts.length > 0) {
                networkFindings.push(String(rawPorts.length) + " open port(s) indexed by Shodan InternetDB");
            } else {
                networkFindings.push("Zero exposed ports detected in passive scan");
            }
            if (highRiskPorts.length > 0) {
                networkImpact += Math.min(highRiskPorts.length * 15, 45);
                const names = highRiskPorts.map((p) => String(p.port) + "/" + p.service).join(", ");
                networkFindings.push("High-risk administrative/DB services: " + names);
            }
            if (cveDescriptors.length > 0) {
                networkImpact += Math.min(cveDescriptors.length * 12, 50);
                networkFindings.push(String(cveDescriptors.length) + " unpatched CVE identifier(s) associated with host");
            }
            const feedFindings = [];
            let feedImpact = 0;
            if (otxData) {
                const pulses = otxData.pulses_found || 0;
                if (pulses > 0) {
                    feedImpact += Math.min(pulses * 8, 45);
                    feedFindings.push("Referenced in " + String(pulses) + " AlienVault OTX threat intelligence pulse(s)");
                } else {
                    feedFindings.push("Zero active threat pulses in AlienVault OTX");
                }
            }
            if (hibpData) {
                const count = hibpData.length;
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
            const infraFindings = [];
            let infraImpact = 0;
            if (ipApiData) {
                infraFindings.push("ASN: " + (ipApiData.as || "N/A") + " (" + (ipApiData.isp || "Unknown ISP") + ")");
                infraFindings.push("Geolocation: " + (ipApiData.city || "Unknown") + ", " + (ipApiData.country || "Unknown"));
                if (ipApiData.proxy) {
                    infraImpact += 20;
                    infraFindings.push("Flagged as anonymizing Proxy / VPN / Tor exit node");
                }
                if (ipApiData.hosting) {
                    infraImpact += 10;
                    infraFindings.push("Classified as cloud datacenter / dedicated hosting range");
                }
            } else if (report.type === "email") {
                infraFindings.push("Identity-level target; BGP/ASN telemetry not applicable");
            } else {
                infraFindings.push("Infrastructure telemetry unavailable for target");
            }
            const pillars = [
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
            const riskLevel = report.risk_level || ThreatAnalyticsEngine.computeRisk(report.threat_score);
            const executiveSummary = ThreatAnalyticsEngine.buildSummary(
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
        static computeRisk(score) {
            if (score >= 75) return "CRITICAL";
            if (score >= 45) return "HIGH";
            if (score >= 20) return "MEDIUM";
            return "LOW";
        }
        static buildSummary(report, riskLevel, openPortCount, cveCount) {
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
            const resolvedNote = report.resolved_ip ? " (Resolved IPv4: " + report.resolved_ip + ")" : "";
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
    ThreatAnalyticsEngine.PORT_CATALOG = {
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

    class IntelligenceExporter {
        static triggerFileDownload(filename, content, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const objectUrl = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = objectUrl;
            anchor.download = filename;
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
            URL.revokeObjectURL(objectUrl);
        }
        static sanitizeFilename(target) {
            return target.replace(/[^a-zA-Z0-9._-]/g, "_");
        }
        static exportJson(report, analytics) {
            const payload = {
                generated_at: new Date().toISOString(),
                engine: "OSINT Threat Intelligence Engine v2.0",
                report: report,
                analytics: analytics,
            };
            const safeName = IntelligenceExporter.sanitizeFilename(report.target);
            IntelligenceExporter.triggerFileDownload(
                "osint_report_" + safeName + ".json",
                JSON.stringify(payload, null, 2),
                "application/json;charset=utf-8"
            );
        }
        static exportCsv(report, analytics) {
            const rows = [
                ["Target", "Resolved_IP", "Type", "Threat_Score", "Risk_Level", "Open_Ports", "CVEs_Detected", "Source_Count"],
                [
                    report.target,
                    report.resolved_ip || "N/A",
                    report.type,
                    String(report.threat_score),
                    analytics.riskLevel,
                    analytics.portProfiles.map((p) => String(p.port) + "/" + p.service).join("; ") || "None",
                    analytics.cveDescriptors.map((c) => c.cveId).join("; ") || "None",
                    String(report.sources_checked),
                ],
            ];
            const csvString = rows
                .map((row) => row.map((cell) => '"' + cell.replace(/"/g, '""') + '"').join(","))
                .join("\r\n");
            const safeName = IntelligenceExporter.sanitizeFilename(report.target);
            IntelligenceExporter.triggerFileDownload(
                "osint_report_" + safeName + ".csv",
                csvString,
                "text/csv;charset=utf-8"
            );
        }
        static exportMarkdown(report, analytics) {
            const lines = [
                "OSINT Threat Intelligence Report: " + report.target,
                "====================================================",
                "",
                "* Generated At: " + new Date().toUTCString(),
                "* Indicator Type: " + report.type,
                "* Resolved IPv4: " + (report.resolved_ip || "N/A"),
                "* Heuristic Threat Score: " + String(report.threat_score) + " / 100",
                "* Risk Classification: " + analytics.riskLevel,
                "",
                "Executive Summary",
                "=================",
                analytics.executiveSummary,
                "",
                "Pillar Breakdown",
                "================",
            ];
            analytics.pillars.forEach((pillar) => {
                lines.push(
                    "* " +
                        pillar.title +
                        " (" +
                        pillar.statusLabel +
                        " - Impact: " +
                        String(pillar.scoreImpact) +
                        "/" +
                        String(pillar.maxImpact) +
                        ")"
                );
                pillar.findings.forEach((finding) => lines.push("  * " + finding));
                lines.push("");
            });
            if (analytics.portProfiles.length > 0) {
                lines.push("Exposed Network Ports");
                lines.push("=====================");
                analytics.portProfiles.forEach((p) => {
                    lines.push(
                        "* Port " +
                            String(p.port) +
                            " (" +
                            p.service +
                            " / " +
                            p.protocol +
                            ") - Severity: " +
                            p.severity +
                            " - " +
                            p.rationale
                    );
                });
                lines.push("");
            }
            lines.push("Raw Intelligence Feeds");
            lines.push("======================");
            report.results.forEach((res) => {
                const statusText = res.error ? "Error (" + res.error + ")" : "Telemetry Collected";
                lines.push("* " + res.source + ": " + statusText);
            });
            const safeName = IntelligenceExporter.sanitizeFilename(report.target);
            IntelligenceExporter.triggerFileDownload(
                "osint_report_" + safeName + ".md",
                lines.join("\n"),
                "text/markdown;charset=utf-8"
            );
        }
    }

    class DashboardComponents {
        static escapeHtml(unsafe) {
            return String(unsafe)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        static getRiskBadgeStyle(risk) {
            switch (risk) {
                case "CRITICAL":
                    return "bg-rose-950 text-rose-300 border border-rose-700";
                case "HIGH":
                    return "bg-orange-950 text-orange-300 border border-orange-700";
                case "MEDIUM":
                    return "bg-amber-950 text-amber-300 border border-amber-700";
                default:
                    return "bg-emerald-950 text-emerald-300 border border-emerald-700";
            }
        }
        static renderPillars(pillars) {
            return pillars
                .map((pillar) => {
                    const findingsHtml = pillar.findings
                        .map((f) => {
                            return (
                                '<li class="text-xs text-slate-300 flex items-start gap-1.5">' +
                                '<span class="text-indigo-400">▸</span>' +
                                "<span>" +
                                DashboardComponents.escapeHtml(f) +
                                "</span></li>"
                            );
                        })
                        .join("");
                    const badgeClass =
                        pillar.scoreImpact >= 20
                            ? "bg-rose-950 text-rose-300 border-rose-800"
                            : "bg-slate-800 text-slate-300 border-slate-700";
                    return [
                        '<div class="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">',
                        "<div>",
                        '<div class="flex items-center justify-between gap-2 mb-3">',
                        '<h3 class="text-xs font-bold uppercase tracking-wider text-slate-400">' +
                            DashboardComponents.escapeHtml(pillar.title) +
                            "</h3>",
                        '<span class="text-[11px] font-mono px-2 py-0.5 rounded border ' +
                            badgeClass +
                            '">' +
                            DashboardComponents.escapeHtml(pillar.statusLabel) +
                            "</span>",
                        "</div>",
                        '<ul class="space-y-1.5 mb-3">' + findingsHtml + "</ul>",
                        "</div>",
                        '<div class="pt-2 border-t border-slate-900 flex justify-between items-center text-xs text-slate-400">',
                        "<span>Risk Contribution</span>",
                        '<span class="font-mono font-bold text-white">+' + String(pillar.scoreImpact) + " pts</span>",
                        "</div>",
                        "</div>",
                    ].join("");
                })
                .join("");
        }
        static renderSourceCards(results, analytics) {
            return results
                .map((res) => {
                    const title = DashboardComponents.escapeHtml(res.source);
                    if (res.error || !res.data) {
                        const errText = DashboardComponents.escapeHtml(res.error || "No data returned");
                        return [
                            '<div class="p-5 rounded-xl bg-slate-950 border border-slate-800">',
                            '<div class="flex justify-between items-center mb-2">',
                            '<h3 class="font-bold text-slate-200">' + title + "</h3>",
                            '<span class="text-xs px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">Skipped / Offline</span>',
                            "</div>",
                            '<p class="text-xs text-rose-400 font-mono">' + errText + "</p>",
                            "</div>",
                        ].join("");
                    }
                    if (res.source === "IP-API" && !Array.isArray(res.data)) {
                        const ipData = res.data;
                        const flags = [];
                        if (ipData.proxy) flags.push("Proxy/VPN");
                        if (ipData.hosting) flags.push("Hosting/DC");
                        if (ipData.mobile) flags.push("Mobile ISP");
                        const flagText = flags.length > 0 ? flags.join(", ") : "Standard Residential/Enterprise";
                        return [
                            '<div class="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">',
                            '<div class="flex justify-between items-center">',
                            '<h3 class="font-bold text-white">' + title + " BGP &amp; Geo</h3>",
                            '<span class="text-xs font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">' +
                                DashboardComponents.escapeHtml(ipData.countryCode || "IP") +
                                "</span>",
                            "</div>",
                            '<div class="grid grid-cols-2 gap-2 text-xs pt-1">',
                            '<div><span class="text-slate-500">ASN:</span> <span class="text-slate-200 font-mono">' +
                                DashboardComponents.escapeHtml(ipData.as || "N/A") +
                                "</span></div>",
                            '<div><span class="text-slate-500">ISP:</span> <span class="text-slate-200">' +
                                DashboardComponents.escapeHtml(ipData.isp || "N/A") +
                                "</span></div>",
                            '<div><span class="text-slate-500">Location:</span> <span class="text-slate-200">' +
                                DashboardComponents.escapeHtml(ipData.city || "") +
                                ", " +
                                DashboardComponents.escapeHtml(ipData.country || "") +
                                "</span></div>",
                            '<div><span class="text-slate-500">PTR:</span> <span class="text-slate-300 font-mono">' +
                                DashboardComponents.escapeHtml(ipData.reverse || "None") +
                                "</span></div>",
                            "</div>",
                            '<div class="text-xs pt-2 border-t border-slate-900 text-slate-400">',
                            'Network Classification: <span class="font-semibold text-slate-200">' +
                                DashboardComponents.escapeHtml(flagText) +
                                "</span>",
                            "</div>",
                            "</div>",
                        ].join("");
                    }
                    if (res.source === "Shodan IDB" && !Array.isArray(res.data)) {
                        const shodan = res.data;
                        const portBadges =
                            analytics.portProfiles.length > 0
                                ? analytics.portProfiles
                                      .map((p) => {
                                          const color =
                                              p.severity === "CRITICAL" || p.severity === "HIGH"
                                                  ? "bg-rose-950 text-rose-300 border-rose-800"
                                                  : "bg-slate-900 text-indigo-300 border-slate-700";
                                          return (
                                              '<span title="' +
                                              DashboardComponents.escapeHtml(p.rationale) +
                                              '" class="inline-block text-xs font-mono px-2 py-0.5 rounded border ' +
                                              color +
                                              '">' +
                                              String(p.port) +
                                              "/" +
                                              DashboardComponents.escapeHtml(p.service) +
                                              "</span>"
                                          );
                                      })
                                      .join(" ")
                                : '<span class="text-xs text-emerald-400">No open ports indexed</span>';
                        const cveBadges =
                            analytics.cveDescriptors.length > 0
                                ? analytics.cveDescriptors
                                      .slice(0, 8)
                                      .map((c) => {
                                          return (
                                              '<span class="inline-block text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950/90 text-rose-200 border border-rose-800">' +
                                              DashboardComponents.escapeHtml(c.cveId) +
                                              "</span>"
                                          );
                                      })
                                      .join(" ")
                                : '<span class="text-xs text-emerald-400">Zero known CVEs</span>';
                        const hostnames =
                            shodan.hostnames && shodan.hostnames.length > 0
                                ? DashboardComponents.escapeHtml(shodan.hostnames.slice(0, 3).join(", "))
                                : "None";
                        return [
                            '<div class="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">',
                            '<div class="flex justify-between items-center">',
                            '<h3 class="font-bold text-white">' + title + " Exposure</h3>",
                            '<span class="text-xs font-mono text-slate-400">' +
                                DashboardComponents.escapeHtml(shodan.ip || "") +
                                "</span>",
                            "</div>",
                            "<div>",
                            '<p class="text-xs text-slate-400 mb-1.5">Indexed Open Ports:</p>',
                            '<div class="flex flex-wrap gap-1.5">' + portBadges + "</div>",
                            "</div>",
                            "<div>",
                            '<p class="text-xs text-slate-400 mb-1.5">Associated Vulnerabilities (CVE):</p>',
                            '<div class="flex flex-wrap gap-1.5">' + cveBadges + "</div>",
                            "</div>",
                            '<p class="text-xs text-slate-400 pt-1 border-t border-slate-900">Hostnames: <span class="font-mono text-slate-300">' +
                                hostnames +
                                "</span></p>",
                            "</div>",
                        ].join("");
                    }
                    if (res.source === "AlienVault OTX" && !Array.isArray(res.data)) {
                        const otx = res.data;
                        const pulseList =
                            otx.recent_pulses && otx.recent_pulses.length > 0
                                ? otx.recent_pulses
                                      .map((name) => {
                                          return (
                                              '<li class="text-xs text-rose-300 truncate">• ' +
                                              DashboardComponents.escapeHtml(name) +
                                              "</li>"
                                          );
                                      })
                                      .join("")
                                : '<li class="text-xs text-emerald-400">No active threat pulses linked to indicator</li>';
                        const otxBadgeStyle =
                            otx.pulses_found > 0
                                ? "bg-rose-950 text-rose-300 border border-rose-800"
                                : "bg-emerald-950 text-emerald-300 border border-emerald-800";
                        return [
                            '<div class="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">',
                            '<div class="flex justify-between items-center">',
                            '<h3 class="font-bold text-white">' + title + "</h3>",
                            '<span class="text-xs font-bold px-2.5 py-0.5 rounded ' +
                                otxBadgeStyle +
                                '">' +
                                String(otx.pulses_found) +
                                " Pulse(s)</span>",
                            "</div>",
                            '<ul class="space-y-1 pt-1">' + pulseList + "</ul>",
                            "</div>",
                        ].join("");
                    }
                    if (res.source === "HaveIBeenPwned" && Array.isArray(res.data)) {
                        const breaches = res.data;
                        const breachItems =
                            breaches.length > 0
                                ? breaches
                                      .slice(0, 6)
                                      .map((b) => {
                                          return (
                                              '<span class="text-xs font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">' +
                                              DashboardComponents.escapeHtml(b.Name) +
                                              " (" +
                                              DashboardComponents.escapeHtml(b.BreachDate) +
                                              ")</span>"
                                          );
                                      })
                                      .join(" ")
                                : '<span class="text-xs text-emerald-400">Zero credential breaches found</span>';
                        const hibpBadgeStyle =
                            breaches.length > 0 ? "bg-rose-950 text-rose-300" : "bg-emerald-950 text-emerald-300";
                        return [
                            '<div class="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">',
                            '<div class="flex justify-between items-center">',
                            '<h3 class="font-bold text-white">' + title + "</h3>",
                            '<span class="text-xs font-bold px-2.5 py-0.5 rounded ' +
                                hibpBadgeStyle +
                                '">' +
                                String(breaches.length) +
                                " Breach(es)</span>",
                            "</div>",
                            '<div class="flex flex-wrap gap-1.5 pt-1">' + breachItems + "</div>",
                            "</div>",
                        ].join("");
                    }
                    return "";
                })
                .join("");
        }
        static renderHistoryItems(records) {
            if (records.length === 0) {
                return '<p class="text-xs text-slate-500 text-center py-6">No matching reconnaissance records in audit history.</p>';
            }
            return records
                .map((item) => {
                    const parsedDate = new Date(item.created_at);
                    const formattedDate = parsedDate.toLocaleString("en-US", {
                        month: "short",
                        day: "2-digit",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                    });
                    const scoreBadge =
                        item.threat_score >= 45
                            ? "bg-rose-950 text-rose-300 border-rose-800"
                            : item.threat_score >= 20
                            ? "bg-amber-950 text-amber-300 border-amber-800"
                            : "bg-emerald-950 text-emerald-300 border-emerald-800";
                    const safeTarget = DashboardComponents.escapeHtml(item.target);
                    return [
                        '<div data-rescan="' +
                            safeTarget +
                            '" class="history-item cursor-pointer flex justify-between items-center p-3.5 bg-slate-950 rounded-xl border border-slate-800 hover:border-indigo-700 transition">',
                        '<div class="flex items-center gap-3">',
                        '<span class="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700">' +
                            DashboardComponents.escapeHtml(item.type) +
                            "</span>",
                        "<div>",
                        '<p class="font-mono text-sm font-semibold text-white">' + safeTarget + "</p>",
                        '<p class="text-xs text-slate-500">' + formattedDate + "</p>",
                        "</div>",
                        "</div>",
                        '<div class="flex items-center gap-3">',
                        '<span class="text-xs font-mono font-semibold px-2.5 py-1 rounded border ' +
                            scoreBadge +
                            '">Score: ' +
                            String(item.threat_score) +
                            "</span>",
                        '<span class="text-xs text-indigo-400 hover:underline">Rescan →</span>',
                        "</div>",
                        "</div>",
                    ].join("");
                })
                .join("");
        }
    }

    class OSINTDashboardApp {
        constructor() {
            this.currentReport = null;
            this.currentAnalytics = null;
            this.cachedHistory = [];
            this.formEl = document.getElementById("analyzeForm");
            this.targetInputEl = document.getElementById("target");
            this.submitBtnEl = document.getElementById("submitBtn");
            this.iocBadgeEl = document.getElementById("iocPreviewBadge");
            this.validationHintEl = document.getElementById("validationHint");
            this.loadingEl = document.getElementById("loading");
            this.errorAlertEl = document.getElementById("errorAlert");
            this.resultAreaEl = document.getElementById("resultArea");
            this.historyAreaEl = document.getElementById("historyArea");
            this.historyFilterEl = document.getElementById("historyFilterType");
            this.historySearchEl = document.getElementById("historySearchInput");
        }
        async init() {
            this.bindEvents();
            await Promise.all([this.checkHealth(), this.refreshStats(), this.loadHistory()]);
        }
        bindEvents() {
            this.targetInputEl.addEventListener("input", () => {
                this.handleLiveValidation();
            });
            this.formEl.addEventListener("submit", async (event) => {
                event.preventDefault();
                await this.executeAnalysis();
            });
            const presetButtons = document.querySelectorAll(".preset-btn");
            presetButtons.forEach((btn) => {
                btn.addEventListener("click", async () => {
                    const presetTarget = btn.getAttribute("data-preset") || "";
                    if (presetTarget) {
                        this.targetInputEl.value = presetTarget;
                        this.handleLiveValidation();
                        await this.executeAnalysis();
                    }
                });
            });
            const loadHistoryBtn = document.getElementById("loadHistoryBtn");
            if (loadHistoryBtn) {
                loadHistoryBtn.addEventListener("click", async () => {
                    await this.loadHistory();
                });
            }
            this.historyFilterEl.addEventListener("change", () => {
                this.renderFilteredHistory();
            });
            this.historySearchEl.addEventListener("input", () => {
                this.renderFilteredHistory();
            });
            document.getElementById("exportJsonBtn")?.addEventListener("click", () => {
                if (this.currentReport && this.currentAnalytics) {
                    IntelligenceExporter.exportJson(this.currentReport, this.currentAnalytics);
                }
            });
            document.getElementById("exportCsvBtn")?.addEventListener("click", () => {
                if (this.currentReport && this.currentAnalytics) {
                    IntelligenceExporter.exportCsv(this.currentReport, this.currentAnalytics);
                }
            });
            document.getElementById("exportMdBtn")?.addEventListener("click", () => {
                if (this.currentReport && this.currentAnalytics) {
                    IntelligenceExporter.exportMarkdown(this.currentReport, this.currentAnalytics);
                }
            });
        }
        handleLiveValidation() {
            const outcome = IOCValidator.inspect(this.targetInputEl.value);
            this.validationHintEl.textContent = outcome.advisoryMessage;
            if (!this.targetInputEl.value.trim()) {
                this.iocBadgeEl.textContent = "Awaiting IOC Input";
                this.iocBadgeEl.className =
                    "text-xs font-mono px-2.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700";
                return outcome;
            }
            if (outcome.isValid) {
                this.iocBadgeEl.textContent = "VALID " + outcome.detectedCategory.toUpperCase();
                this.iocBadgeEl.className =
                    "text-xs font-mono px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
            } else {
                this.iocBadgeEl.textContent = outcome.isPrivateNetwork ? "PRIVATE IP (BLOCKED)" : "INVALID IOC";
                this.iocBadgeEl.className =
                    "text-xs font-mono px-2.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800";
            }
            return outcome;
        }
        async checkHealth() {
            const badge = document.getElementById("healthBadge");
            if (!badge) return;
            try {
                const response = await fetch("/api/health");
                if (response.ok) {
                    const payload = await response.json();
                    const cacheStatus = payload.redis_connected ? "Redis Active" : "Local Mode";
                    badge.textContent = "Engine Online (" + cacheStatus + ")";
                    badge.className =
                        "px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800";
                }
            } catch {
                badge.textContent = "Engine Offline";
                badge.className =
                    "px-3 py-1 rounded-full text-xs font-semibold bg-rose-950 text-rose-300 border border-rose-800";
            }
        }
        async refreshStats() {
            try {
                const response = await fetch("/api/stats");
                if (!response.ok) return;
                const payload = await response.json();
                if (payload.status === "success") {
                    const totalEl = document.getElementById("statTotalScans");
                    const avgEl = document.getElementById("statAvgScore");
                    const highEl = document.getElementById("statHighRisk");
                    if (totalEl) totalEl.textContent = String(payload.data.total_scans);
                    if (avgEl) avgEl.textContent = String(payload.data.average_threat_score);
                    if (highEl) highEl.textContent = String(payload.data.high_risk_detections);
                }
            } catch {
                return;
            }
        }
        async executeAnalysis() {
            const validation = this.handleLiveValidation();
            this.errorAlertEl.classList.add("hidden");
            if (!validation.isValid) {
                this.errorAlertEl.textContent = validation.advisoryMessage;
                this.errorAlertEl.classList.remove("hidden");
                return;
            }
            this.targetInputEl.value = validation.normalizedTarget;
            this.submitBtnEl.disabled = true;
            this.resultAreaEl.classList.add("hidden");
            this.loadingEl.classList.remove("hidden");
            try {
                const response = await fetch("/api/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target: validation.normalizedTarget }),
                });
                if (!response.ok) {
                    throw new Error("HTTP " + String(response.status));
                }
                const payload = await response.json();
                if (payload.status === "success" && payload.data) {
                    this.currentReport = payload.data;
                    this.currentAnalytics = ThreatAnalyticsEngine.correlate(payload.data);
                    this.renderAnalysisResult(payload.data, this.currentAnalytics, payload.cached);
                    await Promise.all([this.refreshStats(), this.loadHistory()]);
                }
            } catch (err) {
                const msg = err instanceof Error ? err.message : "Unknown network error";
                this.errorAlertEl.textContent = "Reconnaissance request failed: " + msg;
                this.errorAlertEl.classList.remove("hidden");
            } finally {
                this.submitBtnEl.disabled = false;
                this.loadingEl.classList.add("hidden");
            }
        }
        renderAnalysisResult(report, analytics, isCached) {
            const targetEl = document.getElementById("resTarget");
            const resolvedIpEl = document.getElementById("resResolvedIp");
            const scoreEl = document.getElementById("resScore");
            const typeBadgeEl = document.getElementById("resTypeBadge");
            const cacheBadgeEl = document.getElementById("resCacheBadge");
            const riskBadgeEl = document.getElementById("resRiskBadge");
            const breakdownEl = document.getElementById("analyticsBreakdown");
            const summaryCardsEl = document.getElementById("summaryCards");
            const jsonResultEl = document.getElementById("jsonResult");
            if (targetEl) targetEl.textContent = report.target;
            if (resolvedIpEl) {
                resolvedIpEl.textContent =
                    report.resolved_ip && report.resolved_ip !== report.target
                        ? "Resolved IPv4: " + report.resolved_ip
                        : "";
            }
            if (scoreEl) scoreEl.textContent = String(report.threat_score) + "/100";
            if (typeBadgeEl) typeBadgeEl.textContent = report.type;
            if (cacheBadgeEl) {
                cacheBadgeEl.textContent = isCached ? "REDIS CACHE HIT" : "LIVE TELEMETRY";
            }
            if (riskBadgeEl) {
                riskBadgeEl.textContent = analytics.riskLevel + " RISK";
                riskBadgeEl.className =
                    "text-xs font-bold uppercase px-2.5 py-1 rounded " +
                    DashboardComponents.getRiskBadgeStyle(analytics.riskLevel);
            }
            if (breakdownEl) {
                breakdownEl.innerHTML = DashboardComponents.renderPillars(analytics.pillars);
            }
            if (summaryCardsEl) {
                summaryCardsEl.innerHTML = DashboardComponents.renderSourceCards(report.results, analytics);
            }
            if (jsonResultEl) {
                jsonResultEl.textContent = JSON.stringify(report, null, 2);
            }
            this.resultAreaEl.classList.remove("hidden");
        }
        async loadHistory() {
            try {
                const response = await fetch("/api/history?limit=30");
                if (!response.ok) return;
                const payload = await response.json();
                if (payload.status === "success") {
                    this.cachedHistory = payload.data;
                    this.renderFilteredHistory();
                }
            } catch {
                this.historyAreaEl.innerHTML =
                    '<p class="text-xs text-rose-400 text-center py-4">Failed to load audit history.</p>';
            }
        }
        renderFilteredHistory() {
            const selectedCategory = this.historyFilterEl.value || "ALL";
            const searchQuery = this.historySearchEl.value.trim().toLowerCase();
            const filtered = this.cachedHistory.filter((item) => {
                const matchesType = selectedCategory === "ALL" || item.type === selectedCategory;
                const matchesSearch = !searchQuery || item.target.toLowerCase().includes(searchQuery);
                return matchesType && matchesSearch;
            });
            this.historyAreaEl.innerHTML = DashboardComponents.renderHistoryItems(filtered);
            const rowElements = this.historyAreaEl.querySelectorAll(".history-item");
            rowElements.forEach((row) => {
                row.addEventListener("click", async () => {
                    const targetToRescan = row.getAttribute("data-rescan") || "";
                    if (targetToRescan) {
                        this.targetInputEl.value = targetToRescan;
                        this.handleLiveValidation();
                        window.scrollTo({ top: 0, behavior: "smooth" });
                        await this.executeAnalysis();
                    }
                });
            });
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const app = new OSINTDashboardApp();
        void app.init();
    });
})();