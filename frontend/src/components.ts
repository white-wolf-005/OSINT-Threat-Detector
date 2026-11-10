import {
    CorrelatedAnalytics,
    CveDescriptor,
    HibpBreachRecord,
    HistoryRecordItem,
    IpApiTelemetry,
    OtxTelemetry,
    PillarBreakdown,
    PortRiskProfile,
    RiskLevel,
    ShodanIdbTelemetry,
    SourceResultItem,
} from "./types.js";

export class DashboardComponents {
    public static escapeHtml(unsafe: string): string {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    public static getRiskBadgeStyle(risk: RiskLevel): string {
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

    public static renderPillars(pillars: PillarBreakdown[]): string {
        return pillars
            .map((pillar: PillarBreakdown): string => {
                const findingsHtml: string = pillar.findings
                    .map((f: string): string => {
                        return (
                            '<li class="text-xs text-slate-300 flex items-start gap-1.5">' +
                            '<span class="text-indigo-400">▸</span>' +
                            "<span>" +
                            DashboardComponents.escapeHtml(f) +
                            "</span></li>"
                        );
                    })
                    .join("");

                const badgeClass: string =
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

    public static renderSourceCards(results: SourceResultItem[], analytics: CorrelatedAnalytics): string {
        return results
            .map((res: SourceResultItem): string => {
                const title: string = DashboardComponents.escapeHtml(res.source);

                if (res.error || !res.data) {
                    const errText: string = DashboardComponents.escapeHtml(res.error || "No data returned");
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
                    const ipData: IpApiTelemetry = res.data as IpApiTelemetry;
                    const flags: string[] = [];
                    if (ipData.proxy) flags.push("Proxy/VPN");
                    if (ipData.hosting) flags.push("Hosting/DC");
                    if (ipData.mobile) flags.push("Mobile ISP");
                    const flagText: string = flags.length > 0 ? flags.join(", ") : "Standard Residential/Enterprise";

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
                    const shodan: ShodanIdbTelemetry = res.data as ShodanIdbTelemetry;
                    const portBadges: string =
                        analytics.portProfiles.length > 0
                            ? analytics.portProfiles
                                  .map((p: PortRiskProfile): string => {
                                      const color: string =
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

                    const cveBadges: string =
                        analytics.cveDescriptors.length > 0
                            ? analytics.cveDescriptors
                                  .slice(0, 8)
                                  .map((c: CveDescriptor): string => {
                                      return (
                                          '<span class="inline-block text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950/90 text-rose-200 border border-rose-800">' +
                                          DashboardComponents.escapeHtml(c.cveId) +
                                          "</span>"
                                      );
                                  })
                                  .join(" ")
                            : '<span class="text-xs text-emerald-400">Zero known CVEs</span>';

                    const hostnames: string =
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
                    const otx: OtxTelemetry = res.data as OtxTelemetry;
                    const pulseList: string =
                        otx.recent_pulses && otx.recent_pulses.length > 0
                            ? otx.recent_pulses
                                  .map((name: string): string => {
                                      return (
                                          '<li class="text-xs text-rose-300 truncate">• ' +
                                          DashboardComponents.escapeHtml(name) +
                                          "</li>"
                                      );
                                  })
                                  .join("")
                            : '<li class="text-xs text-emerald-400">No active threat pulses linked to indicator</li>';

                    const otxBadgeStyle: string =
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
                    const breaches: HibpBreachRecord[] = res.data as HibpBreachRecord[];
                    const breachItems: string =
                        breaches.length > 0
                            ? breaches
                                  .slice(0, 6)
                                  .map((b: HibpBreachRecord): string => {
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

                    const hibpBadgeStyle: string =
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

    public static renderHistoryItems(records: HistoryRecordItem[]): string {
        if (records.length === 0) {
            return '<p class="text-xs text-slate-500 text-center py-6">No matching reconnaissance records in audit history.</p>';
        }

        return records
            .map((item: HistoryRecordItem): string => {
                const parsedDate: Date = new Date(item.created_at);
                const formattedDate: string = parsedDate.toLocaleString("en-US", {
                    month: "short",
                    day: "2-digit",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                    hour12: false,
                });

                const scoreBadge: string =
                    item.threat_score >= 45
                        ? "bg-rose-950 text-rose-300 border-rose-800"
                        : item.threat_score >= 20
                        ? "bg-amber-950 text-amber-300 border-amber-800"
                        : "bg-emerald-950 text-emerald-300 border-emerald-800";

                const safeTarget: string = DashboardComponents.escapeHtml(item.target);

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