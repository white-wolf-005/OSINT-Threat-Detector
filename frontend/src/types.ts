export type TargetCategory = "IPv4" | "domain" | "email" | "invalid";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type PortSeverity = "SAFE" | "MODERATE" | "HIGH" | "CRITICAL";

export type HistoryFilterCategory = "ALL" | "IPv4" | "domain" | "email";

export interface IpApiTelemetry {
    status: string;
    message?: string;
    country: string;
    countryCode: string;
    regionName: string;
    city: string;
    isp: string;
    org: string;
    as: string;
    asname: string;
    reverse: string;
    mobile: boolean;
    proxy: boolean;
    hosting: boolean;
    query: string;
}

export interface ShodanIdbTelemetry {
    ip: string;
    ports: number[];
    vulns: string[];
    hostnames: string[];
    cpes: string[];
    tags: string[];
}

export interface OtxTelemetry {
    pulses_found: number;
    reputation: number;
    recent_pulses: string[];
    country?: string | null;
    asn?: string | null;
}

export interface HibpBreachRecord {
    Name: string;
    Title: string;
    Domain: string;
    BreachDate: string;
    AddedDate?: string;
    PwnCount: number;
    DataClasses: string[];
    IsVerified: boolean;
}

export type SourceDataPayload =
    | IpApiTelemetry
    | ShodanIdbTelemetry
    | OtxTelemetry
    | HibpBreachRecord[]
    | null;

export interface SourceResultItem {
    source: string;
    data: SourceDataPayload;
    error: string | null;
}

export interface AnalysisReport {
    target: string;
    resolved_ip: string | null;
    type: TargetCategory;
    threat_score: number;
    risk_level: RiskLevel;
    sources_checked: number;
    results: SourceResultItem[];
}

export interface AnalyzeApiResponse {
    status: string;
    data: AnalysisReport;
    cached: boolean;
}

export interface HistoryRecordItem {
    id: number;
    target: string;
    type: TargetCategory;
    threat_score: number;
    created_at: string;
}

export interface HistoryApiResponse {
    status: string;
    data: HistoryRecordItem[];
}

export interface TelemetryStats {
    total_scans: number;
    average_threat_score: number;
    high_risk_detections: number;
}

export interface StatsApiResponse {
    status: string;
    data: TelemetryStats;
}

export interface HealthApiResponse {
    status: string;
    version: string;
    redis_connected: boolean;
}

export interface ValidationOutcome {
    isValid: boolean;
    normalizedTarget: string;
    detectedCategory: TargetCategory;
    isPrivateNetwork: boolean;
    wasDefanged: boolean;
    advisoryMessage: string;
}

export interface PortRiskProfile {
    port: number;
    service: string;
    protocol: "TCP" | "UDP" | "TCP/UDP";
    severity: PortSeverity;
    rationale: string;
}

export interface CveDescriptor {
    cveId: string;
    year: number;
    estimatedSeverity: "HIGH" | "CRITICAL" | "MODERATE";
}

export interface PillarBreakdown {
    title: string;
    scoreImpact: number;
    maxImpact: number;
    statusLabel: string;
    findings: string[];
}

export interface CorrelatedAnalytics {
    riskLevel: RiskLevel;
    portProfiles: PortRiskProfile[];
    cveDescriptors: CveDescriptor[];
    pillars: PillarBreakdown[];
    executiveSummary: string;
}