# Cyber Threat Intelligence (CTI) Architecture — UPI Fraud Guard

This document describes the implemented end-to-end CTI architecture in `upi-fraud-guard-v3`.

```mermaid
flowchart TD
    subgraph Ingestion["1. Secure Ingestion & Adapters"]
        Sources["Registered Sources\n(CERT-In, NPCI, RBI, PhishTank,\nURLhaus, OpenPhish, CISA, MITRE, AbuseIPDB, OTX)"]
        SecFetch["cti_security.fetch_secure_content()\n• Pinned-IP Resolution\n• 5 MiB Stream Limit\n• Allowlist Validation\n• Credential Stripping on Redirect"]
        Sources --> SecFetch
    end

    subgraph Processing["2. Extraction, Normalization & Validation"]
        Extractor["cti_extraction.IntelligenceExtractor\n• URL/Domain/IP/Hash/Email/VPA Regex\n• Scam Pattern Keywords"]
        Normalizer["cti_normalization.IntelligenceNormalizer\n• Canonicalization (Host, Path, Syntax)\n• Allowlist Check\n• Confidence & Expiration Calculation"]
        SecFetch --> Extractor
        Extractor --> Normalizer
    end

    subgraph Storage["3. Persistence & Database"]
        DB[("SQLite: data/risk_checks.db\n• cti_sources\n• cti_indicators\n• cti_collection_logs\n• cti_indicator_reviews\n• cti_indicator_quarantine")]
        Normalizer --> DB
    end

    subgraph Matching["4. Trust & Matching Engine"]
        Matcher["cti_matcher.CTIMatcher\n• Filter: Verified Malicious ONLY\n• Check: Quarantined=0 & Unexpired\n• Cache Invalidation on Analyst Review"]
        DB --> Matcher
    end

    subgraph Engine["5. Multimodal Risk Fusion"]
        MsgMod["nlp_module & multilingual_rules\n(EN, HI, MR, Hinglish)"]
        UrlMod["url_qr_module\n(URL ML + UPI QR Parser)"]
        TxnMod["transaction_module\n(RandomForest + Rules)"]
        Fusion["risk_fusion.fuse()\n• Dynamic Signal Weighting\n• CTI Evidence Boost\n• 0-100 Score & Action Recommendation"]
        
        Matcher -->|Pattern Match| MsgMod
        Matcher -->|URL/Domain/VPA Match| UrlMod
        Matcher -->|Recipient VPA Match| TxnMod
        
        MsgMod --> Fusion
        UrlMod --> Fusion
        TxnMod --> Fusion
    end
```

## Key Architectural Principles

1. **No Fake / Static Fallback IOCs**: Connectors never substitute hardcoded sample IOCs when network calls fail or credentials are missing. A failed fetch logs an error and updates source status without inserting fabricated records.
2. **Pinned-IP and Stream-Bounded Fetching**: All outbound HTTP traffic validates destination hostnames against an allowlist, resolves addresses once to check for private/loopback/cloud-metadata IPs, and pins the socket directly to that IP. Response bodies are streamed with a hard limit of 5 MiB.
3. **Explicit Verification Gate**: IOC matching in pre-transaction risk scoring strictly requires `Verified Malicious` status, active lifespan (`expires_at > now`), and non-quarantined status. Confidence score alone is insufficient to trigger high-risk alerts.
4. **Cache Invalidation**: Any manual analyst status review through `/api/intelligence/indicators/{id}/review` invalidates the matcher's indicator cache immediately.
5. **Preserved Multilingual Detection**: CTI message pattern checks complement the existing English, Hindi, and Marathi NLP models and regex rules without replacing them.
