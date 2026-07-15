#!/usr/bin/env python3
"""
Scene 10: HTTP Probing & Encoding Resilience
Extracts HTTP client design, encoding detection, and dual-protocol support.
"""
import json
import re
import csv
from pathlib import Path
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE = Path("/Users/elwood/Desktop/test/original/AI-Infra-Guard")
HTTPX_DIR = BASE / "pkg" / "httpx"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_http_client():
    """Analyze HTTP client architecture"""
    httpx_text = (HTTPX_DIR / "httpx.go").read_text()
    options_text = (HTTPX_DIR / "options.go").read_text()
    response_text = (HTTPX_DIR / "response.go").read_text()

    # HTTP methods
    methods = re.findall(r'func \(h \*HTTPX\) (\w+)\(', httpx_text)

    # HTTP/2 support
    has_http2 = "http2" in httpx_text

    # Redirect handling
    has_redirect_control = "FollowRedirects" in httpx_text
    uses_err_use_last_response = "ErrUseLastResponse" in httpx_text

    # Unsafe mode (rawhttp)
    has_unsafe_mode = "doUnsafe" in httpx_text
    uses_rawhttp = "rawhttp" in httpx_text

    # TLS config
    tls_skip_verify = "InsecureSkipVerify" in httpx_text

    # Retry support
    uses_retryablehttp = "retryablehttp" in httpx_text
    retry_max_found = re.search(r'RetryMax', httpx_text)

    # Proxy support
    has_proxy = "HTTPProxy" in httpx_text

    # Custom headers
    has_custom_headers = "CustomHeaders" in httpx_text

    # Connection settings
    disable_keepalive = "DisableKeepAlives" in httpx_text
    max_idle = re.search(r'MaxIdleConnsPerHost:\s*(\S+)', httpx_text)

    return {
        "http_methods": methods,
        "http2_support": has_http2,
        "redirect_control": has_redirect_control,
        "uses_err_use_last_response": uses_err_use_last_response,
        "unsafe_raw_mode": has_unsafe_mode,
        "uses_rawhttp": uses_rawhttp,
        "tls_skip_verify": tls_skip_verify,
        "retryable_http": uses_retryablehttp,
        "proxy_support": has_proxy,
        "custom_headers": has_custom_headers,
        "disable_keepalive": disable_keepalive,
        "max_idle_conns_per_host": max_idle.group(1) if max_idle else "default",
    }


def analyze_encoding():
    """Analyze encoding detection and conversion"""
    encodings_text = (HTTPX_DIR / "encodings.go").read_text()
    httpx_text = (HTTPX_DIR / "httpx.go").read_text()

    # Supported encodings
    encoding_funcs = re.findall(r'func (Decode|Encode)(\w+)\(', encodings_text)

    # Encoding detection patterns in httpx.go
    detection_patterns = re.findall(r'charset[=\'"]?(\w+)', httpx_text, re.IGNORECASE)

    # Meta charset detection
    meta_charset_regex = re.findall(r'regexp\.MustCompile\("([^"]+)"\)', httpx_text)

    return {
        "encoding_functions": [f"{d}{e}" for d, e in encoding_funcs],
        "detected_charsets": list(set(detection_patterns)),
        "meta_charset_patterns": meta_charset_regex,
        "goto_used": "goto" in httpx_text,
    }


def analyze_title_extraction():
    """Analyze HTML title extraction"""
    title_text = (HTTPX_DIR / "title.go").read_text()

    # Title regex patterns
    title_patterns = re.findall(r'regexp\.MustCompile\(`([^`]+)`\)', title_text)

    # Functions
    funcs = re.findall(r'func (\w+)\(', title_text)

    return {
        "functions": funcs,
        "regex_patterns": title_patterns,
    }


def analyze_user_agents():
    """Analyze User-Agent rotation"""
    ua_text = (HTTPX_DIR / "user-agent.go").read_text()
    ua_list = re.findall(r'"([^"]+)"', ua_text)
    ua_list = [u for u in ua_list if any(b in u for b in ['Mozilla', 'Chrome', 'Safari', 'Firefox', 'curl'])]
    return {
        "user_agent_count": len(ua_list),
        "user_agents": ua_list[:5],  # sample
    }


def make_charts(http_info, encoding_info, title_info, ua_info, outfile):
    """Generate HTTP probing chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Feature matrix
    features = [
        ('HTTP/1.1', True),
        ('HTTP/2', http_info["http2_support"]),
        ('TLS Skip\nVerify', http_info["tls_skip_verify"]),
        ('Retry\nMechanism', http_info["retryable_http"]),
        ('Redirect\nControl', http_info["redirect_control"]),
        ('Raw HTTP\n(Unsafe)', http_info["unsafe_raw_mode"]),
        ('Proxy\nSupport', http_info["proxy_support"]),
        ('Custom\nHeaders', http_info["custom_headers"]),
        ('Disable\nKeepAlive', http_info["disable_keepalive"]),
    ]
    labels = [f[0] for f in features]
    values = [1 if f[1] else 0 for f in features]
    colors = ['#4ECDC4' if v else '#E0E0E0' for v in values]
    axes[0].barh(labels, values, color=colors)
    axes[0].set_title("HTTP Client Feature Matrix", fontsize=12, fontweight='bold')
    axes[0].set_xlabel("Supported (1) / Not (0)")
    axes[0].set_xlim(0, 1.5)

    # Encoding detection coverage
    encoding_labels = ['GBK\nDecode', 'BIG5\nDecode', 'BIG5\nEncode', 'Meta\nCharset\nDetection', 'Content-Type\nCharset\nDetection']
    encoding_values = [
        1 if 'Decodegbk' in encoding_info["encoding_functions"] else 0,
        1 if 'Decodebig5' in encoding_info["encoding_functions"] else 0,
        1 if 'Encodebig5' in encoding_info["encoding_functions"] else 0,
        1 if encoding_info["meta_charset_patterns"] else 0,
        1 if encoding_info["detected_charsets"] else 0,
    ]
    colors2 = ['#4ECDC4' if v else '#E0E0E0' for v in encoding_values]
    axes[1].bar(encoding_labels, encoding_values, color=colors2)
    axes[1].set_title("Encoding Resilience Coverage", fontsize=12, fontweight='bold')
    axes[1].set_ylabel("Supported (1) / Not (0)")
    axes[1].set_ylim(0, 1.5)
    plt.xticks(rotation=15, fontsize=9)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    http_info = analyze_http_client()
    encoding_info = analyze_encoding()
    title_info = analyze_title_extraction()
    ua_info = analyze_user_agents()

    data = {
        "http_client": http_info,
        "encoding": encoding_info,
        "title_extraction": title_info,
        "user_agents": ua_info,
    }

    with open(RESULTS / "http_probing.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "http_probing.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Feature", "Value"])
        for k, v in http_info.items():
            writer.writerow([k, v])

    make_charts(http_info, encoding_info, title_info, ua_info, RESULTS / "http_probing.png")
    print("Done: http_probing")


if __name__ == "__main__":
    main()
