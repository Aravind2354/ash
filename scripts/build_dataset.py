"""
Dataset Builder Script for Website Authenticity & Phishing Detection.

Generates comprehensive, leak-free, representative training datasets:
- data/legitimate.csv
- data/phishing.csv
- data/dataset.csv

All samples are encoded using the 48 canonical numerical features from FeatureExtractor.
"""

import os
import random
from typing import Tuple, Dict, List, Optional, Any
import numpy as np
import pandas as pd

from src.feature_extractor import FEATURE_NAMES


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def generate_legitimate_samples(n_samples: int = 2500, seed: int = 42) -> pd.DataFrame:
    """Generate representative legitimate website feature rows."""
    rng = np.random.RandomState(seed)
    rows = []

    for i in range(n_samples):
        # Category of legitimate site
        site_type = rng.choice(["tech_brand", "ecommerce", "banking", "content_blog", "edu_gov", "saas_app"])

        # Domain/URL
        url_len = float(rng.randint(18, 55))
        is_https = 1.0 if rng.rand() < 0.98 else 0.0
        subdomains = float(rng.choice([0, 1, 1, 2], p=[0.4, 0.4, 0.15, 0.05]))
        has_ip = 0.0
        hyphens = float(rng.choice([0, 0, 1, 2], p=[0.6, 0.25, 0.1, 0.05]))
        dots = float(subdomains + 1.0)
        suspicious_tld = 0.0
        domain_len = float(rng.randint(7, 22))
        longest_num = float(rng.choice([0, 0, 1, 2], p=[0.8, 0.1, 0.08, 0.02]))
        num_ratio = (longest_num / domain_len) if domain_len > 0 else 0.0
        entropy = float(rng.uniform(2.1, 3.4))
        punycode = 0.0
        suspicious_kw = float(rng.choice([0, 0, 1], p=[0.85, 0.1, 0.05]))
        path_len = float(rng.randint(0, 35))
        query_len = float(rng.choice([0, 0, 5, 20], p=[0.6, 0.2, 0.15, 0.05]))
        non_std_port = 0.0

        # Brand
        if site_type in ["tech_brand", "ecommerce", "banking"]:
            brand_det = float(rng.choice([0.0, 1.0], p=[0.2, 0.8]))
            brand_match = 1.0 if brand_det > 0 else 0.0
            brand_mismatch = 0.0
        else:
            brand_det = 0.0
            brand_match = 0.0
            brand_mismatch = 0.0

        # SSL
        ssl_valid = 1.0 if is_https > 0 and rng.rand() < 0.99 else (1.0 if is_https > 0 else 0.0)
        ssl_expired = 0.0 if ssl_valid > 0 else (1.0 if rng.rand() < 0.02 else 0.0)
        ssl_self_signed = 0.0
        ssl_rec_ca = 1.0 if ssl_valid > 0 and rng.rand() < 0.98 else 0.0

        # DOM
        elements = float(rng.randint(80, 2500))
        forms = float(rng.choice([0, 1, 2, 3], p=[0.3, 0.45, 0.2, 0.05]))
        if site_type in ["banking", "tech_brand"] and forms > 0 and rng.rand() < 0.6:
            pwd_c = 1.0
            email_c = float(rng.choice([0, 1]))
            login_kw = float(rng.randint(1, 4))
        else:
            pwd_c = 0.0
            email_c = 0.0
            login_kw = float(rng.choice([0, 1], p=[0.8, 0.2]))

        card_c = 1.0 if site_type == "ecommerce" and forms > 0 and rng.rand() < 0.25 else 0.0
        otp_c = 1.0 if site_type == "banking" and forms > 0 and rng.rand() < 0.20 else 0.0
        hidden_c = float(rng.randint(0, 4))
        iframes = float(rng.choice([0, 1, 2], p=[0.7, 0.25, 0.05]))
        scripts = float(rng.randint(2, 30))
        ext_action = float(rng.choice([0, 1], p=[0.92, 0.08]))
        cross_action = 0.0  # Legitimate sites do not exfiltrate to foreign third parties
        has_cred_form = 1.0 if (pwd_c > 0 or email_c > 0 or card_c > 0 or otp_c > 0) else 0.0

        # Network
        req_c = float(rng.randint(15, 120))
        https_ratio = float(rng.uniform(0.92, 1.0)) if is_https > 0 else float(rng.uniform(0.1, 0.5))
        u_domains = float(rng.randint(1, 15))
        ext_domains = float(min(u_domains - 1, rng.randint(0, 10)))

        # JS
        js_scripts = scripts
        js_dom_mods = float(rng.randint(5, 500))
        js_api_calls = float(rng.randint(0, 20))

        # Visual
        has_screenshot = 1.0
        vp_w = 1920.0 if rng.rand() < 0.7 else 1280.0
        vp_h = 1080.0 if vp_w == 1920.0 else 800.0
        img_c = float(rng.randint(2, 45))

        # Threat intelligence
        threat_flag = 0.0

        row = {
            "url_length": url_len,
            "is_https": is_https,
            "subdomain_count": subdomains,
            "has_ip_address": has_ip,
            "hyphen_count": hyphens,
            "dot_count": dots,
            "is_suspicious_tld": suspicious_tld,
            "domain_length": domain_len,
            "longest_numeric_sequence": longest_num,
            "numeric_ratio": num_ratio,
            "domain_entropy": entropy,
            "is_punycode": punycode,
            "suspicious_keyword_count": suspicious_kw,
            "path_length": path_len,
            "query_length": query_len,
            "non_standard_port": non_std_port,
            "brand_detected": brand_det,
            "brand_domain_match": brand_match,
            "brand_domain_mismatch": brand_mismatch,
            "ssl_chain_valid": ssl_valid,
            "ssl_expired": ssl_expired,
            "ssl_self_signed": ssl_self_signed,
            "ssl_recognized_ca": ssl_rec_ca,
            "dom_element_count": elements,
            "dom_form_count": forms,
            "dom_iframe_count": iframes,
            "dom_script_count": scripts,
            "password_input_count": pwd_c,
            "email_input_count": email_c,
            "card_input_count": card_c,
            "otp_input_count": otp_c,
            "hidden_input_count": hidden_c,
            "login_keyword_count": login_kw,
            "external_form_action_count": ext_action,
            "cross_domain_form_action_count": cross_action,
            "has_credential_harvesting_form": has_cred_form,
            "network_request_count": req_c,
            "network_https_ratio": https_ratio,
            "network_unique_domains_count": u_domains,
            "network_external_domains_count": ext_domains,
            "js_script_count": js_scripts,
            "js_dom_modifications": js_dom_mods,
            "js_external_api_calls": js_api_calls,
            "has_screenshot": has_screenshot,
            "viewport_width": vp_w,
            "viewport_height": vp_h,
            "image_count": img_c,
            "threat_intelligence_flag": threat_flag,
            "is_phishing": 0,
        }
        rows.append(row)

    return pd.DataFrame(rows)


def generate_phishing_samples(n_samples: int = 2500, seed: int = 43) -> pd.DataFrame:
    """Generate representative phishing attack pattern feature rows."""
    rng = np.random.RandomState(seed)
    rows = []

    for i in range(n_samples):
        # Specific phishing attack scenario
        attack_type = rng.choice([
            "brand_subdomain_mismatch",   # e.g. allegro.oferta7678678564.pl
            "brand_hyphen_impersonation", # e.g. paypal-login-verify.com
            "credential_harvester_generic",
            "cross_domain_exfiltration",
            "suspicious_tld_random_dga",
            "numeric_heavy_hostname",
            "punycode_homograph",
            "raw_ip_credential_scam",
            "payment_otp_harvesting",
            "hidden_fields_deception",
        ])

        # Domain/URL
        url_len = float(rng.randint(35, 95))
        is_https = 1.0 if rng.rand() < 0.75 else 0.0  # Many phishing sites now use valid HTTPS!
        
        if attack_type == "brand_subdomain_mismatch":
            subdomains = float(rng.choice([1, 2, 3]))
            has_ip = 0.0
            hyphens = float(rng.randint(0, 3))
            longest_num = float(rng.choice([0, 5, 8, 10, 12], p=[0.2, 0.15, 0.25, 0.25, 0.15]))
            domain_len = float(rng.randint(12, 28))
            num_ratio = (longest_num / domain_len) if domain_len > 0 else 0.0
            entropy = float(rng.uniform(2.9, 3.8))
            suspicious_tld = float(rng.choice([0, 1], p=[0.6, 0.4]))
            punycode = 0.0
            brand_det = 1.0
            brand_match = 0.0
            brand_mismatch = 1.0
        elif attack_type == "numeric_heavy_hostname":
            subdomains = float(rng.choice([0, 1, 2]))
            has_ip = 0.0
            longest_num = float(rng.randint(6, 15))
            domain_len = float(rng.randint(14, 30))
            num_ratio = float(rng.uniform(0.35, 0.75))
            entropy = float(rng.uniform(3.2, 4.2))
            hyphens = float(rng.randint(1, 4))
            suspicious_tld = float(rng.choice([0, 1], p=[0.4, 0.6]))
            punycode = 0.0
            brand_det = float(rng.choice([0, 1], p=[0.5, 0.5]))
            brand_match = 0.0
            brand_mismatch = brand_det
        elif attack_type == "raw_ip_credential_scam":
            subdomains = 0.0
            has_ip = 1.0
            longest_num = 3.0
            domain_len = 15.0
            num_ratio = float(rng.uniform(0.6, 0.8))
            entropy = float(rng.uniform(2.5, 3.1))
            hyphens = 0.0
            suspicious_tld = 0.0
            punycode = 0.0
            brand_det = float(rng.choice([0, 1], p=[0.6, 0.4]))
            brand_match = 0.0
            brand_mismatch = brand_det
        elif attack_type == "punycode_homograph":
            subdomains = float(rng.choice([0, 1]))
            has_ip = 0.0
            longest_num = 0.0
            domain_len = float(rng.randint(12, 22))
            num_ratio = 0.0
            entropy = float(rng.uniform(3.1, 3.9))
            hyphens = float(rng.randint(1, 3))
            suspicious_tld = 0.0
            punycode = 1.0
            brand_det = 1.0
            brand_match = 0.0
            brand_mismatch = 1.0
        else:
            subdomains = float(rng.choice([0, 1, 2, 3], p=[0.2, 0.4, 0.3, 0.1]))
            has_ip = 0.0
            longest_num = float(rng.choice([0, 2, 5, 8], p=[0.3, 0.3, 0.25, 0.15]))
            domain_len = float(rng.randint(10, 26))
            num_ratio = (longest_num / domain_len) if domain_len > 0 else 0.0
            entropy = float(rng.uniform(2.8, 3.9))
            hyphens = float(rng.randint(1, 5))
            suspicious_tld = float(rng.choice([0, 1], p=[0.5, 0.5]))
            punycode = 0.0
            brand_det = float(rng.choice([0, 1], p=[0.35, 0.65]))
            brand_match = 0.0
            brand_mismatch = brand_det

        dots = float(subdomains + 1.0)
        suspicious_kw = float(rng.choice([0, 0, 1, 2, 3], p=[0.35, 0.20, 0.25, 0.15, 0.05]))
        path_len = float(rng.randint(5, 60))
        query_len = float(rng.randint(0, 45))
        non_std_port = float(rng.choice([0, 1], p=[0.88, 0.12]))

        # SSL: Phishing sites commonly have Let's Encrypt / Cloudflare SSL or no SSL
        if is_https > 0:
            ssl_valid = 1.0 if rng.rand() < 0.85 else 0.0
            ssl_expired = 1.0 if ssl_valid == 0 and rng.rand() < 0.4 else 0.0
            ssl_self_signed = 1.0 if (ssl_valid == 0 and rng.rand() < 0.5) else 0.0
            ssl_rec_ca = 1.0 if (ssl_valid > 0 and not ssl_self_signed) else 0.0
        else:
            ssl_valid = 0.0
            ssl_expired = 0.0
            ssl_self_signed = 0.0
            ssl_rec_ca = 0.0

        # DOM & Form Credential Harvesting
        elements = float(rng.randint(15, 350))
        forms = float(rng.choice([1, 1, 2], p=[0.7, 0.2, 0.1]))
        
        if attack_type == "payment_otp_harvesting":
            pwd_c = float(rng.choice([0, 1]))
            email_c = float(rng.choice([0, 1]))
            card_c = float(rng.choice([1, 2]))
            otp_c = float(rng.choice([1, 2]))
            login_kw = float(rng.randint(2, 6))
        elif attack_type in ["brand_subdomain_mismatch", "brand_hyphen_impersonation", "credential_harvester_generic"]:
            pwd_c = 1.0
            email_c = float(rng.choice([1, 1, 0], p=[0.7, 0.2, 0.1]))
            card_c = float(rng.choice([0, 1], p=[0.8, 0.2]))
            otp_c = float(rng.choice([0, 1], p=[0.8, 0.2]))
            login_kw = float(rng.randint(1, 5))
        else:
            pwd_c = float(rng.choice([0, 1], p=[0.4, 0.6]))
            email_c = float(rng.choice([0, 1], p=[0.4, 0.6]))
            card_c = float(rng.choice([0, 1], p=[0.85, 0.15]))
            otp_c = float(rng.choice([0, 1], p=[0.85, 0.15]))
            login_kw = float(rng.randint(1, 4))

        if attack_type == "hidden_fields_deception":
            hidden_c = float(rng.randint(6, 16))
        else:
            hidden_c = float(rng.randint(0, 5))

        iframes = float(rng.choice([0, 1, 6], p=[0.6, 0.3, 0.1]))
        scripts = float(rng.randint(1, 12))

        if attack_type == "cross_domain_exfiltration":
            ext_action = 1.0
            cross_action = 1.0
        else:
            ext_action = float(rng.choice([0, 1], p=[0.6, 0.4]))
            cross_action = float(rng.choice([0, 1], p=[0.65, 0.35]))

        has_cred_form = 1.0 if (pwd_c > 0 or email_c > 0 or card_c > 0 or otp_c > 0) else 0.0

        # Network
        req_c = float(rng.randint(5, 45))
        https_ratio = float(rng.uniform(0.6, 1.0)) if is_https > 0 else float(rng.uniform(0.0, 0.3))
        u_domains = float(rng.randint(1, 8))
        ext_domains = float(rng.randint(1, 6))

        # JS
        js_scripts = scripts
        js_dom_mods = float(rng.randint(0, 120))
        js_api_calls = float(rng.randint(0, 15))

        # Visual
        has_screenshot = 1.0 if rng.rand() < 0.95 else 0.0
        vp_w = 1280.0
        vp_h = 800.0
        img_c = float(rng.randint(0, 15))

        # Threat intelligence
        threat_flag = float(rng.choice([0, 1], p=[0.85, 0.15]))

        row = {
            "url_length": url_len,
            "is_https": is_https,
            "subdomain_count": subdomains,
            "has_ip_address": has_ip,
            "hyphen_count": hyphens,
            "dot_count": dots,
            "is_suspicious_tld": suspicious_tld,
            "domain_length": domain_len,
            "longest_numeric_sequence": longest_num,
            "numeric_ratio": num_ratio,
            "domain_entropy": entropy,
            "is_punycode": punycode,
            "suspicious_keyword_count": suspicious_kw,
            "path_length": path_len,
            "query_length": query_len,
            "non_standard_port": non_std_port,
            "brand_detected": brand_det,
            "brand_domain_match": brand_match,
            "brand_domain_mismatch": brand_mismatch,
            "ssl_chain_valid": ssl_valid,
            "ssl_expired": ssl_expired,
            "ssl_self_signed": ssl_self_signed,
            "ssl_recognized_ca": ssl_rec_ca,
            "dom_element_count": elements,
            "dom_form_count": forms,
            "dom_iframe_count": iframes,
            "dom_script_count": scripts,
            "password_input_count": pwd_c,
            "email_input_count": email_c,
            "card_input_count": card_c,
            "otp_input_count": otp_c,
            "hidden_input_count": hidden_c,
            "login_keyword_count": login_kw,
            "external_form_action_count": ext_action,
            "cross_domain_form_action_count": cross_action,
            "has_credential_harvesting_form": has_cred_form,
            "network_request_count": req_c,
            "network_https_ratio": https_ratio,
            "network_unique_domains_count": u_domains,
            "network_external_domains_count": ext_domains,
            "js_script_count": js_scripts,
            "js_dom_modifications": js_dom_mods,
            "js_external_api_calls": js_api_calls,
            "has_screenshot": has_screenshot,
            "viewport_width": vp_w,
            "viewport_height": vp_h,
            "image_count": img_c,
            "threat_intelligence_flag": threat_flag,
            "is_phishing": 1,
        }
        rows.append(row)

    return pd.DataFrame(rows)


def build_and_save_datasets(n_each: int = 3000, seed: int = 42) -> Tuple[str, str, str]:
    """Build legitimate, phishing, and combined datasets and save to data/ directory."""
    os.makedirs(DATA_DIR, exist_ok=True)

    print(f"Generating {n_each} legitimate website samples...")
    df_legit = generate_legitimate_samples(n_samples=n_each, seed=seed)
    legit_path = os.path.join(DATA_DIR, "legitimate.csv")
    df_legit.to_csv(legit_path, index=False)
    print(f"Saved legitimate dataset to {legit_path} ({len(df_legit)} rows)")

    print(f"Generating {n_each} phishing website samples...")
    df_phish = generate_phishing_samples(n_samples=n_each, seed=seed + 1)
    phish_path = os.path.join(DATA_DIR, "phishing.csv")
    df_phish.to_csv(phish_path, index=False)
    print(f"Saved phishing dataset to {phish_path} ({len(df_phish)} rows)")

    print("Combining and shuffling dataset...")
    df_all = pd.concat([df_legit, df_phish], ignore_index=True)
    df_all = df_all.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    dataset_path = os.path.join(DATA_DIR, "dataset.csv")
    df_all.to_csv(dataset_path, index=False)
    print(f"Saved full combined dataset to {dataset_path} ({len(df_all)} total rows)")

    # Validate feature consistency
    expected_cols = FEATURE_NAMES + ["is_phishing"]
    assert list(df_all.columns) == expected_cols, f"Column mismatch in generated dataset: {list(df_all.columns)}"

    return legit_path, phish_path, dataset_path


if __name__ == "__main__":
    build_and_save_datasets()
