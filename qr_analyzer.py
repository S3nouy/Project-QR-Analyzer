import cv2
import numpy as np
import re
import os
import time
import base64
import json
import socket
import sys
import threading
from xml.sax.saxutils import escape as xml_escape

import requests
from datetime import datetime
from urllib.parse import urlparse
from pyzbar import pyzbar
from dotenv import load_dotenv
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# ==========================================
# URL DEFANGING UTILITY
# ==========================================
def defang_url(url):
    """Defang a URL (or any text that may contain one) so it can be displayed
    without being clickable. Handles the scheme wherever it appears in the
    string and regardless of case (BUG FIX: the original only defanged a
    scheme found at position 0, and its case-insensitive match was paired
    with a case-sensitive replace, so 'HTTPS://' or embedded links like
    'Scan: https://evil.com' slipped through un-defanged)."""
    if not url:
        return url

    def _defang_scheme(match):
        return re.sub('http', 'hxxp', match.group(0), flags=re.IGNORECASE)

    url = re.sub(r'https?://', _defang_scheme, url, flags=re.IGNORECASE)
    return url.replace('.', '[.]')

def defang_domain(domain):
    return domain.replace('.', '[.]') if domain else domain

def defang_ip(ip):
    return ip.replace('.', '[.]') if ip else ip

# ==========================================
# DNS RESOLVER
# ==========================================
class DNSResolver:
    @staticmethod
    def resolve_domain(domain):
        ips = []
        try:
            parsed = urlparse(f"http://{domain}" if not domain.startswith('http') else domain)
            hostname = parsed.netloc if parsed.netloc else domain
            hostname = hostname.split(':')[0]
            addr_info = socket.getaddrinfo(hostname, None)
            for info in addr_info:
                ip = info[4][0]
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return ips

# ==========================================
# RISK SCORING SYSTEM
# ==========================================
class RiskScorer:
    SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'bank', 'paypal', 'microsoft', 'office365',
                           'account', 'password', 'signin', 'authentication', 'wallet', 'crypto', 'bitcoin',
                           'free', 'winner', 'prize', 'urgent', 'confirm', 'suspend']
    URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'goo.gle', 'ow.ly', 'is.gd', 'buff.ly',
                       'bl.ink', 'short.io']

    def __init__(self):
        self.factors = {}
        self.score = 0

    def analyze(self, url, entities, vt_results):
        """BUG FIX: previously bailed out entirely (returning a 0 score with no
        factors) whenever `url` was falsy, which happened for every QR code
        that encoded plain text / WiFi / vCard data rather than a link. That
        also meant VirusTotal results for any extracted IPs/domains were
        silently dropped. Now, URL-shape checks only run when there's an
        actual URL, but VT results (which can exist even without a URL) are
        always factored in."""
        self.factors = {}
        self.score = 0

        if url:
            self._check_https(url)
            self._check_ip_in_url(url)
            self._check_url_shortener(url)
            self._check_suspicious_keywords(url)
            self._check_url_length(url)
        else:
            self.factors['url_analysis'] = {
                'risk': 0,
                'reason': 'No URL found in the QR payload; link-based checks were skipped.'
            }

        self._check_vt_results(vt_results)
        return min(self.score, 100), self.factors

    def _check_https(self, url):
        if not url.startswith('https://'):
            self.factors['https'] = {'risk': 15, 'reason': 'URL does not use HTTPS (insecure connection)'}
            self.score += 15
        else:
            self.factors['https'] = {'risk': 0, 'reason': 'URL uses HTTPS (secure connection)'}

    def _check_ip_in_url(self, url):
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            self.factors['ip_in_url'] = {'risk': 20, 'reason': 'URL contains IP address instead of domain name'}
            self.score += 20
        else:
            self.factors['ip_in_url'] = {'risk': 0, 'reason': 'URL uses domain name'}

    def _check_url_shortener(self, url):
        domain = urlparse(url).netloc.lower()
        for shortener in self.URL_SHORTENERS:
            if shortener in domain:
                self.factors['url_shortener'] = {'risk': 15, 'reason': f'URL uses shortener service ({shortener})'}
                self.score += 15
                return
        self.factors['url_shortener'] = {'risk': 0, 'reason': 'URL is not shortened'}

    def _check_suspicious_keywords(self, url):
        # BUG FIX: naive substring matching flagged unrelated URLs (e.g. 'free'
        # matched inside 'freelancer.com'). Word-boundary matching cuts down
        # on false positives while still catching e.g. 'free-prize' or
        # '/login'.
        url_lower = url.lower()
        found = [k for k in self.SUSPICIOUS_KEYWORDS if re.search(rf'\b{re.escape(k)}\b', url_lower)]
        if found:
            risk = min(len(found) * 5, 20)
            self.factors['keywords'] = {'risk': risk, 'reason': f'Suspicious keywords found: {", ".join(found)}'}
            self.score += risk
        else:
            self.factors['keywords'] = {'risk': 0, 'reason': 'No suspicious keywords detected'}

    def _check_url_length(self, url):
        length = len(url)
        if length > 200:
            self.factors['length'] = {'risk': 10, 'reason': f'URL is very long ({length} characters)'}
            self.score += 10
        elif length > 100:
            self.factors['length'] = {'risk': 5, 'reason': f'URL is moderately long ({length} characters)'}
            self.score += 5
        else:
            self.factors['length'] = {'risk': 0, 'reason': f'URL length is normal ({length} characters)'}

    def _check_vt_results(self, vt_results):
        if not vt_results or 'error' in vt_results:
            self.factors['virustotal'] = {'risk': 0, 'reason': 'VirusTotal analysis not available'}
            return
        total_malicious = sum(
            data.get('malicious_count', 0)
            for cat in ['urls', 'ips', 'domains'] if cat in vt_results
            for data in vt_results[cat].values() if isinstance(data, dict)
        )
        if total_malicious > 0:
            risk = min(total_malicious * 5, 20)
            self.factors['virustotal'] = {'risk': risk, 'reason': f'VirusTotal detected {total_malicious} malicious engines'}
            self.score += risk
        else:
            self.factors['virustotal'] = {'risk': 0, 'reason': 'VirusTotal reports clean'}

    def get_verdict(self):
        if self.score >= 70: return "CRITICAL", "#ff4444"
        elif self.score >= 50: return "HIGH RISK", "#ff8800"
        elif self.score >= 30: return "MEDIUM RISK", "#ffaa00"
        elif self.score >= 10: return "LOW RISK", "#88cc00"
        else: return "SAFE", "#00cc44"

# ==========================================
# HISTORY & REPORT MANAGERS
# ==========================================
class HistoryManager:
    def __init__(self, history_file='history.json'):
        self.history_file = history_file
        self.history = self._load_history()

    def _load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_history(self):
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)

    def add_entry(self, entry):
        self.history.insert(0, entry)
        self._save_history()

    def get_history(self):
        return self.history

class ReportGenerator:
    def __init__(self, reports_dir='reports'):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    def get_recommendations(self, data):
        recs = []
        factors = data.get('risk_factors', {})

        if data.get('visual_status') in ['COVERED/DAMAGED', 'SUSPICIOUS']:
            recs.append("• 🚨 PHYSICAL SECURITY (QUISHING): Physical tampering detected. The QR code shows signs of a sticker overlay or visual break. DO NOT SCAN OR VISIT THE URL. Report to physical security.")
        if factors.get('https', {}).get('risk', 0) > 0:
            recs.append("• CONNECTION SECURITY: The URL does not use HTTPS. Avoid entering any sensitive information.")
        if factors.get('ip_in_url', {}).get('risk', 0) > 0:
            recs.append("• URL STRUCTURE: The URL uses a raw IP address. This is highly unusual and often indicates phishing.")
        if factors.get('url_shortener', {}).get('risk', 0) > 0:
            recs.append("• URL OBSCURATION: The link is shortened. Use a URL expander service to reveal the final destination.")
        if factors.get('keywords', {}).get('risk', 0) > 0:
            recs.append("• PHISHING INDICATORS: The URL contains suspicious keywords (e.g., login, verify, secure). Be highly skeptical.")
        if factors.get('virustotal', {}).get('risk', 0) > 0:
            recs.append("• THREAT INTELLIGENCE: VirusTotal has flagged this entity as malicious. Block this domain immediately.")
        if data.get('risk_score', 0) >= 50 and data.get('visual_status') == 'LEGITIMATE':
            recs.append("• GENERAL ACTION: Due to the high digital risk score, it is strongly recommended to NOT visit this URL.")

        if not recs:
            recs.append("• No specific security recommendations. The QR code and URL appear safe based on current heuristics.")
        return recs

    @staticmethod
    def _safe(text):
        """BUG FIX: raw decoded QR content (including defanged versions of it)
        was being dropped straight into reportlab Paragraph objects, which
        parse a small XML-like markup language. Payloads containing a bare
        '<' (very plausible in arbitrary QR text/URLs) crash doc.build() with
        a ValueError ('parse ended with unclosed tags'), so every field that
        can contain QR-derived text is now XML-escaped before insertion."""
        return xml_escape(str(text))

    def generate_pdf(self, analysis_data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.reports_dir, f"qr_analysis_{timestamp}.pdf")
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1a1a1a'), spaceAfter=30, alignment=1)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#2c3e50'), spaceAfter=12, spaceBefore=12)
        rec_style = ParagraphStyle('RecStyle', parent=styles['Normal'], fontSize=10, leftIndent=10, spaceAfter=6)

        story.append(Paragraph("QR Code Security Analysis Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(f"<b>Analysis Date:</b> {self._safe(analysis_data['timestamp'])}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        tampering = analysis_data.get('tampering_detected', False)
        if tampering:
            story.append(Paragraph("<font color='#ff4444'><b>⚠️ PHYSICAL TAMPERING DETECTED — treat this code as malicious. Do not scan it with a phone; the findings below were extracted for investigation and reporting only.</b></font>", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))

        # The image couldn't be read, or was readable but PyZbar couldn't
        # decode any data from it — nothing further to report.
        if analysis_data.get('verdict') == 'ERROR' or analysis_data.get('raw_data') in (None, "UNREADABLE"):
            verdict_color = analysis_data.get('verdict_color', '#888888')
            story.append(Paragraph(f"<b>Verdict:</b> <font color='{verdict_color}'>{self._safe(analysis_data.get('verdict', 'UNKNOWN'))}</font>", heading_style))
            if analysis_data.get('visual_details'):
                story.append(Paragraph("Visual Analysis Details", heading_style))
                story.append(Paragraph(self._safe(analysis_data['visual_details']), styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(
                "The QR code could not be decoded, so no URL, IP, or domain data is available."
                if analysis_data.get('verdict') != 'ERROR' else
                "The image file itself could not be read.",
                styles['Normal']
            ))
            if tampering:
                story.append(Spacer(1, 0.3*inch))
                story.append(Paragraph("Security Recommendations", heading_style))
                for rec in self.get_recommendations(analysis_data):
                    story.append(Paragraph(rec, rec_style))
            doc.build(story)
            return filename

        # Full findings — always included once data was extracted, whether
        # or not tampering was also flagged.
        story.append(Paragraph(f"<b>Verdict:</b> <font color='{analysis_data['verdict_color']}'>{self._safe(analysis_data['verdict'])}</font>", heading_style))
        story.append(Paragraph(f"<b>Risk Score:</b> {analysis_data['risk_score']}/100", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Security Recommendations", heading_style))
        for rec in self.get_recommendations(analysis_data):
            story.append(Paragraph(rec, rec_style))
        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Decoded Data (DEFANGED)", heading_style))
        story.append(Paragraph(f"<font face='Courier' color='gray'>{self._safe(defang_url(analysis_data['raw_data']))}</font>", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))

        factors_data = [['Factor', 'Risk Points', 'Reason']]
        for factor, data in analysis_data['risk_factors'].items():
            factors_data.append([factor.replace('_', ' ').title(), str(data['risk']), self._safe(data['reason'])])

        factors_table = Table(factors_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        factors_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        story.append(factors_table)
        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Extracted Entities (DEFANGED)", heading_style))
        entities = analysis_data['entities']
        story.append(Paragraph(f"<b>URLs ({len(entities.get('urls', []))}):</b>", styles['Normal']))
        for url in entities.get('urls', []):
            story.append(Paragraph(f"• <font face='Courier' color='gray'>{self._safe(defang_url(url))}</font>", styles['Normal']))
        story.append(Paragraph(f"<b>IP Addresses ({len(entities.get('ips', []))}):</b>", styles['Normal']))
        for ip in entities.get('ips', []):
            story.append(Paragraph(f"• <font face='Courier' color='gray'>{self._safe(defang_ip(ip))}</font>", styles['Normal']))
        story.append(Paragraph(f"<b>Domains ({len(entities.get('domains', []))}):</b>", styles['Normal']))
        for domain in entities.get('domains', []):
            story.append(Paragraph(f"• <font face='Courier' color='gray'>{self._safe(defang_domain(domain))}</font>", styles['Normal']))

        doc.build(story)
        return filename

# ==========================================
# QR ANALYZER (Core Logic - 3-Step Method)
# ==========================================
class QRAnalyzer:
    def __init__(self, log_callback=None):
        self.log = log_callback or print
        self.dns_resolver = DNSResolver()
        if not VT_API_KEY:
            self.log("[WARNING] VirusTotal API key not found.")

    @staticmethod
    def _locate_qr_boundary(gray):
        """Find the QR code's true outer polygon.

        BUG FIX: the previous version ran Canny edge detection over the
        whole image and picked the largest 4-point contour it found. A QR
        code's outer edge is a jagged mix of black/white modules, not one
        continuous line, so that search almost never landed on the actual
        code — it typically locked onto a single finder pattern instead
        (the nested black/white/black corner squares, which *do* form a
        clean rectangle on their own). Every downstream check then ran on
        that tiny sub-region: the "quiet zone" ring sampled around a finder
        pattern lands back inside the code's own data modules — solid
        black — which the quiet-zone check reads as a tampering signature.
        That's why real, untampered QR codes were being flagged almost
        every time.

        cv2's dedicated QRCodeDetector uses the actual finder-pattern
        geometry QR codes are built around to return the code's real four
        corners, so it's used here instead.
        """
        detector = cv2.QRCodeDetector()
        ok, points = detector.detect(gray)
        if not ok or points is None:
            # The detector needs a handful of pixels per module to find the
            # finder-pattern ratio reliably; low-resolution or heavily
            # downscaled captures can miss on the first pass. One retry at
            # higher resolution recovers most of those cases.
            scale = 3
            big = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            ok, points = detector.detect(big)
            if ok and points is not None:
                points = points / scale

        if not ok or points is None:
            return None, None

        pts = points.reshape(-1, 2).astype(np.int32)
        mask = np.zeros(gray.shape, dtype="uint8")
        cv2.fillPoly(mask, [pts], 255)
        return cv2.boundingRect(pts), mask

    def analyze_visual_integrity(self, image):
        """Step 1: Expert Visual Analysis for Physical Tampering"""
        self.log("[Step 1/3] Performing expert visual analysis...")
        img = cv2.imread(image) if isinstance(image, str) else image
        if img is None:
            return {"status": "ERROR", "message": "Could not read image file."}

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        box, mask = self._locate_qr_boundary(gray)
        if box is None:
            # BUG FIX: failing to *locate* a boundary (poor lighting, an
            # off-angle photo, low resolution) is not evidence of tampering
            # and used to be lumped in with SUSPICIOUS, which flagged
            # perfectly legitimate codes the detector simply couldn't lock
            # onto. It's now its own status so the pipeline can still decode
            # and run threat-intel checks — just without a physical-tamper
            # opinion either way.
            return {"status": "UNVERIFIED",
                    "message": "Could not visually locate the QR code boundary (angle, lighting, or resolution). "
                                "Physical-tamper checks were skipped; digital checks still ran."}

        x, y, w, h = box

        # --- CHECK 1: Quiet Zone Analysis ---
        kernel = np.ones((15, 15), np.uint8)
        dilated_mask = cv2.dilate(mask, kernel, iterations=1)
        quiet_zone_ring = cv2.subtract(dilated_mask, mask)

        quiet_zone_mean, _ = cv2.meanStdDev(gray, mask=quiet_zone_ring)
        if quiet_zone_mean[0][0] < 200:
            return {"status": "SUSPICIOUS", "message": f"Quiet zone violated or overflowing (Mean intensity: {quiet_zone_mean[0][0]:.0f}/255)."}

        # --- CHECK 2: Texture/Sharpness Uniformity ---
        center_y1, center_y2 = y + h // 3, y + 2 * h // 3
        center_x1, center_x2 = x + w // 3, x + 2 * w // 3

        center_region = gray[center_y1:center_y2, center_x1:center_x2]
        # BUG FIX: a tiny/degenerate bounding box produced an empty slice,
        # which made cv2.Laplacian(...).var() emit a RuntimeWarning and
        # return nan. Guard against the empty-region case explicitly.
        center_sharpness = cv2.Laplacian(center_region, cv2.CV_64F).var() if center_region.size else 0.0

        periphery_mask = mask.copy()
        cv2.rectangle(periphery_mask, (center_x1, center_y1), (center_x2, center_y2), 0, -1)

        laplacian_full = cv2.Laplacian(gray, cv2.CV_64F)
        periphery_laplacian_pixels = laplacian_full[periphery_mask == 255]
        periphery_sharpness = np.var(periphery_laplacian_pixels) if len(periphery_laplacian_pixels) > 0 else 0.0

        if center_sharpness > 0 and periphery_sharpness > 0:
            sharpness_ratio = min(center_sharpness, periphery_sharpness) / max(center_sharpness, periphery_sharpness)
            if sharpness_ratio < 0.6:
                return {"status": "COVERED/DAMAGED", "message": f"Texture/sharpness break detected (Ratio: {sharpness_ratio:.2f}). Probable sticker overlay."}

        # --- CHECK 3: Internal Structure & Variance ---
        qr_region = cv2.bitwise_and(gray, gray, mask=mask)
        mean, stddev = cv2.meanStdDev(qr_region, mask=mask)
        is_covered = stddev[0][0] < 30

        inner_edges = cv2.Canny(qr_region, 50, 150)
        inner_contours, _ = cv2.findContours(inner_edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        square_count = sum(1 for cnt in inner_contours if len(cv2.approxPolyDP(cnt, 0.04 * cv2.arcLength(cnt, True), True)) == 4)
        if square_count < 15:
            is_covered = True

        if is_covered:
            return {"status": "COVERED/DAMAGED", "message": f"Suspicious internal structure. StdDev: {stddev[0][0]:.2f}, Internal Squares: {square_count}."}

        return {"status": "LEGITIMATE", "message": "Visual structure, quiet zone, and texture are uniform and legitimate.", "boundary_detected": True}

    def extract_and_normalize(self, image):
        """Step 3: Secure Reading (Only called if Step 1 & 2 pass)"""
        self.log("[Step 3/3] Visually sound. Proceeding with secure PyZbar reading...")
        img = cv2.imread(image) if isinstance(image, str) else image
        decoded_objects = pyzbar.decode(img)
        if not decoded_objects:
            return None, []

        raw_data = decoded_objects[0].data.decode('utf-8').strip()
        entities = {"urls": [], "ips": [], "domains": []}

        # Simplified vs. the original: matches the same unreserved/URL-safe
        # character set without the redundant, confusing double-escaped
        # backslashes (which only ever let a literal backslash match, which
        # can't legally appear in a URL anyway).
        url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z0-9$\-_@.&+!*'(),]|%[0-9a-fA-F]{2})+")
        entities["urls"] = list(set(url_pattern.findall(raw_data)))

        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        raw_ips = ip_pattern.findall(raw_data)
        entities["ips"] = list(set([ip for ip in raw_ips if all(0 <= int(part) < 256 for part in ip.split('.'))]))

        domains = set()
        for url in entities["urls"]:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc)
        domain_pattern = re.compile(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}')
        for match in domain_pattern.findall(raw_data):
            if not match.startswith('http') and '.' in match:
                domains.add(match)
        entities["domains"] = list(domains)

        self.log("[DNS] Resolving domains to IP addresses...")
        resolved_ips = set(entities["ips"])
        for domain in entities["domains"]:
            domain_ips = self.dns_resolver.resolve_domain(domain)
            if domain_ips:
                self.log(f"  [DNS] {domain} → {', '.join(domain_ips)}")
                resolved_ips.update(domain_ips)
        entities["ips"] = list(resolved_ips)

        return raw_data, entities

    def _vt_get(self, url, headers):
        """BUG FIX: requests.get() had no timeout and no error handling, so a
        single network hiccup (DNS failure, VT downtime, a hung connection)
        raised an uncaught exception that aborted the *entire* analysis —
        including the risk score and visual-tamper result that had already
        been computed. Failures are now caught per-request and reported as a
        REQUEST_FAILED verdict for just that item."""
        try:
            return requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as e:
            self.log(f"[Threat Intel] Request failed: {e}")
            return None

    def analyze_with_virustotal(self, entities):
        if not VT_API_KEY:
            return {"error": "VirusTotal API key missing."}
        self.log("[Threat Intel] Querying VirusTotal API...")
        headers = {"x-apikey": VT_API_KEY}
        results = {"urls": {}, "ips": {}, "domains": {}}

        def parse_vt_response(response):
            if response is None:
                return {"verdict": "REQUEST_FAILED", "malicious_count": 0}
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                last_analysis = data.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                return {"malicious_count": malicious, "suspicious_count": suspicious,
                        "verdict": "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")}
            elif response.status_code == 404:
                return {"verdict": "NOT_FOUND_IN_VT", "malicious_count": 0}
            elif response.status_code == 429:
                return {"verdict": "RATE_LIMIT_EXCEEDED", "malicious_count": 0}
            else:
                return {"verdict": f"ERROR_{response.status_code}", "malicious_count": 0}

        for url in entities.get("urls", []):
            url_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')
            resp = self._vt_get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers)
            results["urls"][url] = parse_vt_response(resp)
            time.sleep(1)

        for ip in entities.get("ips", []):
            resp = self._vt_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers)
            results["ips"][ip] = parse_vt_response(resp)
            time.sleep(1)

        for domain in entities.get("domains", []):
            resp = self._vt_get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers)
            results["domains"][domain] = parse_vt_response(resp)
            time.sleep(1)

        return results

    def run_full_analysis(self, image_source):
        """3-Step Method: visual check -> secure decode -> threat-intel lookup.

        A tamper flag from Step 1 no longer halts the pipeline. Reading pixel
        data with pyzbar doesn't "visit" anything and carries no risk to the
        analyst, so decoding and the VirusTotal lookup always proceed as long
        as the image itself is readable. Physical tampering is instead
        folded in as an automatic critical risk factor on top of whatever the
        digital checks find, so investigators get the full picture (what URL
        it points to, what VT says about it) instead of a dead end.
        """
        self.log("=" * 60)

        # STEP 1: Visual Analysis
        visual_report = self.analyze_visual_integrity(image_source)
        self.log(f"[Visual Status] {visual_report['status']}")
        self.log(f"[Visual Details] {visual_report['message']}")

        # ERROR means the image file itself couldn't be read at all — there's
        # nothing to decode or investigate, so this is the one case that
        # still stops here.
        if visual_report["status"] == "ERROR":
            self.log("[Analysis] Aborting — the image could not be read.")
            self.log("=" * 60)
            return {
                'timestamp': datetime.now().isoformat(),
                'verdict': "ERROR",
                'verdict_color': "#888888",
                'visual_status': visual_report['status'],
                'visual_details': visual_report['message'],
                'tampering_detected': False,
                'raw_data': None,
                'entities': {"urls": [], "ips": [], "domains": []},
                'risk_score': 0,
                'risk_factors': {},
            }

        tampering_detected = visual_report["status"] in ["COVERED/DAMAGED", "SUSPICIOUS"]
        if tampering_detected:
            self.log("⚠️ Physical tampering suspected — continuing with decoding and threat-intel lookup so the destination can still be identified and reported.")

        # STEP 3: Secure Reading — always attempted on a readable image.
        raw_data, entities = self.extract_and_normalize(image_source)

        if not raw_data:
            self.log("[Extraction] FAILED: PyZbar could not decode the data.")
            self.log("=" * 60)
            return {
                'timestamp': datetime.now().isoformat(),
                'verdict': "BLOCKED" if tampering_detected else "UNREADABLE",
                'verdict_color': "#ff4444" if tampering_detected else "#ffaa00",
                'visual_status': visual_report['status'],
                'visual_details': visual_report['message'],
                'tampering_detected': tampering_detected,
                'raw_data': "UNREADABLE",
                'entities': entities,
                'risk_score': 100 if tampering_detected else 0,
                'risk_factors': ({'physical_tampering': {'risk': 100, 'reason': visual_report['message']}}
                                 if tampering_detected else {}),
            }

        self.log(f"✅ Decoded QR data: {raw_data}")

        vt_results = self.analyze_with_virustotal(entities) if VT_API_KEY else None
        if vt_results:
            self.log("[Threat Intel] Analysis complete")

        # BUG FIX (kept from earlier pass): don't run URL-shape checks on
        # data that was never a URL (WiFi/vCard/plain-text QR codes).
        url_to_analyze = entities['urls'][0] if entities['urls'] else None
        # BUG FIX (kept from earlier pass): a fresh RiskScorer per analysis
        # avoids cross-talk between concurrent scans (webcam + manual select).
        risk_scorer = RiskScorer()
        risk_score, risk_factors = risk_scorer.analyze(url_to_analyze, entities, vt_results)

        if tampering_detected:
            # Physical tampering overrides the digital score as an automatic
            # critical finding, but the digital breakdown is kept alongside
            # it rather than discarded.
            risk_factors['physical_tampering'] = {'risk': 100, 'reason': visual_report['message']}
            risk_score = 100
            verdict, verdict_color = "BLOCKED", "#ff4444"
            self.log("⚠️ ALERT: Physical tampering detected (probable sticker). Do not scan this code with a phone — the extracted data below is for investigation only.")
        else:
            verdict, verdict_color = risk_scorer.get_verdict()

        self.log(f"[Digital Risk Score] {risk_score}/100 | [Verdict] {verdict}")
        self.log("=" * 60)

        return {
            'timestamp': datetime.now().isoformat(), 'raw_data': raw_data, 'visual_status': visual_report['status'],
            'visual_details': visual_report['message'], 'tampering_detected': tampering_detected,
            'entities': entities, 'vt_results': vt_results, 'risk_score': risk_score,
            'risk_factors': risk_factors, 'verdict': verdict, 'verdict_color': verdict_color
        }

# ==========================================
# MODERN GUI APPLICATION
# ==========================================
class QRAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("QR Code Security Analyzer")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.analyzer = QRAnalyzer(log_callback=self.append_log)
        self.history_manager = HistoryManager()
        self.report_generator = ReportGenerator()
        self.tk_img = None
        self.webcam_running = False
        self.cap = None
        # BUG FIX: self.cap was read/written from both the GUI thread (via
        # start_webcam/stop_webcam, e.g. on a button click) and the
        # background webcam_loop thread, with no synchronization. Stopping
        # the webcam while the loop thread was mid-read could hand it a
        # None or already-released capture object and crash. All access to
        # self.cap now goes through this lock.
        self.cap_lock = threading.Lock()
        self.current_analysis = None

        self.setup_ui()

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="🔍 QR Analyzer", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_analyze = ctk.CTkButton(self.sidebar, text="📷 Analyze Image", command=self.select_image, height=40)
        self.btn_analyze.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_webcam = ctk.CTkButton(self.sidebar, text="📹 Use Webcam", command=self.toggle_webcam, height=40)
        self.btn_webcam.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_history = ctk.CTkButton(self.sidebar, text="📜 View History", command=self.show_history, height=40)
        self.btn_history.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.btn_clear = ctk.CTkButton(self.sidebar, text="🗑️ Clear Results", command=self.clear_results, height=40, fg_color="gray40")
        self.btn_clear.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self.main_content = ctk.CTkFrame(self, corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew")
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(1, weight=1)

        self.top_bar = ctk.CTkFrame(self.main_content, height=200)
        self.top_bar.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        self.top_bar.grid_columnconfigure(1, weight=1)

        self.image_label = ctk.CTkLabel(self.top_bar, text="No image selected", width=200, height=180, corner_radius=10)
        self.image_label.grid(row=0, column=0, padx=10, pady=10)

        self.verdict_frame = ctk.CTkFrame(self.top_bar)
        self.verdict_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.verdict_frame.grid_columnconfigure(0, weight=1)

        self.verdict_label = ctk.CTkLabel(self.verdict_frame, text="Awaiting Analysis", font=ctk.CTkFont(size=28, weight="bold"), text_color="gray", wraplength=500)
        self.verdict_label.grid(row=0, column=0, pady=10)

        self.score_label = ctk.CTkLabel(self.verdict_frame, text="Risk Score: --/100", font=ctk.CTkFont(size=18))
        self.score_label.grid(row=1, column=0)

        self.btn_pdf = ctk.CTkButton(self.verdict_frame, text="📄 Generate PDF Report", command=self.generate_pdf_report, state="disabled", height=35)
        self.btn_pdf.grid(row=2, column=0, pady=10)

        self.tabview = ctk.CTkTabview(self.main_content)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        self.tab_logs = self.tabview.add("Analysis Logs")
        self.text_logs = ctk.CTkTextbox(self.tab_logs, wrap="word", state="disabled")
        self.text_logs.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_risk = self.tabview.add("Risk Factors")
        self.text_risk = ctk.CTkTextbox(self.tab_risk, wrap="word", state="disabled")
        self.text_risk.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_entities = self.tabview.add("Extracted Data")
        self.text_entities = ctk.CTkTextbox(self.tab_entities, wrap="word", state="disabled")
        self.text_entities.pack(fill="both", expand=True, padx=10, pady=10)

    def select_image(self):
        file_path = filedialog.askopenfilename(title="Select QR Code Image", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")])
        if file_path:
            self.display_image(file_path)
            self.clear_results()
            threading.Thread(target=self.run_analysis, args=(file_path,), daemon=True).start()

    def toggle_webcam(self):
        if not self.webcam_running:
            self.start_webcam()
        else:
            self.stop_webcam()

    def start_webcam(self):
        self.append_log("[Webcam] Searching for available cameras...")
        camera_found = False
        for index in [0, 1, 2]:
            cap = cv2.VideoCapture(index)
            if cap.isOpened():
                with self.cap_lock:
                    self.cap = cap
                camera_found = True
                self.append_log(f"[Webcam] Camera {index} opened successfully!")
                break
            else:
                cap.release()

        if not camera_found:
            messagebox.showerror("Webcam Error", "Could not open webcam.\n\nPossible causes:\n1. Webcam is in use\n2. No webcam connected\n3. Permission denied")
            self.append_log("[Webcam] ERROR: No camera found")
            return

        self.webcam_running = True
        self.btn_webcam.configure(text="⏹️ Stop Webcam", fg_color="red")
        threading.Thread(target=self.webcam_loop, daemon=True).start()

    def stop_webcam(self):
        self.webcam_running = False
        with self.cap_lock:
            if self.cap is not None:
                try:
                    self.cap.release()
                except Exception:
                    pass
                self.cap = None
        if self.winfo_exists():
            self.btn_webcam.configure(text="📹 Use Webcam")
            self.image_label.configure(text="No image selected", image=None)
        self.append_log("[Webcam] Stopped")

    def webcam_loop(self):
        frame_count = 0
        while self.webcam_running:
            with self.cap_lock:
                cap = self.cap
                if not cap or not cap.isOpened():
                    break
                try:
                    ret, frame = cap.read()
                except Exception:
                    break

            if not ret:
                self.append_log("[Webcam] ERROR: Failed to capture frame")
                break

            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(frame_rgb)
            pil_img.thumbnail((200, 180))
            self.tk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(200, 180))
            if self.winfo_exists():
                self.image_label.configure(image=self.tk_img, text="")

            if frame_count % 5 == 0:
                decoded = pyzbar.decode(frame)
                if decoded:
                    self.append_log("[Webcam] QR Code detected! Running visual security check...")
                    self.stop_webcam()
                    threading.Thread(target=self.run_analysis, args=(frame,), daemon=True).start()
                    break
            frame_count += 1
            time.sleep(0.03)

    def display_image(self, file_path):
        try:
            cv_img = cv2.imread(file_path)
            if cv_img is None:
                self.image_label.configure(text="Error: Invalid image")
                return
            cv_img = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(cv_img)
            pil_img.thumbnail((200, 180))
            self.tk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(200, 180))
            self.image_label.configure(image=self.tk_img, text="")
        except Exception as e:
            self.image_label.configure(text=f"Error: {e}")

    def run_analysis(self, image_source):
        try:
            result = self.analyzer.run_full_analysis(image_source)
            if result:
                self.current_analysis = result
                self.history_manager.add_entry(result)
                if self.winfo_exists():
                    self.after(0, lambda: self.update_ui_with_results(result))
        except Exception as e:
            # FIX FOR PYTHON 3.12 SCOPING:
            error_msg = str(e)
            if self.winfo_exists():
                self.after(0, lambda msg=error_msg: self.append_log(f"\n[ERROR] {msg}"))

    def update_ui_with_results(self, result):
        if not self.winfo_exists():
            return

        # The image itself couldn't be read at all — nothing to show.
        if result.get('verdict') == 'ERROR':
            self.verdict_label.configure(text="⚠️ Could not read the image file.", text_color="#888888")
            self.score_label.configure(text="Risk Score: --/100")
            self.btn_pdf.configure(state="disabled")
            return

        tampering = result.get('tampering_detected', False)

        # Verdict / score header. Tampering still gets top billing, but no
        # longer suppresses the data extracted below it.
        if tampering:
            self.verdict_label.configure(text="⚠️ ALERT: Physical tampering detected.\nDo not scan this code with a phone.", text_color="#ff4444")
        else:
            self.verdict_label.configure(text=result['verdict'], text_color=result['verdict_color'])
        score_suffix = " (BLOCKED)" if tampering else ""
        self.score_label.configure(text=f"Risk Score: {result['risk_score']}/100{score_suffix}")
        self.btn_pdf.configure(state="normal")

        self.text_risk.configure(state="normal")
        self.text_risk.delete("1.0", "end")
        if tampering:
            self.text_risk.insert("end", "🚨 PHYSICAL TAMPERING DETECTED 🚨\n\n")
        for factor, data in result.get('risk_factors', {}).items():
            self.text_risk.insert("end", f"{factor.replace('_', ' ').title()}\n  Risk: {data['risk']} points\n  Reason: {data['reason']}\n\n")
        self.text_risk.configure(state="disabled")

        self.text_entities.configure(state="normal")
        self.text_entities.delete("1.0", "end")
        if result.get('raw_data') in (None, "UNREADABLE"):
            self.text_entities.insert("end", "The QR code could not be decoded by PyZbar.\n")
            if tampering:
                self.text_entities.insert("end", "\nPhysical tampering was also detected on this code — do not attempt to scan it yourself.")
        else:
            if tampering:
                self.text_entities.insert("end", "⚠️ This code showed signs of physical tampering (likely sticker overlay).\nDo not scan it yourself — the data below was extracted for investigation and reporting only.\n\n")
            self.text_entities.insert("end", f"Raw Data (DEFANGED):\n{defang_url(result['raw_data'])}\n\n")
            self.text_entities.insert("end", f"URLs ({len(result['entities']['urls'])}):\n")
            for url in result['entities']['urls']:
                self.text_entities.insert("end", f"  • {defang_url(url)}\n")
            self.text_entities.insert("end", f"\nIP Addresses ({len(result['entities']['ips'])}):\n")
            for ip in result['entities']['ips']:
                self.text_entities.insert("end", f"  • {defang_ip(ip)}\n")
            self.text_entities.insert("end", f"\nDomains ({len(result['entities']['domains'])}):\n")
            for domain in result['entities']['domains']:
                self.text_entities.insert("end", f"  • {defang_domain(domain)}\n")
            self.text_entities.insert("end", "\n⚠️ All URLs and IPs have been defanged for safety")
        self.text_entities.configure(state="disabled")

    def generate_pdf_report(self):
        if not self.current_analysis:
            messagebox.showwarning("Warning", "No analysis to report")
            return
        try:
            filename = self.report_generator.generate_pdf(self.current_analysis)
            messagebox.showinfo("Success", f"PDF report generated:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PDF:\n{e}")

    def show_history(self):
        history = self.history_manager.get_history()
        history_window = ctk.CTkToplevel(self)
        history_window.title("Analysis History")
        history_window.geometry("800x600")
        text = ctk.CTkTextbox(history_window, wrap="word")
        text.pack(fill="both", expand=True, padx=20, pady=20)
        if not history:
            text.insert("end", "No analysis history yet.")
        else:
            for entry in history:
                text.insert("end", f"{'='*60}\nDate: {entry['timestamp']}\nVerdict: {entry['verdict']}\n")
                if entry.get('tampering_detected'):
                    text.insert("end", "Status: PHYSICAL TAMPERING DETECTED\n")
                if entry.get('raw_data') in (None, "UNREADABLE"):
                    text.insert("end", "Data: (could not be decoded)\n")
                else:
                    text.insert("end", f"Risk Score: {entry['risk_score']}/100\nData: {defang_url(entry['raw_data'][:100])}...\n")
                text.insert("end", "\n")
        text.configure(state="disabled")

    def append_log(self, message):
        if self.winfo_exists():
            self.after(0, self._append_log_ui, str(message))

    def _append_log_ui(self, message):
        if not self.winfo_exists():
            return
        self.text_logs.configure(state='normal')
        self.text_logs.insert("end", message + '\n')
        self.text_logs.see("end")
        self.text_logs.configure(state='disabled')

    def clear_results(self):
        if not self.winfo_exists():
            return
        for text_box in [self.text_logs, self.text_risk, self.text_entities]:
            text_box.configure(state='normal')
            text_box.delete("1.0", "end")
            text_box.configure(state='disabled')
        self.verdict_label.configure(text="Awaiting Analysis", text_color="gray")
        self.score_label.configure(text="Risk Score: --/100")
        self.btn_pdf.configure(state="disabled")
        self.current_analysis = None

    def on_closing(self):
        self.stop_webcam()
        self.quit()
        self.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app = QRAnalyzerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()