"""Forensic Payload Baker & Entity Link Graph Engine.

100% Offline Air-Gapped Forensic Reconstruction OS Tools.
Provides Shannon entropy calculation, IOC extraction, payload transformation/decoding,
and concentric 4-ring radial entity relationship graphs without external graph dependencies.
"""

from __future__ import annotations

import base64
import binascii
import html as html_lib
import ipaddress
import math
import re
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import plotly.graph_objects as go

from src.evidence.hashing import calculate_sha256_bytes
from src.timeline.schema import Event


class ForensicPayloadBaker:
    """Chronica forensic payload decoder, IOC extractor, and entropy analyzer."""

    # Pre-compiled regex patterns for forensic IOC extraction
    IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+|/[A-Za-z0-9_\-\.\/]+(?:\?[^\s<>\"']*)?")
    PATH_UNIX_PATTERN = re.compile(r"(?:/(?:etc|bin|sbin|usr|var|tmp|home|root|opt|lib|dev|proc|sys)/[^\s<>\"',;:]+)")
    PATH_WIN_PATTERN = re.compile(r"[A-Za-z]:\\[^\s<>\"',;:]+")
    SHA256_PATTERN = re.compile(r"\b[A-Fa-f0-9]{64}\b")
    MD5_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32}\b")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    USER_TOKEN_PATTERN = re.compile(r"(?:user(?:name)?|acct|uid)=([^\s,;]+)", re.IGNORECASE)

    @staticmethod
    def extract_iocs(text: str) -> Dict[str, List[str]]:
        """Extract all forensic indicators of compromise from arbitrary text."""
        if not text:
            return {
                "ipv4_public": [],
                "ipv4_private": [],
                "urls_uris": [],
                "file_paths": [],
                "sha256_hashes": [],
                "md5_hashes": [],
                "emails_users": [],
            }

        # IP Extraction with Private/Loopback classification
        raw_ips = sorted(list(set(ForensicPayloadBaker.IPV4_PATTERN.findall(text))))
        pub_ips: List[str] = []
        priv_ips: List[str] = []
        for ip_str in raw_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                    priv_ips.append(ip_str)
                else:
                    pub_ips.append(ip_str)
            except ValueError:
                pass

        # URLs and file paths
        urls = sorted(list(set(ForensicPayloadBaker.URL_PATTERN.findall(text))))
        paths = sorted(list(set(
            ForensicPayloadBaker.PATH_UNIX_PATTERN.findall(text) +
            ForensicPayloadBaker.PATH_WIN_PATTERN.findall(text)
        )))

        # Hashes
        sha256s = sorted(list(set(ForensicPayloadBaker.SHA256_PATTERN.findall(text))))
        md5s = sorted(list(set(ForensicPayloadBaker.MD5_PATTERN.findall(text))))

        # Users and Emails
        emails = ForensicPayloadBaker.EMAIL_PATTERN.findall(text)
        user_matches = ForensicPayloadBaker.USER_TOKEN_PATTERN.findall(text)
        users = sorted(list(set(emails + user_matches)))

        return {
            "ipv4_public": pub_ips,
            "ipv4_private": priv_ips,
            "urls_uris": urls[:20],
            "file_paths": paths[:20],
            "sha256_hashes": sha256s,
            "md5_hashes": md5s,
            "emails_users": users,
        }

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Compute Shannon entropy H(X) in [0.0, 8.0] bits/byte."""
        if not text:
            return 0.0
        data = text.encode("utf-8", errors="replace")
        length = len(data)
        if length == 0:
            return 0.0

        freqs = defaultdict(int)
        for byte in data:
            freqs[byte] += 1

        entropy = 0.0
        for count in freqs.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return round(entropy, 4)

    @staticmethod
    def auto_bake(text: str) -> List[Dict[str, str]]:
        """Automatically detect encoded payloads and generate decoded recipe items."""
        recipes: List[Dict[str, str]] = []
        if not text:
            return recipes

        # 1. URL Decoding detection (%20, %2F, %3D, etc.)
        if "%" in text and re.search(r"%[0-9A-Fa-f]{2}", text):
            try:
                decoded_url = urllib.parse.unquote(text)
                if decoded_url != text:
                    recipes.append({
                        "recipe": "URL Decode",
                        "detected": "Percent-encoded URI characters",
                        "result": decoded_url,
                    })
            except Exception:
                pass

        # 2. Hex sequence detection (e.g., auditd proctitle=2F7573722F62696E...)
        hex_match = re.search(r"\b([0-9A-Fa-f]{8,})\b", text)
        if hex_match:
            hex_cand = hex_match.group(1)
            if len(hex_cand) % 2 == 0:
                try:
                    raw_bytes = binascii.unhexlify(hex_cand)
                    decoded_ascii = raw_bytes.decode("utf-8", errors="replace").replace("\x00", " ").strip()
                    if any(c.isalnum() for c in decoded_ascii) and len(decoded_ascii) >= 3:
                        recipes.append({
                            "recipe": "Hex Decode",
                            "detected": f"Hex sequence ({len(hex_cand)} chars)",
                            "result": decoded_ascii,
                        })
                except Exception:
                    pass

        # 3. Base64 token detection (>= 12 alphanumeric/+/= chars)
        b64_matches = re.findall(r"\b([A-Za-z0-9+/]{12,}={0,2})\b", text)
        for b64_cand in b64_matches[:3]:
            try:
                decoded_bytes = base64.b64decode(b64_cand, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="replace").strip()
                if any(c.isalnum() for c in decoded_str) and len(decoded_str) >= 4:
                    recipes.append({
                        "recipe": f"Base64 Decode ({b64_cand[:8]}...)",
                        "detected": "Base64 encoded string",
                        "result": decoded_str,
                    })
            except Exception:
                pass

        # 4. Unix Epoch detection (e.g. 1728123456.789)
        epoch_matches = re.findall(r"\b(1[5-9]\d{8}(?:\.\d{1,6})?)\b", text)
        for ep_cand in epoch_matches[:2]:
            try:
                sec = float(ep_cand)
                dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                recipes.append({
                    "recipe": f"Epoch to UTC ({ep_cand})",
                    "detected": "Unix Epoch timestamp",
                    "result": dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC"),
                })
            except Exception:
                pass

        return recipes

    @staticmethod
    def apply_recipe(text: str, operation: str, param: str = "") -> str:
        """Apply a manual or automated Chronica transformation recipe."""
        if not text:
            return ""

        if operation == "Auto-Bake All":
            bakes = ForensicPayloadBaker.auto_bake(text)
            if not bakes:
                return f"[NO AUTOMATIC ENCODINGS DETECTED]\nRaw Payload:\n{text}"
            lines = ["=== CHRONICA AUTO-BAKE RESULTS ==="]
            for b in bakes:
                lines.append(f"[{b['recipe']}] ({b['detected']}):")
                lines.append(b['result'])
                lines.append("-" * 40)
            return "\n".join(lines)

        elif operation == "Hex Decode":
            clean = re.sub(r"[^0-9A-Fa-f]", "", text)
            if len(clean) % 2 != 0:
                clean = "0" + clean
            try:
                b = binascii.unhexlify(clean)
                return b.decode("utf-8", errors="replace").replace("\x00", " ")
            except Exception as e:
                return f"[HEX DECODE ERROR]: {e}"

        elif operation == "Hex Encode":
            return binascii.hexlify(text.encode("utf-8", errors="replace")).decode("ascii")

        elif operation == "Base64 Decode":
            clean = text.strip()
            # Pad if needed
            pad = len(clean) % 4
            if pad > 0:
                clean += "=" * (4 - pad)
            try:
                b = base64.b64decode(clean, validate=False)
                return b.decode("utf-8", errors="replace")
            except Exception as e:
                return f"[BASE64 DECODE ERROR]: {e}"

        elif operation == "Base64 Encode":
            return base64.b64encode(text.encode("utf-8", errors="replace")).decode("ascii")

        elif operation == "URL Decode":
            return urllib.parse.unquote(text)

        elif operation == "URL Encode":
            return urllib.parse.quote(text)

        elif operation == "Defang IOCs":
            # 1.1.1.1 -> 1[.]1[.]1[.]1, http:// -> hxxp://
            defanged = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
            defanged = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", defanged)
            return defanged

        elif operation == "Refang IOCs":
            refanged = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
            refanged = re.sub(r"\[\.\]", ".", refanged)
            return refanged

        elif operation == "Compute SHA-256":
            h = calculate_sha256_bytes(text.encode("utf-8", errors="replace"))
            return f"SHA-256: {h}\nPayload Length: {len(text)} chars\nEntropy: {ForensicPayloadBaker.shannon_entropy(text):.4f} bits/byte"

        elif operation == "Extract IPs & Paths":
            iocs = ForensicPayloadBaker.extract_iocs(text)
            lines = ["=== EXTRACTED FORENSIC IOCs ==="]
            lines.append(f"Public IPs:  {', '.join(iocs['ipv4_public']) or 'None'}")
            lines.append(f"Private IPs: {', '.join(iocs['ipv4_private']) or 'None'}")
            lines.append(f"File Paths:  {', '.join(iocs['file_paths']) or 'None'}")
            lines.append(f"URLs/URIs:   {', '.join(iocs['urls_uris']) or 'None'}")
            lines.append(f"Hashes:      {', '.join(iocs['sha256_hashes'] + iocs['md5_hashes']) or 'None'}")
            lines.append(f"Actors/Auth: {', '.join(iocs['emails_users']) or 'None'}")
            return "\n".join(lines)

        elif operation == "Regex Extract":
            pat = param.strip() or r"([A-Za-z0-9_\-\.\/]+)"
            try:
                matches = re.findall(pat, text)
                return f"Pattern: {pat}\nMatches Found: {len(matches)}\n\n" + "\n".join([str(m) for m in matches[:100]])
            except Exception as e:
                return f"[REGEX ERROR]: {e}"

        return text


class EntityGraphBuilder:
    """Concentric 4-ring radial entity link graph visualizer."""

    @staticmethod
    def build_plotly_graph(events: List[Event]) -> go.Figure:
        """Construct an interactive Plotly node-link relationship graph.
        
        Extracts 4 entity tiers placed in concentric orbits:
          Ring 1 (Inner, r=1.0): HOST nodes (cyan squares)
          Ring 2 (Middle-Inner, r=2.2): USER nodes (emerald diamonds)
          Ring 3 (Middle-Outer, r=3.4): IP_ADDRESS nodes (amber/crimson hexagons)
          Ring 4 (Outer, r=4.6): REQUEST_SESSION nodes (violet circles)
        """
        # Node tracking
        hosts: Set[str] = set()
        users: Set[str] = set()
        ips: Set[str] = set()
        sessions: Set[str] = set()

        # Edge tracking: (source_label, target_label) -> count
        edges: Dict[Tuple[str, str], int] = defaultdict(int)

        for e in events:
            h = e.source_host or e.original_filename
            u = e.username
            ip = e.src_ip
            req = e.request_id or e.session_id

            if h:
                hosts.add(h)
            if u:
                users.add(u)
            if ip:
                ips.add(ip)
            if req:
                sessions.add(req)

            # Build relationships
            if ip and u:
                edges[(ip, u)] += 1
            if u and h:
                edges[(u, h)] += 1
            if ip and h:
                edges[(ip, h)] += 1
            if h and req:
                edges[(h, req)] += 1

        # Fallback if case has no connected entities
        if not hosts and not users and not ips:
            fig = go.Figure()
            fig.update_layout(
                paper_bgcolor="#FFFFFF",
                plot_bgcolor="#FFFFFF",
                annotations=[dict(text="No correlated entities to visualize", showarrow=False, font=dict(color="#69707D", size=14))],
                height=450,
            )
            return fig

        # Concentric radial coordinate allocation
        node_coords: Dict[str, Tuple[float, float, str, str, str]] = {}
        # (x, y, category, color, symbol)

        def layout_ring(items: List[str], radius: float, category: str, color: str, symbol: str) -> None:
            n = len(items)
            if n == 0:
                return
            angle_step = (2 * math.pi) / n
            for idx, item in enumerate(sorted(items)):
                angle = idx * angle_step
                x = round(radius * math.cos(angle), 3)
                y = round(radius * math.sin(angle), 3)
                node_coords[item] = (x, y, category, color, symbol)

        # Light Mode palette
        layout_ring(list(hosts), radius=1.0, category="HOST", color="#006BB4", symbol="square")
        layout_ring(list(users), radius=2.2, category="USER", color="#017D73", symbol="diamond")
        layout_ring(list(ips), radius=3.4, category="IP_ADDRESS", color="#BD271E", symbol="hexagon")
        layout_ring(list(sessions)[:16], radius=4.6, category="REQUEST_SESSION", color="#9170B8", symbol="circle")

        # Build edge line coordinates
        edge_x = []
        edge_y = []
        for (src, dst), weight in edges.items():
            if src in node_coords and dst in node_coords:
                x0, y0, _, _, _ = node_coords[src]
                x1, y1, _, _, _ = node_coords[dst]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

        fig = go.Figure()

        # Add Edges Trace (slate line #98A2B3)
        fig.add_trace(go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=1, color="#98A2B3"),
            hoverinfo="none",
            mode="lines",
            showlegend=False,
        ))

        # Add Nodes by Category for discrete coloring and legend
        category_styles = {
            "HOST": ("Host", "#006BB4", "square", 16),
            "USER": ("User Account", "#017D73", "diamond", 14),
            "IP_ADDRESS": ("IP Address", "#BD271E", "hexagon", 14),
            "REQUEST_SESSION": ("Session Token", "#9170B8", "circle", 12),
        }

        for cat, (cat_label, color, symbol, size) in category_styles.items():
            cat_nodes = [name for name, val in node_coords.items() if val[2] == cat]
            if not cat_nodes:
                continue
            xs = [node_coords[name][0] for name in cat_nodes]
            ys = [node_coords[name][1] for name in cat_nodes]
            hover_text = [
                f"<b>{cat_label}</b><br>Identifier: <code>{html_lib.escape(str(name))}</code><br>Degree: {sum(1 for (s, d) in edges if s == name or d == name)} links"
                for name in cat_nodes
            ]

            fig.add_trace(go.Scatter(
                x=xs,
                y=ys,
                mode="markers+text",
                name=cat_label,
                text=[name[:14] for name in cat_nodes],
                textposition="top center",
                textfont=dict(family="sans-serif", size=10, color="#535966"),
                hoverinfo="text",
                hovertext=hover_text,
                marker=dict(
                    symbol=symbol,
                    size=size,
                    color=color,
                    line=dict(color="#FFFFFF", width=1.5),
                ),
            ))

        # Add Concentric Guide Rings
        for r, ring_label in [(1.0, "Hosts (r=1)"), (2.2, "Users (r=2.2)"), (3.4, "IPs (r=3.4)"), (4.6, "Sessions (r=4.6)")]:
            fig.add_shape(
                type="circle",
                xref="x",
                yref="y",
                x0=-r,
                y0=-r,
                x1=r,
                y1=r,
                line=dict(color="#D3DAE6", width=1, dash="dot"),
            )

        fig.update_layout(
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            title=dict(
                text="Entity Topology & Correlation Graph",
                font=dict(family="sans-serif", size=13, color="#1A1C21"),
                x=0.02,
                y=0.98,
            ),
            margin=dict(l=20, r=20, t=40, b=20),
            height=500,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.05,
                xanchor="center",
                x=0.5,
                font=dict(family="sans-serif", size=11, color="#1A1C21"),
            ),
            hovermode="closest",
        )

        return fig
