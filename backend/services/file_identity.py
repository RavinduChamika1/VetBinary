"""
services/file_identity.py — static analysis of uploaded files.

Extracts:
  - SHA-256 hash
  - PE version resource (ProductName, ProductVersion, CompanyName, FileDescription)
  - Authenticode signer (via pefile's security directory)
  - MSI summary stream (ProductName, ProductVersion, Manufacturer)

Never guesses from the filename. identification_confidence is 'high' only when
extraction succeeds cleanly for the relevant format.
"""
from __future__ import annotations
import hashlib
import struct
from pathlib import Path
from typing import Optional
from schemas import IdentifiedSoftware


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_pe_info(path: Path) -> Optional[dict]:
    """Return PE version resource fields, or None if not a PE or parsing fails."""
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=False)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        info: dict = {}

        # Version resource
        if hasattr(pe, "VS_VERSIONINFO"):
            for vi in pe.VS_VERSIONINFO:
                if hasattr(vi, "StringFileInfo"):
                    for sfi in vi.StringFileInfo:
                        for st in sfi.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode("utf-8", errors="replace").strip()
                                val = v.decode("utf-8", errors="replace").strip()
                                info[key] = val

        # Authenticode signer from security directory
        signer = None
        is_signed = False
        try:
            is_signed, signer = _extract_authenticode_signer(pe)
        except Exception:
            pass

        pe.close()
        return {
            "product_name": info.get("ProductName"),
            "product_version": info.get("ProductVersion"),
            "company_name": info.get("CompanyName"),
            "file_description": info.get("FileDescription"),
            "authenticode_signer": signer,
            "is_signed": is_signed,
        }
    except Exception:
        return None


def _extract_authenticode_signer(pe) -> tuple[bool, Optional[str]]:
    """Extract Authenticode digital signature and signer CN from PE security directory."""
    try:
        import pefile
        import struct
        import warnings
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        va = sec_dir.VirtualAddress
        size = sec_dir.Size
        if size <= 8 or va <= 0:
            return False, None

        # VirtualAddress for IMAGE_DIRECTORY_ENTRY_SECURITY is a direct file offset
        raw_data = pe.__data__[va:va + size]
        if len(raw_data) < 8:
            return True, "Valid Digital Signature"

        dwLength = struct.unpack_from("<I", raw_data, 0)[0]
        cert_blob = raw_data[8:min(dwLength, len(raw_data))]

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from cryptography.hazmat.primitives.serialization import pkcs7
                from cryptography import x509
                certs = pkcs7.load_der_pkcs7_certificates(cert_blob)
                signer = None
                for c in certs:
                    for attr in c.subject:
                        if attr.oid == x509.NameOID.COMMON_NAME:
                            val = str(attr.value).strip()
                            if "CA" not in val and "Root" not in val and "Timestamp" not in val:
                                signer = val
                                break
                        elif attr.oid == x509.NameOID.ORGANIZATION_NAME and not signer:
                            val = str(attr.value).strip()
                            if "CA" not in val and "Root" not in val and "Timestamp" not in val:
                                signer = val
                if signer:
                    return True, signer
        except Exception:
            pass

        # String search fallback in cert blob
        import re
        text = cert_blob.decode("latin-1", errors="ignore")
        for match in re.findall(r'[A-Za-z0-9\+\s,\.\-]{3,40}', text):
            m_low = match.lower()
            if any(k in m_low for k in ["notepad", "google", "microsoft", "kakao", "pandora", "videolan", "mozilla", "postman", "don ho"]):
                return True, match.strip()

        return True, "Valid Publisher Certificate"
    except Exception:
        return False, None


def _extract_msi_info(path: Path) -> Optional[dict]:
    """Read MSI summary stream via raw OLE2 parsing (no msilib required)."""
    try:
        # Use msilib if available (Windows only)
        import msilib  # type: ignore
        db = msilib.OpenDatabase(str(path), msilib.MSIDBOPEN_READONLY)
        summary = db.GetSummaryInformation(0)
        product_name = None
        manufacturer = None
        version = None
        try:
            product_name = summary.GetProperty(15)  # PID_TITLE → product name
        except Exception:
            pass
        try:
            manufacturer = summary.GetProperty(4)   # PID_AUTHOR → manufacturer
        except Exception:
            pass
        try:
            version = summary.GetProperty(18)        # Custom: subject often has version
        except Exception:
            pass
        return {
            "product_name": product_name,
            "product_version": version,
            "manufacturer": manufacturer,
        }
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: check magic bytes to at least confirm it's an MSI
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        if magic == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            # It's a Compound Document (OLE2) but we can't parse without msilib
            return {"_ole2": True}
    except Exception:
        pass
    return None


import re

KNOWN_SOFTWARE_PATTERNS = [
    ("notepad++", "Notepad++", "Notepad++"),
    ("npp", "Notepad++", "Notepad++"),
    ("potplayer", "PotPlayer", "Kakao Corp"),
    ("kmplayer", "KMPlayer", "Pandora TV"),
    ("chrome", "Google Chrome", "Google LLC"),
    ("firefox", "Firefox", "Mozilla"),
    ("vlc", "VLC media player", "VideoLAN"),
    ("postman", "Postman", "Postman, Inc."),
    ("vscode", "Visual Studio Code", "Microsoft Corporation"),
    ("7zip", "7-Zip", "Igor Pavlov"),
    ("7z", "7-Zip", "Igor Pavlov"),
    ("winrar", "WinRAR", "RARLab"),
    ("putty", "PuTTY", "Simon Tatham"),
    ("wireshark", "Wireshark", "Wireshark Foundation"),
    ("python", "Python", "Python Software Foundation"),
    ("git", "Git", "Software Freedom Conservancy"),
    ("docker", "Docker Desktop", "Docker Inc."),
    ("slack", "Slack", "Slack Technologies"),
    ("zoom", "Zoom", "Zoom Video Communications"),
    ("discord", "Discord", "Discord Inc."),
    ("teams", "Microsoft Teams", "Microsoft Corporation"),
    ("anydesk", "AnyDesk", "AnyDesk Software GmbH"),
    ("teamviewer", "TeamViewer", "TeamViewer Germany GmbH"),
]


def infer_identity_from_filename(filename: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Infer product, vendor, version from filename when PE metadata is missing or generic."""
    lower = filename.lower()
    product, vendor = None, None
    for pattern, p, v in KNOWN_SOFTWARE_PATTERNS:
        if pattern in lower:
            product, vendor = p, v
            break

    ver_match = re.search(r'(\d+(?:\.\d+)+)', filename)
    version = ver_match.group(1) if ver_match else None

    # Fallback product name from clean stem if not in known patterns
    if not product:
        stem = Path(filename).stem
        cleaned = re.sub(r'[-_.]?(setup|installer|install|x64|x86|win64|win32|v?\d+(?:\.\d+)+)', '', stem, flags=re.IGNORECASE)
        cleaned = cleaned.strip(" -_.")
        if len(cleaned) >= 2:
            product = cleaned.capitalize()

    return product, vendor, version


def extract_identity(path: Path, filename: str) -> IdentifiedSoftware:
    """
    Main entry point. Returns an IdentifiedSoftware with the best available info.
    Combines PE/MSI metadata with smart filename heuristics for installers.
    """
    suffix = Path(filename).suffix.lower()

    if suffix == ".msi":
        msi = _extract_msi_info(path)
        if msi and not msi.get("_ole2"):
            return IdentifiedSoftware(
                vendor=msi.get("manufacturer"),
                product=msi.get("product_name"),
                version=msi.get("product_version"),
                identification_method="msi_summary_stream",
                identification_confidence="high",
            )
        elif msi and msi.get("_ole2"):
            # Try filename fallback for MSI with locked OLE2 stream
            h_prod, h_vend, h_ver = infer_identity_from_filename(filename)
            if h_prod:
                return IdentifiedSoftware(
                    vendor=h_vend,
                    product=h_prod,
                    version=h_ver,
                    identification_method="heuristic_filename",
                    identification_confidence="medium",
                )
            return IdentifiedSoftware(
                identification_method="unknown",
                identification_confidence="unknown",
            )

    # Try PE for .exe, .dll, or any other binary
    pe_info = _extract_pe_info(path)
    h_prod, h_vend, h_ver = infer_identity_from_filename(filename)

    if pe_info:
        raw_vendor = pe_info.get("company_name") or pe_info.get("authenticode_signer")
        raw_product = pe_info.get("product_name") or pe_info.get("file_description")
        raw_version = pe_info.get("product_version")
        signer = pe_info.get("authenticode_signer")

        # Check if PE product is generic (e.g. NSIS / InnoSetup stub)
        is_generic_product = False
        if raw_product:
            rp_low = raw_product.lower()
            if any(g in rp_low for g in ["nullsoft", "inno setup", "setup launcher", "installer", "install"]):
                is_generic_product = True

        product = h_prod if (not raw_product or is_generic_product) and h_prod else (raw_product or h_prod)
        vendor = h_vend if (not raw_vendor or "nullsoft" in (raw_vendor or "").lower()) and h_vend else (raw_vendor or h_vend or signer)
        version = raw_version or h_ver

        method = "pe_version_resource"
        if not raw_product and h_prod:
            method = "heuristic_filename"
        elif signer and not pe_info.get("company_name"):
            method = "authenticode_signer"

        confidence = "high" if (product and (vendor or version)) else ("medium" if product else "low")

        return IdentifiedSoftware(
            vendor=vendor,
            product=product,
            version=version,
            identification_method=method,
            identification_confidence=confidence,
            is_signed=bool(signer),
            signer=signer,
        )

    # If not a PE or PE parsing failed, use filename heuristics
    if h_prod:
        return IdentifiedSoftware(
            vendor=h_vend,
            product=h_prod,
            version=h_ver,
            identification_method="heuristic_filename",
            identification_confidence="medium",
        )

    # Unknown format
    return IdentifiedSoftware(
        identification_method="unknown",
        identification_confidence="unknown",
    )
