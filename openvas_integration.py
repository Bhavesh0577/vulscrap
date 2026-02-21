"""Utilities for running OpenVAS (GVM) scans and normalizing the findings.

Supports two execution backends:
- python-gvm over GMP/TLS (default)
- Docker Compose + gvm-tools over the gvmd Unix socket (useful on Windows)
"""

import logging
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

try:
    from gvm.connections import TLSConnection
    from gvm.errors import GvmError
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform

    OPENVAS_DEPENDENCIES_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    TLSConnection = None  # type: ignore
    GvmError = Exception  # type: ignore
    Gmp = None  # type: ignore
    EtreeTransform = None  # type: ignore
    OPENVAS_DEPENDENCIES_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class OpenVASConfig:
    """Configuration values needed to connect to an OpenVAS (GVM) server."""

    host: str
    port: int = 9390
    username: str = ""
    password: str = ""
    scan_config_id: str = ""
    port_list_id: str = ""
    verify_tls: bool = False
    timeout_seconds: int = 45 * 60
    poll_interval: int = 30

    # Execution backend.
    # - "python-gvm": connect to OPENVAS_HOST:OPENVAS_PORT via GMP/TLS
    # - "docker": run gvm-cli inside the docker compose gvm-tools service via Unix socket
    backend: str = "python-gvm"
    compose_file: str = "docker-compose.yml"
    compose_service: str = "gvm-tools"


@dataclass
class OpenVASScanResult:
    """Normalized representation of an executed OpenVAS scan."""

    vulnerabilities: List[Dict[str, str]]
    task_id: Optional[str]
    report_id: Optional[str]
    scan_name: str
    duration_seconds: float


class OpenVASConfigurationError(RuntimeError):
    """Raised when OpenVAS configuration is missing or invalid."""


class OpenVASExecutionError(RuntimeError):
    """Raised when OpenVAS scan execution fails."""


def docker_backend_available() -> bool:
    """Return True if Docker Compose appears available on this machine."""

    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        proc = subprocess.run(
            [docker, "compose", "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def load_openvas_config(overrides: Optional[Dict[str, str]] = None) -> OpenVASConfig:
    """Load OpenVAS connection details from environment variables or overrides."""

    overrides = overrides or {}

    def _get(key: str, default: Optional[str] = None) -> str:
        return str(overrides.get(key, os.getenv(key, default) or "")).strip()

    backend = (_get("OPENVAS_BACKEND", "python-gvm") or "python-gvm").strip().lower()
    if backend not in {"python-gvm", "docker"}:
        raise OpenVASConfigurationError(
            "OPENVAS_BACKEND must be either 'python-gvm' or 'docker'"
        )

    if backend == "python-gvm" and not OPENVAS_DEPENDENCIES_AVAILABLE:
        raise OpenVASConfigurationError(
            "python-gvm is not installed. Install it via pip or set OPENVAS_BACKEND=docker."
        )
    if backend == "docker" and not docker_backend_available():
        raise OpenVASConfigurationError(
            "Docker Compose is not available. Install Docker Desktop or set OPENVAS_BACKEND=python-gvm."
        )

    host = _get("OPENVAS_HOST")
    port = int(_get("OPENVAS_PORT", "9390") or 9390)
    username = _get("OPENVAS_USERNAME")
    password = str(overrides.get("password", os.getenv("OPENVAS_PASSWORD", "") or "")).strip()
    scan_config_id = _get("OPENVAS_SCAN_CONFIG_ID")
    port_list_id = _get("OPENVAS_PORT_LIST_ID")
    verify_tls = (_get("OPENVAS_VERIFY_TLS", "false").lower() == "true")
    timeout_seconds = int(overrides.get("timeout_seconds") or os.getenv("OPENVAS_TIMEOUT_SECONDS", 2700))
    poll_interval = int(overrides.get("poll_interval") or os.getenv("OPENVAS_POLL_INTERVAL", 30))

    compose_file = _get("OPENVAS_COMPOSE_FILE", "docker-compose.yml")
    compose_service = _get("OPENVAS_COMPOSE_SERVICE", "gvm-tools")

    required_pairs = [
        ("OPENVAS_USERNAME", username),
        ("OPENVAS_PASSWORD", password),
        ("OPENVAS_SCAN_CONFIG_ID", scan_config_id),
        ("OPENVAS_PORT_LIST_ID", port_list_id),
    ]
    if backend == "python-gvm":
        required_pairs.insert(0, ("OPENVAS_HOST", host))

    missing = [key for key, value in required_pairs if not value]

    if missing:
        raise OpenVASConfigurationError(
            "Missing OpenVAS configuration values: " + ", ".join(missing)
        )

    return OpenVASConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        scan_config_id=scan_config_id,
        port_list_id=port_list_id,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        poll_interval=poll_interval,
        backend=backend,
        compose_file=compose_file,
        compose_service=compose_service,
    )


def run_openvas_scan(
    targets: List[str],
    scan_name: Optional[str] = None,
    config: Optional[OpenVASConfig] = None,
) -> OpenVASScanResult:
    """Execute an OpenVAS scan and return normalized vulnerability data."""

    # Note: config/backend may allow operation without python-gvm.

    if not targets:
        raise ValueError("At least one target host or IP is required for an OpenVAS scan")

    config = config or load_openvas_config()
    scan_name = scan_name or f"Streamlit Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    start_time = time.time()

    def _run_with_python_gvm() -> OpenVASScanResult:
        if not OPENVAS_DEPENDENCIES_AVAILABLE:
            raise OpenVASConfigurationError(
                "python-gvm is not installed. Install it via pip or set OPENVAS_BACKEND=docker."
            )

        connection_kwargs = {
            "hostname": config.host,
            "port": config.port,
            "timeout": config.timeout_seconds,
        }
        if not config.verify_tls:
            logger.warning("OpenVAS TLS certificate verification is disabled for this scan")

        connection = TLSConnection(**connection_kwargs)
        transform = EtreeTransform()

        logger.info("Connecting to OpenVAS at %s:%s", config.host, config.port)
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(config.username, config.password)
            logger.info("Authenticated to OpenVAS as %s", config.username)

            target_name = f"{scan_name} Targets"
            target_resp = gmp.create_target(
                name=target_name,
                hosts=",".join(targets),
                port_list_id=config.port_list_id,
            )
            target_id = target_resp.get("id")
            logger.info("Created OpenVAS target %s for %s", target_id, targets)

            task_resp = gmp.create_task(name=scan_name, config_id=config.scan_config_id, target_id=target_id)
            task_id = task_resp.get("id")
            logger.info("Created OpenVAS task %s", task_id)

            start_resp = gmp.start_task(task_id)
            report_id = _extract_report_id(start_resp)

            logger.info("Started OpenVAS task %s (report %s)", task_id, report_id)
            report_id = _wait_for_task_and_report(
                gmp,
                task_id,
                report_id,
                timeout_seconds=config.timeout_seconds,
                poll_interval=config.poll_interval,
            )

            report = gmp.get_report(report_id=report_id, filter_string="rows=-1", details=True)
            vulnerabilities = _parse_report(report, scan_name)

        duration = time.time() - start_time
        return OpenVASScanResult(
            vulnerabilities=vulnerabilities,
            task_id=task_id,
            report_id=report_id,
            scan_name=scan_name,
            duration_seconds=duration,
        )

    def _run_with_docker_compose() -> OpenVASScanResult:
        if not docker_backend_available():
            raise OpenVASConfigurationError("Docker Compose backend is not available")

        logger.info(
            "Running OpenVAS scan via docker compose (%s:%s)",
            config.compose_file,
            config.compose_service,
        )

        target_name = f"{scan_name} Targets"
        target_id = _docker_create_target(
            name=target_name,
            hosts=",".join(targets),
            port_list_id=config.port_list_id,
            username=config.username,
            password=config.password,
            compose_file=config.compose_file,
            compose_service=config.compose_service,
            timeout_seconds=config.timeout_seconds,
        )

        task_id = _docker_create_task(
            name=scan_name,
            config_id=config.scan_config_id,
            target_id=target_id,
            username=config.username,
            password=config.password,
            compose_file=config.compose_file,
            compose_service=config.compose_service,
            timeout_seconds=config.timeout_seconds,
        )

        report_id = _docker_start_task(
            task_id=task_id,
            username=config.username,
            password=config.password,
            compose_file=config.compose_file,
            compose_service=config.compose_service,
            timeout_seconds=config.timeout_seconds,
        )

        report_id = _docker_wait_for_task_and_report(
            task_id=task_id,
            existing_report_id=report_id,
            username=config.username,
            password=config.password,
            compose_file=config.compose_file,
            compose_service=config.compose_service,
            timeout_seconds=config.timeout_seconds,
            poll_interval=config.poll_interval,
        )

        report = _docker_get_report(
            report_id=report_id,
            username=config.username,
            password=config.password,
            compose_file=config.compose_file,
            compose_service=config.compose_service,
            timeout_seconds=config.timeout_seconds,
        )
        vulnerabilities = _parse_report(report, scan_name)

        duration = time.time() - start_time
        return OpenVASScanResult(
            vulnerabilities=vulnerabilities,
            task_id=task_id,
            report_id=report_id,
            scan_name=scan_name,
            duration_seconds=duration,
        )

    backend = (config.backend or "python-gvm").strip().lower()
    if backend == "docker":
        return _run_with_docker_compose()

    try:
        return _run_with_python_gvm()
    except Exception as exc:
        message = str(exc)
        looks_like_transport_issue = any(
            token in message
            for token in (
                "UNEXPECTED_EOF_WHILE_READING",
                "Connection refused",
                "EOF occurred in violation of protocol",
                "Connection reset",
            )
        )
        if looks_like_transport_issue and docker_backend_available():
            logger.warning(
                "python-gvm connection failed (%s). Falling back to docker backend.",
                message,
            )
            return _run_with_docker_compose()
        raise


def _run_gvm_cli_xml(
    *,
    xml: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> ET.Element:
    docker = shutil.which("docker")
    if not docker:
        raise OpenVASExecutionError("Docker is not installed or not on PATH")

    compose_file = os.path.abspath(compose_file)

    cmd = [
        docker,
        "compose",
        "-f",
        compose_file,
        "run",
        "--rm",
        compose_service,
        "gvm-cli",
        "--gmp-username",
        username,
        "--gmp-password",
        password,
        "socket",
        "--xml",
        xml,
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=max(30, timeout_seconds),
        check=False,
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise OpenVASExecutionError(
            f"gvm-cli failed (exit {proc.returncode}). {stderr or stdout or 'No output'}"
        )

    if not stdout:
        raise OpenVASExecutionError("gvm-cli returned no output")

    try:
        return ET.fromstring(stdout)
    except ET.ParseError as exc:
        raise OpenVASExecutionError(f"Failed to parse gvm-cli XML output: {exc}") from exc


def _parse_created_id(root: ET.Element) -> str:
    created_id = root.get("id")
    if created_id:
        return created_id

    # Some responses nest the created resource.
    nested = root.find(".//*[@id]")
    if nested is not None and nested.get("id"):
        return str(nested.get("id"))
    raise OpenVASExecutionError("Could not determine created resource id from GMP response")


def _docker_create_target(
    *,
    name: str,
    hosts: str,
    port_list_id: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> str:
    xml = (
        "<create_target>"
        f"<name>{_xml_escape(name)}</name>"
        f"<hosts>{_xml_escape(hosts)}</hosts>"
        f"<port_list id=\"{_xml_escape(port_list_id)}\"/>"
        "</create_target>"
    )
    root = _run_gvm_cli_xml(
        xml=xml,
        username=username,
        password=password,
        compose_file=compose_file,
        compose_service=compose_service,
        timeout_seconds=timeout_seconds,
    )
    return _parse_created_id(root)


def _docker_create_task(
    *,
    name: str,
    config_id: str,
    target_id: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> str:
    xml = (
        "<create_task>"
        f"<name>{_xml_escape(name)}</name>"
        f"<config id=\"{_xml_escape(config_id)}\"/>"
        f"<target id=\"{_xml_escape(target_id)}\"/>"
        "</create_task>"
    )
    root = _run_gvm_cli_xml(
        xml=xml,
        username=username,
        password=password,
        compose_file=compose_file,
        compose_service=compose_service,
        timeout_seconds=timeout_seconds,
    )
    return _parse_created_id(root)


def _docker_start_task(
    *,
    task_id: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> Optional[str]:
    xml = f"<start_task task_id=\"{_xml_escape(task_id)}\"/>"
    root = _run_gvm_cli_xml(
        xml=xml,
        username=username,
        password=password,
        compose_file=compose_file,
        compose_service=compose_service,
        timeout_seconds=timeout_seconds,
    )
    report_id = root.findtext("report_id")
    return report_id.strip() if report_id else None


def _docker_get_task(
    *,
    task_id: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> ET.Element:
    xml = f"<get_tasks task_id=\"{_xml_escape(task_id)}\" details=\"1\"/>"
    return _run_gvm_cli_xml(
        xml=xml,
        username=username,
        password=password,
        compose_file=compose_file,
        compose_service=compose_service,
        timeout_seconds=timeout_seconds,
    )


def _docker_wait_for_task_and_report(
    *,
    task_id: str,
    existing_report_id: Optional[str],
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
    poll_interval: int,
) -> str:
    deadline = time.time() + timeout_seconds
    report_id = existing_report_id
    last_status = None

    while time.time() < deadline:
        task_doc = _docker_get_task(
            task_id=task_id,
            username=username,
            password=password,
            compose_file=compose_file,
            compose_service=compose_service,
            timeout_seconds=timeout_seconds,
        )
        status = task_doc.findtext(".//status")
        progress = task_doc.findtext(".//progress")
        if status != last_status and status:
            logger.info("OpenVAS task %s status: %s%% (%s)", task_id, progress or "0", status)
            last_status = status

        if status == "Done":
            if not report_id:
                report_id = task_doc.findtext(".//last_report/report/@id")
            if not report_id:
                report_elem = task_doc.find(".//last_report/report")
                if report_elem is not None:
                    report_id = report_elem.get("id")
            if report_id:
                return report_id
        elif status in {"Stopped", "Stopped by user", "Canceled", "Failed"}:
            raise OpenVASExecutionError(f"OpenVAS task {task_id} ended with status '{status}'")

        time.sleep(max(5, poll_interval))

    raise TimeoutError(f"Timed out waiting for OpenVAS task {task_id} to complete")


def _docker_get_report(
    *,
    report_id: str,
    username: str,
    password: str,
    compose_file: str,
    compose_service: str,
    timeout_seconds: int,
) -> ET.Element:
    xml = f"<get_reports report_id=\"{_xml_escape(report_id)}\" details=\"1\" filter=\"rows=-1\"/>"
    return _run_gvm_cli_xml(
        xml=xml,
        username=username,
        password=password,
        compose_file=compose_file,
        compose_service=compose_service,
        timeout_seconds=timeout_seconds,
    )


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _extract_report_id(response) -> Optional[str]:
    if response is None:
        return None
    report_id = None
    try:
        report_id = response.findtext("report_id")  # type: ignore[attr-defined]
    except AttributeError:
        pass
    return report_id


def _wait_for_task_and_report(
    gmp,
    task_id: str,
    existing_report_id: Optional[str],
    timeout_seconds: int,
    poll_interval: int,
) -> str:
    deadline = time.time() + timeout_seconds
    report_id = existing_report_id
    last_status = None

    while time.time() < deadline:
        task = gmp.get_task(task_id=task_id)
        status = task.findtext(".//status")
        progress = task.findtext(".//progress")
        if status != last_status and status:
            logger.info("OpenVAS task %s status: %s%% (%s)", task_id, progress or "0", status)
            last_status = status

        if status == "Done":
            if not report_id:
                report_elem = task.find(".//last_report/report")
                if report_elem is not None:
                    report_id = report_elem.get("id")
            if report_id:
                return report_id
        elif status in {"Stopped", "Stopped by user", "Canceled", "Failed"}:
            raise RuntimeError(f"OpenVAS task {task_id} ended with status '{status}'")

        time.sleep(max(5, poll_interval))

    raise TimeoutError(f"Timed out waiting for OpenVAS task {task_id} to complete")


def _parse_report(report, scan_name: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if report is None:
        return results

    report_node = report.find(".//report")
    if report_node is None:
        return results

    for result in report_node.findall(".//result"):
        host = result.findtext("host", default="Unknown host")
        port = result.findtext("port", default="n/a")
        threat = result.findtext("threat", default="Medium")
        severity = result.findtext("severity")
        nvt = result.find("nvt")
        oid = nvt.get("oid") if nvt is not None else None
        cve_id = None
        nvt_name = None
        tags = {}

        if nvt is not None:
            cve_id = nvt.findtext("cve")
            nvt_name = nvt.findtext("name")
            tags = _parse_tag_field(nvt.findtext("tags", default=""))

        description = tags.get("summary") or result.findtext("description") or "No description provided."
        mitigation = tags.get("solution") or result.findtext("solution") or "See OpenVAS advisory for remediation details."
        reference = tags.get("see_also") or _extract_first_reference(nvt)
        cve_id = (cve_id or (oid and f"OPENVAS-{oid}") or f"OPENVAS-{host}-{port}")

        vulnerability = {
            "product_name": f"{host} - {nvt_name or 'Unknown NVT'}",
            "product_version": port,
            "oem_name": "OpenVAS",
            "severity_level": _map_severity(threat, severity),
            "vulnerability_description": description,
            "mitigation_strategy": mitigation,
            "published_date": datetime.utcnow().strftime("%b %Y"),
            "cve_id": cve_id,
            "url": reference or "https://www.greenbone.net/en/technology/",
            "scan_name": scan_name,
            "openvas_host": host,
        }

        results.append(vulnerability)

    return results


def _parse_tag_field(tag_blob: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not tag_blob:
        return values

    for pair in tag_blob.split("|"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _extract_first_reference(nvt) -> Optional[str]:
    if nvt is None:
        return None
    refs_container = nvt.find("refs")
    if refs_container is None:
        return None
    ref = refs_container.find("ref")
    if ref is not None and ref.text:
        return ref.text.strip()
    return None


def _map_severity(threat: Optional[str], severity_value: Optional[str]) -> str:
    if threat:
        normalized = threat.strip().capitalize()
        if normalized in {"Low", "Medium", "High", "Critical"}:
            return "Critical" if normalized == "Alarm" else normalized

    try:
        score = float(severity_value) if severity_value else None
    except ValueError:
        score = None

    if score is None:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
