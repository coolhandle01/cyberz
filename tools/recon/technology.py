"""
tools/recon/technology.py - normalise raw recon strings into typed
``Technology`` values.

httpx's ``-tech-detect`` flag emits strings like ``"Django:4.2"``,
``"Apache:2.4.41"``, ``"WordPress"``. nmap's ``-sV`` (when #176 lands)
emits richer banners. nuclei's tech-detect templates emit similar.
All three sources speak a Wappalyzer-shape vocabulary; this helper is
the single coercion point that maps those strings to the typed
``Technology`` model in ``models/technology.py``.

The catalogue is intentionally seed-sized - new entries land when a
recon-string in the wild is observed missing here. Unmapped strings
are dropped silently (they are noise to classify later, not errors).
"""

from __future__ import annotations

from models.technology import Technology, TechnologyCategory

# Wappalyzer-canonical name -> categories.  Keys are lowercase; the
# coercer lowercases input before lookup. Append-only; one entry per
# canonical name. Multi-category entries are valid (Next.js is both
# a JS framework and a hosting platform; WordPress is a CMS that some
# would also call a web framework via plugins, but we keep it tight to
# avoid bleed).
_CATALOGUE: dict[str, list[TechnologyCategory]] = {
    # Web servers
    "apache": [TechnologyCategory.web_server],
    "nginx": [TechnologyCategory.web_server],
    "iis": [TechnologyCategory.web_server],
    "caddy": [TechnologyCategory.web_server],
    # Server-side frameworks
    "django": [TechnologyCategory.web_framework],
    "rails": [TechnologyCategory.web_framework],
    "ruby on rails": [TechnologyCategory.web_framework],
    "spring": [TechnologyCategory.web_framework],
    "laravel": [TechnologyCategory.web_framework],
    "express": [TechnologyCategory.web_framework],
    "asp.net": [TechnologyCategory.web_framework],
    "tornado": [TechnologyCategory.web_framework],
    "flask": [TechnologyCategory.web_framework],
    # JS frameworks
    "react": [TechnologyCategory.js_framework],
    "vue": [TechnologyCategory.js_framework],
    "vue.js": [TechnologyCategory.js_framework],
    "angular": [TechnologyCategory.js_framework],
    "angularjs": [TechnologyCategory.js_framework],
    "next.js": [TechnologyCategory.js_framework, TechnologyCategory.paas],
    "nuxt.js": [TechnologyCategory.js_framework],
    "svelte": [TechnologyCategory.js_framework],
    # JS libraries
    "jquery": [TechnologyCategory.js_library],
    "lodash": [TechnologyCategory.js_library],
    # CSS frameworks
    "bootstrap": [TechnologyCategory.css_framework],
    "tailwind": [TechnologyCategory.css_framework],
    "tailwind css": [TechnologyCategory.css_framework],
    "foundation": [TechnologyCategory.css_framework],
    # CMS
    "wordpress": [TechnologyCategory.cms],
    "drupal": [TechnologyCategory.cms],
    "joomla": [TechnologyCategory.cms],
    "ghost": [TechnologyCategory.cms],
    "magento": [TechnologyCategory.cms],
    # Databases
    "redis": [TechnologyCategory.database],
    "mongodb": [TechnologyCategory.database],
    "postgresql": [TechnologyCategory.database],
    "mysql": [TechnologyCategory.database],
    "mariadb": [TechnologyCategory.database],
    "elasticsearch": [TechnologyCategory.database],
    "couchdb": [TechnologyCategory.database],
    # CDNs
    "cloudflare": [TechnologyCategory.cdn],
    "akamai": [TechnologyCategory.cdn],
    "fastly": [TechnologyCategory.cdn],
    # PaaS / hosting platforms
    "aws": [TechnologyCategory.paas],
    "amazon web services": [TechnologyCategory.paas],
    "google cloud": [TechnologyCategory.paas],
    "heroku": [TechnologyCategory.paas],
    "vercel": [TechnologyCategory.paas],
    "netlify": [TechnologyCategory.paas],
    # Operating systems
    "ubuntu": [TechnologyCategory.operating_system],
    "debian": [TechnologyCategory.operating_system],
    "centos": [TechnologyCategory.operating_system],
    "windows": [TechnologyCategory.operating_system],
    "windows server": [TechnologyCategory.operating_system],
    # Programming languages
    "php": [TechnologyCategory.programming_language],
    "python": [TechnologyCategory.programming_language],
    "ruby": [TechnologyCategory.programming_language],
    "node.js": [TechnologyCategory.programming_language],
    "java": [TechnologyCategory.programming_language],
    # SSH / mail / ftp servers (typically surface via nmap -sV banners)
    "openssh": [TechnologyCategory.ssh_server],
    "dropbear": [TechnologyCategory.ssh_server],
    "postfix": [TechnologyCategory.mail_server],
    "dovecot": [TechnologyCategory.mail_server],
    "exim": [TechnologyCategory.mail_server],
    "vsftpd": [TechnologyCategory.ftp_server],
    "proftpd": [TechnologyCategory.ftp_server],
    "pure-ftpd": [TechnologyCategory.ftp_server],
    # Monitoring / dashboards
    "grafana": [TechnologyCategory.monitoring],
    "kibana": [TechnologyCategory.monitoring],
    "portainer": [TechnologyCategory.monitoring],
    "prometheus": [TechnologyCategory.monitoring],
    # Service discovery / secret stores
    "consul": [TechnologyCategory.service_discovery],
    "vault": [TechnologyCategory.service_discovery],
    "etcd": [TechnologyCategory.service_discovery],
    # Hosting control panels
    "cpanel": [TechnologyCategory.hosting_panel],
    "plesk": [TechnologyCategory.hosting_panel],
    "directadmin": [TechnologyCategory.hosting_panel],
    "webmin": [TechnologyCategory.hosting_panel],
    # Message queues
    "rabbitmq": [TechnologyCategory.message_queue],
    "kafka": [TechnologyCategory.message_queue],
}

# Defence: cap blast radius if a raw recon string is wildly long.
# Anything longer than 128 chars is not plausibly a Wappalyzer name -
# typically junk or an injection attempt. Skip before lookup so we
# don't waste a catalogue hit on it.
_MAX_RAW_LEN = 128


def coerce_technologies(raw_strings: list[str]) -> list[Technology]:
    """Map raw recon strings (httpx tech-detect, nmap banner, nuclei) to typed Technology.

    Input: the list of strings recon binaries emit (httpx
    ``-tech-detect`` JSON ``tech`` field, future nmap ``-sV`` banner
    text, nuclei tech-detect template output). Strings carry an optional
    ``:<version>`` suffix per the Wappalyzer convention
    (``"Django:4.2"``, ``"Apache:2.4.41"``, ``"WordPress"``).

    Output: typed ``Technology`` values for every input string whose
    name resolves against the seed catalogue above. Unmapped strings
    are dropped silently - they are noise to classify by appending to
    the catalogue, not errors to raise. Duplicates (same name +
    version) are de-duped in output.

    The catalogue is the only place name -> categories mapping lives.
    Add new entries here when a string in the wild is observed missing.
    """
    out: list[Technology] = []
    seen: set[tuple[str, str | None]] = set()
    for raw in raw_strings:
        if not raw or not isinstance(raw, str):
            continue
        if len(raw) > _MAX_RAW_LEN:
            continue
        # Wappalyzer / httpx convention: "Name:Version" or just "Name"
        raw_name, _, raw_version = raw.partition(":")
        name = raw_name.strip().lower()
        version: str | None = raw_version.strip() or None
        if not name:
            continue
        categories = _CATALOGUE.get(name)
        if categories is None:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Technology(name=name, categories=categories, version=version))
    return out


__all__ = ["coerce_technologies"]
