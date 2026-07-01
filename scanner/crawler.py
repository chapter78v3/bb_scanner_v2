from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from .models import CrawlResult, FormDescriptor, FormField, PageObservation
from .request_engine import RequestEngine


class WebCrawler:
    """Discovers in-scope pages, forms, and JavaScript sources."""

    def __init__(
        self,
        request_engine: RequestEngine,
        max_pages: int = 50,
        allow_external: bool = False,
        respect_robots: bool = True,
        concurrency: int = 1,
        renderer=None,
    ) -> None:
        self.request_engine = request_engine
        self.max_pages = max_pages
        self.allow_external = allow_external
        self.respect_robots = respect_robots
        self.concurrency = max(1, concurrency)
        self.renderer = renderer

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Dedup key: path plus the *set* of query parameter names.

        This keeps distinct parameterized endpoints (e.g. ?id= vs ?name=)
        as separate crawl targets while collapsing value-only variations
        (?id=1 vs ?id=2) so the crawler does not loop on data explosions.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        param_names = sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        query_key = "&".join(param_names)
        base = f"{parsed.scheme}://{parsed.netloc}{path}"
        return f"{base}?{query_key}" if query_key else base

    def _can_fetch(self, url: str, robots: RobotFileParser | None) -> bool:
        if not self.respect_robots or robots is None:
            return True
        return robots.can_fetch("bb_scanner_v2", url)

    def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        parsed_start = urlparse(start_url)
        start_host = parsed_start.netloc

        robots = None
        if self.respect_robots:
            robots = RobotFileParser()
            robots.set_url(urljoin(start_url, "/robots.txt"))
            try:
                robots.read()
            except Exception:
                robots = None

        queue = deque([start_url])
        visited: Set[str] = set()

        while queue and len(visited) < self.max_pages:
            # Build a wave of unique, in-scope, fetchable URLs to fetch together.
            wave: List[str] = []
            while (
                queue
                and len(wave) < self.concurrency
                and (len(visited) + len(wave)) < self.max_pages
            ):
                current = queue.popleft()
                normalized = self._normalize_url(current)
                if normalized in visited:
                    continue
                if not self.allow_external and urlparse(current).netloc != start_host:
                    continue
                if not self._can_fetch(current, robots):
                    continue
                visited.add(normalized)
                wave.append(current)
                result.urls.append(current)

            if not wave:
                continue

            # Network fetches run in parallel; DOM parsing/enqueue stays serial.
            if self.concurrency > 1 and len(wave) > 1:
                with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                    fetched = list(executor.map(self._fetch, wave))
            else:
                fetched = [self._fetch(url) for url in wave]

            for current, response, error in fetched:
                if response is None:
                    if error:
                        result.errors.append({"url": current, **error})
                    continue

                content_type = response.headers.get("Content-Type", "")
                result.observations.append(
                    PageObservation(
                        url=current,
                        status_code=response.status_code,
                        content_type=content_type,
                        headers={k: v for k, v in response.headers.items()},
                        set_cookie=response.raw.headers.get_all("Set-Cookie")
                        if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "get_all")
                        else ([response.headers["Set-Cookie"]] if "Set-Cookie" in response.headers else []),
                    )
                )
                if "html" not in content_type:
                    continue

                html = response.text
                extra_links: List[str] = []
                if self.renderer is not None:
                    rendered = self.renderer.render(
                        current,
                        headers=dict(self.request_engine.session.headers),
                        verify_tls=self.request_engine.verify_tls,
                    )
                    if rendered is not None:
                        html, extra_links = rendered

                soup = BeautifulSoup(html, "html.parser")
                self._extract_forms(page_url=current, soup=soup, result=result)
                self._extract_js(page_url=current, soup=soup, result=result)

                links = self._extract_links(page_url=current, soup=soup) + extra_links
                for link in links:
                    if self.allow_external or urlparse(link).netloc == start_host:
                        if self._normalize_url(link) not in visited:
                            queue.append(link)

        result.js_files = sorted(set(result.js_files))
        return result

    def _fetch(self, url: str) -> Tuple[str, Optional["object"], Optional[dict]]:
        try:
            return url, self.request_engine.get(url), None
        except Exception as exc:
            return url, None, {"error_type": type(exc).__name__, "error": str(exc)[:300]}

    @staticmethod
    def _extract_links(page_url: str, soup: BeautifulSoup) -> List[str]:
        discovered = []
        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            discovered.append(urljoin(page_url, href))
        return discovered

    @staticmethod
    def _extract_js(page_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        for script in soup.find_all("script", src=True):
            src = script.get("src", "").strip()
            if src:
                result.js_files.append(urljoin(page_url, src))

    @staticmethod
    def _extract_forms(page_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            method = (form.get("method") or "GET").upper()
            fields = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                field_type = field.get("type", "text")
                value = field.get("value", "")
                fields.append(FormField(name=name, field_type=field_type, value=value))

            result.forms.append(
                FormDescriptor(
                    page_url=page_url,
                    action_url=urljoin(page_url, action),
                    method=method,
                    fields=fields,
                )
            )
