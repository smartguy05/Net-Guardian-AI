"""Documentation loader service for AI chat context."""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Base paths for documentation
BACKEND_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BACKEND_DIR / "data"
DOCS_DIR = BACKEND_DIR.parent / "docs"


class DocLoader:
    """Service for loading documentation and help content.

    This is a singleton service that caches loaded content to avoid
    repeated file I/O.
    """

    def __init__(self) -> None:
        self._help_content: dict[str, Any] | None = None
        self._docs_cache: dict[str, str] = {}

    def _load_help_content(self) -> dict[str, Any]:
        """Load help content from JSON file."""
        if self._help_content is not None:
            return self._help_content

        help_path = DATA_DIR / "help_content.json"
        try:
            if help_path.exists():
                with open(help_path, encoding="utf-8") as f:
                    self._help_content = json.load(f)
                logger.debug("help_content_loaded", path=str(help_path))
            else:
                logger.warning("help_content_not_found", path=str(help_path))
                self._help_content = {}
        except Exception as e:
            logger.error("help_content_load_error", error=str(e))
            self._help_content = {}

        return self._help_content

    def _load_doc_file(self, filename: str) -> str:
        """Load a markdown documentation file."""
        if filename in self._docs_cache:
            return self._docs_cache[filename]

        doc_path = DOCS_DIR / filename
        try:
            if doc_path.exists():
                with open(doc_path, encoding="utf-8") as f:
                    content = f.read()
                self._docs_cache[filename] = content
                logger.debug("doc_file_loaded", filename=filename)
                return content
            else:
                logger.warning("doc_file_not_found", filename=filename)
                return ""
        except Exception as e:
            logger.error("doc_file_load_error", filename=filename, error=str(e))
            return ""

    def get_help_for_pages(self, pages: list[str]) -> str:
        """Get help content for specific pages.

        Args:
            pages: List of page paths (e.g., ["/dashboard/devices", "/dashboard/alerts"])

        Returns:
            Formatted help text for the specified pages.
        """
        help_content = self._load_help_content()
        if not help_content:
            return ""

        sections: list[str] = []

        for page in pages:
            # Try exact match first
            page_help = help_content.get(page)

            # Try with /dashboard prefix if not found
            if not page_help and not page.startswith("/dashboard"):
                page_help = help_content.get(f"/dashboard{page}")

            # Try device detail pattern
            if not page_help and "devices/" in page:
                page_help = help_content.get("/dashboard/devices/detail")

            if page_help:
                section_text = self._format_page_help(page_help)
                sections.append(section_text)

        return "\n\n".join(sections) if sections else ""

    def _format_page_help(self, page_help: dict[str, Any]) -> str:
        """Format a page's help content as text."""
        lines = [f"## {page_help.get('title', 'Help')}"]
        lines.append(page_help.get("overview", ""))

        for section in page_help.get("sections", []):
            lines.append(f"\n### {section.get('title', '')}")
            lines.append(section.get("description", ""))

            tips = section.get("tips", [])
            if tips:
                lines.append("\n**Tips:**")
                for tip in tips:
                    lines.append(f"- {tip}")

        return "\n".join(lines)

    def get_all_help_content(self) -> str:
        """Get all help content formatted as text.

        Returns:
            Complete help documentation as formatted text.
        """
        help_content = self._load_help_content()
        if not help_content:
            return ""

        # Format all pages
        all_pages = list(help_content.keys())
        return self.get_help_for_pages(all_pages)

    def get_configuration_doc(self) -> str:
        """Get the configuration documentation.

        Returns:
            Full configuration.md content.
        """
        return self._load_doc_file("configuration.md")

    def get_config_section(self, section_name: str) -> str:
        """Get a specific section from configuration.md.

        Args:
            section_name: Name of the section to extract.

        Returns:
            The section content, or empty string if not found.
        """
        config_doc = self.get_configuration_doc()
        if not config_doc:
            return ""

        # Find section by header
        lines = config_doc.split("\n")
        section_lines: list[str] = []
        in_section = False
        section_level = 0

        for line in lines:
            # Check for section header
            if line.startswith("#"):
                header_level = len(line.split()[0]) if line.split() else 0
                header_text = line.lstrip("#").strip().lower()

                if section_name.lower() in header_text:
                    in_section = True
                    section_level = header_level
                    section_lines.append(line)
                elif in_section and header_level <= section_level:
                    # End of section (same or higher level header)
                    break
                elif in_section:
                    section_lines.append(line)
            elif in_section:
                section_lines.append(line)

        return "\n".join(section_lines).strip()

    def get_deployment_guide(self) -> str:
        """Get the deployment guide documentation.

        Returns:
            Full deployment-guide.md content.
        """
        return self._load_doc_file("deployment-guide.md")

    def get_user_guide(self) -> str:
        """Get the user guide documentation.

        Returns:
            Full user-guide.md content, or empty if not found.
        """
        return self._load_doc_file("user-guide.md")

    def search_all_docs(self, query: str, max_results: int = 5) -> list[dict[str, str]]:
        """Search across all documentation for relevant content.

        Args:
            query: Search query.
            max_results: Maximum number of results to return.

        Returns:
            List of matching sections with source and content.
        """
        results: list[dict[str, str]] = []
        query_lower = query.lower()
        query_words = set(query_lower.split())

        # Search help content
        help_content = self._load_help_content()
        for page, content in help_content.items():
            # Check title and overview
            title = content.get("title", "").lower()
            overview = content.get("overview", "").lower()

            if any(word in title or word in overview for word in query_words):
                results.append(
                    {
                        "source": f"Help: {content.get('title', page)}",
                        "content": self._format_page_help(content)[:500],
                    }
                )

            # Check sections
            for section in content.get("sections", []):
                section_title = section.get("title", "").lower()
                section_desc = section.get("description", "").lower()
                tips = " ".join(section.get("tips", [])).lower()

                if any(
                    word in section_title or word in section_desc or word in tips
                    for word in query_words
                ):
                    if len(results) < max_results:
                        results.append(
                            {
                                "source": f"Help: {content.get('title')} > {section.get('title')}",
                                "content": f"{section.get('description', '')}\n\nTips:\n"
                                + "\n".join(f"- {t}" for t in section.get("tips", [])),
                            }
                        )

            if len(results) >= max_results:
                break

        # Search markdown docs
        for doc_name in ["configuration.md", "deployment-guide.md", "user-guide.md"]:
            if len(results) >= max_results:
                break

            doc_content = self._load_doc_file(doc_name)
            if not doc_content:
                continue

            doc_lower = doc_content.lower()
            if any(word in doc_lower for word in query_words):
                # Find relevant section
                lines = doc_content.split("\n")
                for i, line in enumerate(lines):
                    if line.startswith("#") and any(
                        word in line.lower() for word in query_words
                    ):
                        # Extract section
                        section_lines = [line]
                        for j in range(i + 1, min(i + 20, len(lines))):
                            if lines[j].startswith("#"):
                                break
                            section_lines.append(lines[j])

                        results.append(
                            {
                                "source": f"Docs: {doc_name}",
                                "content": "\n".join(section_lines)[:500],
                            }
                        )

                        if len(results) >= max_results:
                            break

        return results[:max_results]

    def get_troubleshooting_context(self, issue_keywords: list[str]) -> str:
        """Get troubleshooting-relevant documentation.

        Args:
            issue_keywords: Keywords describing the issue.

        Returns:
            Relevant documentation sections for troubleshooting.
        """
        relevant_sections: list[str] = []

        # Search for relevant docs
        for keyword in issue_keywords:
            results = self.search_all_docs(keyword, max_results=2)
            for result in results:
                relevant_sections.append(f"**{result['source']}**\n{result['content']}")

        # Always include some common troubleshooting areas
        common_areas = ["log sources", "authentication", "database", "redis"]
        for area in common_areas:
            if any(area in kw.lower() for kw in issue_keywords):
                config_section = self.get_config_section(area)
                if config_section:
                    relevant_sections.append(config_section)

        return "\n\n---\n\n".join(relevant_sections) if relevant_sections else ""


# Global singleton instance
_doc_loader: DocLoader | None = None


@lru_cache(maxsize=1)
def get_doc_loader() -> DocLoader:
    """Get the global DocLoader instance."""
    global _doc_loader
    if _doc_loader is None:
        _doc_loader = DocLoader()
    return _doc_loader
