"""GitHub API — profile, repos, emails."""

from __future__ import annotations

from osintx.models import Finding, Severity, Target
from osintx.providers.base import BaseProvider, ProviderMeta

API = "https://api.github.com"

class GitHubProvider(BaseProvider):
    meta = ProviderMeta(
        name="github",
        category="username",
        description="GitHub profile, repos and public emails",
        targets=("username",),
        rate=1.0,
        burst=2,
        timeout=25.0,
    )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.ctx.config.github_token:
            headers["Authorization"] = f"Bearer {self.ctx.config.github_token}"
        return headers

    async def run(self, target: Target) -> list[Finding]:
        response = await self.ctx.http.get(
            f"{API}/users/{target.value}",
            headers=self._headers(),
            allow_status=(200, 404, 403, 429),
        )
        if response.status_code == 404:
            return []
        if response.status_code in {403, 429}:
            raise RuntimeError("GitHub rate limit")
        profile = response.json() or {}

        findings = [
            Finding(
                provider=self.name,
                category="username",
                title=f"GitHub profile: {profile.get('login')}",
                severity=Severity.LOW,
                url=profile.get("html_url"),
                data={
                    "name": profile.get("name"),
                    "company": profile.get("company"),
                    "blog": profile.get("blog"),
                    "location": profile.get("location"),
                    "bio": profile.get("bio"),
                    "twitter": profile.get("twitter_username"),
                    "public_repos": profile.get("public_repos"),
                    "followers": profile.get("followers"),
                    "created_at": profile.get("created_at"),
                },
            )
        ]

        repos = await self.ctx.http.get(
            f"{API}/users/{target.value}/repos",
            headers=self._headers(),
            params={"per_page": 30, "sort": "updated"},
            allow_status=(200, 404, 403, 429),
        )
        if repos.status_code == 200:
            for repo in repos.json() or []:
                findings.append(
                    Finding(
                        provider=self.name,
                        category="username",
                        title=f"Repository: {repo.get('name')}",
                        severity=Severity.INFO,
                        url=repo.get("html_url"),
                        data={
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count"),
                            "description": repo.get("description"),
                            "updated_at": repo.get("updated_at"),
                        },
                    )
                )
        return findings
