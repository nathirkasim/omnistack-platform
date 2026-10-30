// VULNERABLE: Hardcoded GitHub Personal Access Token (PAT)
const GITHUB_PAT = "ghp_9Kf3mN8pQ2rT4vX6zB8dF1hJ3kL5nP7rT9vX";

async function fetchRepoDetails() {
    const headers = { Authorization: `Bearer ${GITHUB_PAT}` };
    return fetch("https://api.github.com/user/repos", { headers });
}
