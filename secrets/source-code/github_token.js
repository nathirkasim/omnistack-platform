// VULNERABLE: Hardcoded GitHub Personal Access Token (PAT)
const GITHUB_PAT = "ghp_11223344556677889900aabbccddeeff0011";

async function fetchRepoDetails() {
    const headers = { Authorization: `Bearer ${GITHUB_PAT}` };
    return fetch("https://api.github.com/user/repos", { headers });
}
