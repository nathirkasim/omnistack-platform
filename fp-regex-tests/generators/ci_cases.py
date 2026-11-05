from typing import List
from .base import FixtureBuilder, TargetLine

def generate_ci_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: CI/CD
    # -------------------------------------------------------------

    # 1. Script Injection via PR Title (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_injection_title_flag.yml")
    fb.add("name: Validate PR")
    fb.add("on: [pull_request]")
    fb.add("jobs:")
    fb.add("  check:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        '    - run: echo "${{ github.event.pull_request.title }}"',
        "FLAG", "CI", "L1_BASIC", "CI-001",
        "Direct inline interpolation of untrusted pull request title in shell command"
    )
    fixtures.append(fb)

    # 2. Script Injection via Issue Comment Body (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_injection_body_flag.yml")
    fb.add("name: Comment Handler")
    fb.add("on: [issue_comment]")
    fb.add("jobs:")
    fb.add("  process:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        '    - run: ${{ github.event.comment.body }}',
        "FLAG", "CI", "L1_BASIC", "CI-002",
        "Arbitrary shell command execution from user issue comment body"
    )
    fixtures.append(fb)

    # 3. Safe Environment Mapping for Untrusted Context (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_env_mapping_noflag.yml")
    fb.add("name: Validate PR Safe")
    fb.add("on: [pull_request]")
    fb.add("jobs:")
    fb.add("  check:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add("    - name: Echo Title")
    fb.add("      env:")
    fb.add_target(
        '        PR_TITLE: "${{ github.event.pull_request.title }}"',
        "NO_FLAG", "CI", "L1_BASIC", "CI-003",
        "Untrusted title mapped into process environment variable preventing shell injection"
    )
    fb.add_target(
        '      run: echo "$PR_TITLE"',
        "NO_FLAG", "CI", "L1_BASIC", "CI-004",
        "Shell variable reference safely quoting dynamic value"
    )
    fixtures.append(fb)

    # 4. Safe Context Properties in Run (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_safe_context_noflag.yml")
    fb.add("name: Audit Step")
    fb.add("on: [push]")
    fb.add("jobs:")
    fb.add("  audit:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        "    - run: 'echo \"Commit: ${{ github.sha }} Run: ${{ github.run_id }}\"'",
        "NO_FLAG", "CI", "L1_BASIC", "CI-005",
        "Deterministic numeric/hexadecimal GitHub platform variables"
    )
    fixtures.append(fb)

    # 5. Dangerous permissions: write-all (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_permissions_writeall_flag.yml")
    fb.add("name: Permissive Workflow")
    fb.add("on: [push]")
    fb.add_target(
        "permissions: write-all",
        "FLAG", "CI", "L1_BASIC", "CI-006",
        "Excessive broad write permissions assigned to workflow execution token"
    )
    fb.add("jobs:")
    fb.add("  build:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add('    - run: echo "building"')
    fixtures.append(fb)

    # 6. Least-Privilege Scoped Permissions (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_permissions_read_noflag.yml")
    fb.add("name: Hardened Workflow")
    fb.add("on: [push]")
    fb.add("permissions:")
    fb.add_target(
        "  contents: read",
        "NO_FLAG", "CI", "L1_BASIC", "CI-007",
        "Minimal read-only permissions explicitly restricted to repository contents"
    )
    fb.add("jobs:")
    fb.add("  build:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add('    - run: echo "building"')
    fixtures.append(fb)

    # 7. pull_request_target with Untrusted Head Checkout (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_pr_target_checkout_flag.yml")
    fb.add("name: PR Target Audit")
    fb.add("on: pull_request_target")
    fb.add("jobs:")
    fb.add("  test:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add("    - uses: actions/checkout@v4")
    fb.add("      with:")
    fb.add_target(
        '        ref: "${{ github.event.pull_request.head.sha }}"',
        "FLAG", "CI", "L1_BASIC", "CI-008",
        "Checkout of untrusted fork commit running with privileged repository secrets"
    )
    fixtures.append(fb)

    # 8. pull_request_target without Untrusted Checkout (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_pr_target_safe_noflag.yml")
    fb.add("name: PR Target Safe Labeler")
    fb.add("on: pull_request_target")
    fb.add("jobs:")
    fb.add("  label:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        "    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
        "NO_FLAG", "CI", "L1_BASIC", "CI-009",
        "Default base repository checkout pinned to immutable commit SHA"
    )
    fixtures.append(fb)

    # 9. Hardcoded Token in Workflow Env (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_hardcoded_token_flag.yml")
    fb.add("name: Publishing")
    fb.add("on: [push]")
    fb.add("jobs:")
    fb.add("  publish:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add("    - name: Push Packages")
    fb.add("      env:")
    fb.add_target(
        '        GH_TOKEN: "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "CI", "L1_BASIC", "CI-010",
        "Personal access token hardcoded directly in workflow environment"
    )
    fb.add('      run: npm publish')
    fixtures.append(fb)

    # 10. Masking Secret Token Command (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gha_mask_secret_noflag.yml")
    fb.add("name: Secret Obfuscation")
    fb.add("on: [push]")
    fb.add("jobs:")
    fb.add("  mask:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        '    - run: echo "::add-mask::$DYNAMIC_KEY"',
        "NO_FLAG", "CI", "L1_BASIC", "CI-011",
        "GitHub Actions workflow command instructing runner to mask value from log output"
    )
    fixtures.append(fb)

    # 11. GitLab CI Cleartext Secret (FLAG)
    fb = FixtureBuilder("l1_basic/ci/gitlab_ci_secrets_flag.yml")
    fb.add("deploy_job:")
    fb.add("  stage: deploy")
    fb.add("  variables:")
    fb.add_target(
        '    DEPLOY_TOKEN: "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "CI", "L1_BASIC", "CI-012",
        "Cleartext deployment token literal in GitLab CI configuration"
    )
    fb.add("  script:")
    fb.add('    - ./deploy.sh')
    fixtures.append(fb)

    # 12. GitLab CI Variable Mapping (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/gitlab_ci_variables_noflag.yml")
    fb.add("deploy_job:")
    fb.add("  stage: deploy")
    fb.add("  variables:")
    fb.add_target(
        '    DEPLOY_TOKEN: "$CI_DEPLOY_PASSWORD"',
        "NO_FLAG", "CI", "L1_BASIC", "CI-013",
        "Dynamic environment variable expansion in GitLab CI"
    )
    fb.add("  script:")
    fb.add('    - ./deploy.sh')
    fixtures.append(fb)

    # 13. Azure Pipelines Secret Literal (FLAG)
    fb = FixtureBuilder("l1_basic/ci/azure_pipelines_flag.yml")
    fb.add("trigger:")
    fb.add("  - main")
    fb.add("steps:")
    fb.add("  - script: echo Deploying")
    fb.add("    env:")
    fb.add_target(
        '      API_KEY: "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "CI", "L1_BASIC", "CI-014",
        "Hardcoded token literal in Azure Pipelines task environment"
    )
    fixtures.append(fb)

    # 14. Azure Pipelines Variable Mapping (NO_FLAG)
    fb = FixtureBuilder("l1_basic/ci/azure_pipelines_noflag.yml")
    fb.add("trigger:")
    fb.add("  - main")
    fb.add("steps:")
    fb.add("  - script: echo Deploying")
    fb.add("    env:")
    fb.add_target(
        '      API_KEY: $(SECRET_API_KEY)',
        "NO_FLAG", "CI", "L1_BASIC", "CI-015",
        "Pipeline variable reference in Azure Pipelines"
    )
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: CI/CD
    # -------------------------------------------------------------

    # L2-1: PR Validation Pipeline
    fb = FixtureBuilder("l2_intermediate/ci/pr_validation.yml")
    fb.add("name: PR Validation Suite")
    fb.add("on:")
    fb.add("  pull_request:")
    fb.add("    types: [opened, synchronize]")
    fb.add("permissions:")
    fb.add_target(
        "  contents: read",
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-001",
        "Scoped read permission on repository contents"
    )
    fb.add_target(
        "  pull-requests: read",
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-002",
        "Scoped read permission on pull requests"
    )
    fb.add("jobs:")
    fb.add("  verify:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add_target(
        "    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-003",
        "Checkout action pinned by full commit SHA"
    )
    fb.add("    - name: Log Title Unsafe")
    fb.add_target(
        '      run: echo "${{ github.event.pull_request.title }}"',
        "FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-004",
        "Direct script injection flaw in shell execution"
    )
    fb.add("    - name: Log Title Safe")
    fb.add("      env:")
    fb.add_target(
        '        TITLE: "${{ github.event.pull_request.title }}"',
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-005",
        "Safe environment variable binding"
    )
    fb.add_target(
        '      run: echo "$TITLE"',
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-006",
        "Safe shell reference"
    )
    fb.add_target(
        '  write-all-tests:',
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-007",
        "Job name containing write-all lookalike string"
    )
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add('    - run: echo "testing"')
    fixtures.append(fb)

    # L2-2: Release Pipeline
    fb = FixtureBuilder("l2_intermediate/ci/release_pipeline.yml")
    fb.add("name: Production Release Pipeline")
    fb.add("on:")
    fb.add("  push:")
    fb.add("    tags: ['v*']")
    fb.add("jobs:")
    fb.add("  deploy:")
    fb.add("    runs-on: ubuntu-latest")
    fb.add("    steps:")
    fb.add("    - name: Configure Credentials")
    fb.add("      env:")
    fb.add_target(
        '        DEPLOY_TOKEN: "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-008",
        "Embedded deploy token string inside workflow env block"
    )
    fb.add_target(
        '      run: echo "Deploy token is $DEPLOY_TOKEN"',
        "FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-009",
        "Echoing credential variable to workflow console output"
    )
    fb.add_target(
        '    - run: echo "Building release ${{ github.sha }}"',
        "NO_FLAG", "CI", "L2_INTERMEDIATE", "CI-L2-010",
        "Safe SHA reference in build log statement"
    )
    fixtures.append(fb)

    return fixtures
