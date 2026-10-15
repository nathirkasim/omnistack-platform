<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OmniFlow CRM | Enterprise Intelligence</title>
  <link rel="stylesheet" href="/assets/css/app.css">
</head>
<body>
  <aside class="sidebar">
    <div class="sidebar-brand">
      <span style="color:#3b82f6;">◆</span> OmniFlow CRM
    </div>
    <ul class="sidebar-nav">
      <li><a href="#" class="nav-link active">Dashboard</a></li>
      <li><a href="#customers" class="nav-link">Customers</a></li>
      <li><a href="#analytics" class="nav-link">Predictive Analytics</a></li>
      <li><a href="#leads" class="nav-link">AI Lead Scoring</a></li>
      <li><a href="#reports" class="nav-link">Reports & Exports</a></li>
      <li><a href="#settings" class="nav-link">Security Policies</a></li>
    </ul>
  </aside>

  <main class="main-content">
    <header class="header-banner">
      <div>
        <h1 style="font-size: 1.5rem; font-weight: 700;">Executive Dashboard</h1>
        <p style="color: var(--text-secondary); font-size: 0.9rem;">Real-time customer telemetry, AI scoring, and ARR growth</p>
      </div>
      <div>
        <span class="badge badge-green">Production Cluster v2.4</span>
      </div>
    </header>

    <section class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Annual Run Rate (ARR)</div>
        <div class="stat-value" id="stat-total-revenue">$2,450,000</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active Enterprise Accounts</div>
        <div class="stat-value">1,248</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">AI Conversion Rate</div>
        <div class="stat-value" style="color: var(--accent-purple);">68.4%</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Avg Lead Quality (SHAP)</div>
        <div class="stat-value" style="color: var(--accent-green);">84.2</div>
      </div>
    </section>

    <section class="table-card">
      <div class="table-header">
        <span>High-Value Accounts & Predictive Lead Tiers</span>
        <button style="background:var(--accent-blue); color:#fff; border:none; padding:8px 16px; border-radius:6px; font-weight:600; cursor:pointer;">Export Pipeline</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Account Name</th>
            <th>Company</th>
            <th>Status</th>
            <th>AI Lead Score</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>#1001</td>
            <td><strong>Sarah Jenkins</strong></td>
            <td>Apex Global Logistics</td>
            <td><span class="badge badge-green">Active</span></td>
            <td><strong>94.2%</strong> (Tier A)</td>
            <td>2026-09-12</td>
          </tr>
          <tr>
            <td>#1002</td>
            <td><strong>Michael Chen</strong></td>
            <td>Vanguard FinTech</td>
            <td><span class="badge badge-blue">Onboarding</span></td>
            <td><strong>88.5%</strong> (Tier A)</td>
            <td>2026-09-28</td>
          </tr>
          <tr>
            <td>#1003</td>
            <td><strong>Elena Rostova</strong></td>
            <td>Nordic Cloud Systems</td>
            <td><span class="badge badge-amber">Review</span></td>
            <td><strong>64.1%</strong> (Tier B)</td>
            <td>2026-10-04</td>
          </tr>
        </tbody>
      </table>
    </section>
  </main>

  <script src="/assets/js/app.js"></script>
</body>
</html>
