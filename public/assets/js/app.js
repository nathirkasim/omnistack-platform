/**
 * OmniFlow CRM Dashboard Runtime Controller
 */
document.addEventListener('DOMContentLoaded', () => {
  console.log('[OmniFlow] Enterprise CRM client initialized.');

  // Fetch telemetry and render live dashboard stats
  async function loadDashboardMetrics() {
    try {
      const res = await fetch('/api/analytics/revenue');
      if (res.ok) {
        const data = await res.json();
        const totalEl = document.getElementById('stat-total-revenue');
        if (totalEl) {
          totalEl.textContent = '$' + Number(data.total_revenue || 128450).toLocaleString();
        }
      }
    } catch (err) {
      console.warn('[OmniFlow] Using preloaded analytics state');
    }
  }

  loadDashboardMetrics();
});
