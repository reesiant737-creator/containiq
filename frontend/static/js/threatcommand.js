/* ThreatCommand — global JS utilities */

// Check for pending patch releases and show nav badge
(function checkPatchBadge() {
  fetch('/patches/api/pending-count')
    .then(r => r.json())
    .then(d => {
      const badge = document.getElementById('patch-badge');
      if (badge && d.pending > 0) {
        badge.style.display = 'inline';
        badge.textContent = d.pending;
      }
    })
    .catch(() => {});
})();

// Check for pending threat proposals and show nav badge
(function checkThreatBadge() {
  fetch('/threats/api/latest')
    .then(r => r.json())
    .then(d => {
      const badge = document.getElementById('threat-badge');
      if (badge && d.proposals_generated > 0) {
        badge.style.display = 'inline';
        badge.textContent = d.proposals_generated;
      }
    })
    .catch(() => {});
})();

// Auto-dismiss alerts after 5 seconds
document.querySelectorAll('.alert-dismissible').forEach(el => {
  setTimeout(() => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
    if (bsAlert) bsAlert.close();
  }, 5000);
});

// Confirm before destructive actions
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', function(e) {
    if (!confirm(this.dataset.confirm)) e.preventDefault();
  });
});

// Relative timestamps
function relativeTime(isoString) {
  const diff = (Date.now() - new Date(isoString)) / 1000;
  if (diff < 60)   return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}
document.querySelectorAll('[data-ts]').forEach(el => {
  el.textContent = relativeTime(el.dataset.ts);
  el.title = el.dataset.ts;
});
