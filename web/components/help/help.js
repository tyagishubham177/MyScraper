export function initHelp() {
  const helpFab = document.getElementById('help-fab');
  const helpModalEl = document.getElementById('helpModal');
  if (!helpFab || !helpModalEl) return;

  const helpModal = new bootstrap.Modal(helpModalEl);

  const hideFab = () => {
    helpFab.style.display = 'none';
  };

  if (localStorage.getItem('helpDismissed') === 'true') {
    hideFab();
  }

  helpFab.addEventListener('click', () => {
    helpModal.show();
  });

  helpModalEl.addEventListener('hidden.bs.modal', () => {
    localStorage.setItem('helpDismissed', 'true');
    hideFab();
  });

  const howToBtn = document.getElementById('how-to-btn');
  if (howToBtn) {
    howToBtn.addEventListener('click', () => helpModal.show());
  }
}
