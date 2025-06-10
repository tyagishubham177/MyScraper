export function initIcons() {
  function initLucideIcons(retries = 5) {
    if (typeof lucide !== 'undefined' && lucide.createIcons) {
      try {
        console.log('Attempting lucide.createIcons()'); // Add log
        lucide.createIcons();
        console.log('lucide.createIcons() called successfully.'); // Add log
      } catch (e) {
        console.error('Error calling lucide.createIcons():', e); // Log the error
      }
    } else if (retries > 0) {
      console.log(`lucide not ready, retrying initLucideIcons. Retries left: ${retries -1}`);
      setTimeout(() => initLucideIcons(retries - 1), 200);
    } else {
      console.error('lucide.createIcons() not available after multiple retries.');
    }
  }
  initLucideIcons();
  const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
  tooltipTriggerList.map(el => new bootstrap.Tooltip(el));

  function checkBodyScrollable() {
    if (document.body.scrollHeight > window.innerHeight) {
      document.body.classList.add('is-scrollable');
    } else {
      document.body.classList.remove('is-scrollable');
    }
  }
  window.addEventListener('load', checkBodyScrollable);
  window.addEventListener('resize', checkBodyScrollable);
  document.querySelectorAll('.accordion-collapse').forEach(item => {
    item.addEventListener('shown.bs.collapse', checkBodyScrollable);
    item.addEventListener('hidden.bs.collapse', checkBodyScrollable);
  });
}
