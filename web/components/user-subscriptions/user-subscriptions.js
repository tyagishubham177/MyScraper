import { fetchAPI, showGlobalLoader, hideGlobalLoader, sanitizeUrl } from '../utils/utils.js';

export async function initUserSubscriptionsUI() {
  showGlobalLoader();
  const email = localStorage.getItem('userEmail');
  if (!email) {
    window.location.href = '../../index.html';
    return;
  }

  let [recipients, products] = await Promise.all([
    fetchAPI('/api/recipients'),
    fetchAPI('/api/products')
  ]).catch(() => [null, null]);

  if (!recipients || !products) {
    console.error('Failed to load data');
    return;
  }

  const recipient = recipients.find(r => r.email === email);
  if (!recipient) {
    console.error('Recipient not found');
    return;
  }

  let subscriptions = await fetchAPI(`/api/subscriptions?recipient_id=${recipient.id}`).catch(() => []);
  const subscribedMap = new Map(subscriptions.map(s => [s.product_id, s]));

  function loadPaused() {
    try {
      const stored = JSON.parse(localStorage.getItem('pausedSubscriptions') || '{}');
      return new Map(Object.entries(stored));
    } catch {
      return new Map();
    }
  }

  function savePaused(map) {
    const obj = {};
    map.forEach((v, k) => { obj[k] = v; });
    localStorage.setItem('pausedSubscriptions', JSON.stringify(obj));
  }

  const pausedMap = loadPaused();

  const subscribedList = document.getElementById('user-subscribed-list');
  const allList = document.getElementById('all-products-list');
  const searchInput = document.getElementById('product-search');

  function createSubscribedItem(product, sub, paused = false) {
    const li = document.createElement('li');
    li.className = 'list-group-item product-list-item-mobile' + (paused ? ' paused' : '');
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const details = document.createElement('div');
    details.className = 'product-details mb-2';
    const nameEl = document.createElement('h5');
    nameEl.className = 'product-name mb-0';
    nameEl.textContent = product.name;
    const linkEl = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    linkEl.href = safeUrl || '#';
    linkEl.target = '_blank';
    linkEl.className = 'product-url d-block small';
    linkEl.textContent = `${product.url} `;
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'external-link');
    icon.className = 'lucide-xs';
    linkEl.appendChild(icon);
    details.appendChild(nameEl);
    details.appendChild(linkEl);

    const controls = document.createElement('div');
    controls.className = 'product-controls d-flex align-items-center';
    controls.innerHTML = `
      <div class="time-slot-group me-1">
        <input type="time" class="form-control form-control-sm sub-start" value="${sub.start_time || '00:00'}">
      </div>
      <div class="time-slot-group me-2">
        <input type="time" class="form-control form-control-sm sub-end" value="${sub.end_time || '23:59'}">
      </div>
      <button class="btn btn-sm btn-outline-secondary pause-btn me-1 p-1 btn-icon"><i data-lucide="${paused ? 'play' : 'pause'}" class="lucide-small"></i></button>
      <button class="btn btn-sm btn-outline-danger unsub-btn p-1 btn-icon"><i data-lucide="x" class="lucide-small"></i></button>`;

    li.appendChild(details);
    li.appendChild(controls);
    return li;
  }

  function createAllProductItem(product) {
    const li = document.createElement('li');
    li.className = 'list-group-item d-flex justify-content-between align-items-center';
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const info = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = product.name;
    const link = document.createElement('small');
    link.className = 'd-block text-muted';
    const displayUrl = product.url.length > 30 ? product.url.substring(0, 27) + '...' : product.url;
    const anchor = document.createElement('a');
    const safeUrl = sanitizeUrl(product.url);
    anchor.href = safeUrl || '#';
    anchor.target = '_blank';
    anchor.title = product.url;
    anchor.textContent = `${displayUrl} `;
    const icon2 = document.createElement('i');
    icon2.setAttribute('data-lucide', 'external-link');
    icon2.className = 'lucide-small';
    anchor.appendChild(icon2);
    link.appendChild(anchor);
    info.appendChild(strong);
    info.appendChild(link);

    const btn = document.createElement('button');
    btn.className = 'btn btn-sm btn-outline-primary sub-btn';
    btn.innerHTML = '<i data-lucide="plus"></i>';

    li.appendChild(info);
    li.appendChild(btn);
    return li;
  }

  function render() {
    subscribedList.innerHTML = '';
    allList.innerHTML = '';
    for (const [id, sub] of subscribedMap.entries()) {
      const product = products.find(p => p.id === id);
      if (product) subscribedList.appendChild(createSubscribedItem(product, sub, false));
    }
    for (const [id, info] of pausedMap.entries()) {
      if (subscribedMap.has(id)) continue;
      const product = products.find(p => p.id === id);
      if (product) subscribedList.appendChild(createSubscribedItem(product, info, true));
    }
    products.forEach(p => {
      if (!subscribedMap.has(p.id) && !pausedMap.has(p.id)) allList.appendChild(createAllProductItem(p));
    });
    if (window.lucide) window.lucide.createIcons();
    filterProducts(searchInput.value || '');
  }

  async function subscribe(productId) {
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId })
      });
      subscribedMap.set(productId, res);
      render();
    } catch (err) {
      alert(err.message || 'Failed to subscribe');
    } finally {
      hideGlobalLoader();
    }
  }

  async function unsubscribe(productId) {
    showGlobalLoader();
    try {
      await fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId })
      });
      subscribedMap.delete(productId);
      render();
    } catch (err) {
      alert(err.message || 'Failed to unsubscribe');
    } finally {
      hideGlobalLoader();
    }
  }

  async function pause(productId) {
    const li = subscribedList.querySelector(`li[data-product-id="${productId}"]`);
    const start = li ? li.querySelector('.sub-start').value : '00:00';
    const end = li ? li.querySelector('.sub-end').value : '23:59';
    showGlobalLoader();
    try {
      await fetchAPI('/api/subscriptions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId })
      });
    } catch (err) {
      // ignore failures; subscription might not exist
    }
    subscribedMap.delete(productId);
    pausedMap.set(productId, { start_time: start, end_time: end });
    savePaused(pausedMap);
    render();
    hideGlobalLoader();
  }

  async function resume(productId) {
    const li = subscribedList.querySelector(`li[data-product-id="${productId}"]`);
    const start = li ? li.querySelector('.sub-start').value : (pausedMap.get(productId)?.start_time || '00:00');
    const end = li ? li.querySelector('.sub-end').value : (pausedMap.get(productId)?.end_time || '23:59');
    showGlobalLoader();
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end })
      });
      subscribedMap.set(productId, res);
      pausedMap.delete(productId);
      savePaused(pausedMap);
      render();
    } catch (err) {
      alert(err.message || 'Failed to resume');
    } finally {
      hideGlobalLoader();
    }
  }

  async function updateTimes(productId, start, end) {
    showGlobalLoader();
    if (pausedMap.has(productId) && !subscribedMap.has(productId)) {
      pausedMap.set(productId, { start_time: start, end_time: end });
      savePaused(pausedMap);
      hideGlobalLoader();
      return;
    }
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end })
      });
      subscribedMap.set(productId, res);
    } catch (err) {
      alert(err.message || 'Failed to update times');
    } finally {
      hideGlobalLoader();
    }
  }

  subscribedList.addEventListener('click', e => {
    const li = e.target.closest('li[data-product-id]');
    if (!li) return;
    if (e.target.closest('.unsub-btn')) {
      const id = li.dataset.productId;
      if (subscribedMap.has(id)) {
        unsubscribe(id);
      } else {
        pausedMap.delete(id);
        savePaused(pausedMap);
        render();
      }
    } else if (e.target.closest('.pause-btn')) {
      const id = li.dataset.productId;
      if (pausedMap.has(id) && !subscribedMap.has(id)) {
        resume(id);
      } else {
        pause(id);
      }
    }
  });

  subscribedList.addEventListener('change', e => {
    if (!e.target.classList.contains('sub-start') && !e.target.classList.contains('sub-end')) return;
    const li = e.target.closest('li[data-product-id]');
    const start = li.querySelector('.sub-start').value;
    const end = li.querySelector('.sub-end').value;
    updateTimes(li.dataset.productId, start, end);
  });

  allList.addEventListener('click', e => {
    const btn = e.target.closest('.sub-btn');
    if (!btn) return;
    const li = btn.closest('li[data-product-id]');
    subscribe(li.dataset.productId);
  });

  function filterProducts(term) {
  console.log('[FilterDebug] filterProducts called with term:', term);
    const items = allList.querySelectorAll('li');
  const searchWords = term.toLowerCase().split(' ').filter(word => word.length > 0);
  console.log('[FilterDebug] searchWords:', searchWords);

  let shownCount = 0;
  let hiddenCount = 0;

  items.forEach((item, index) => {
    const title = (item.dataset.name || item.querySelector('strong')?.textContent || '').toLowerCase();

    let allWordsMatch = false;
    if (searchWords.length === 0) {
      allWordsMatch = true; // Show all if search is empty
    } else {
      allWordsMatch = searchWords.every(word => title.includes(word));
    }

    if (index < 5) { // Log details for the first 5 items for brevity
      console.log(`[FilterDebug] Item ${index}: Title: "${title}", Matches: ${allWordsMatch}`);
    }

    if (allWordsMatch) {
      item.classList.remove('product-item-hidden');
      shownCount++;
    } else {
      item.classList.add('product-item-hidden');
      hiddenCount++;
    }
    });
  console.log(`[FilterDebug] Filtering complete. Shown: ${shownCount}, Hidden: ${hiddenCount} (Total: ${items.length})`);
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => filterProducts(searchInput.value));
  }

  render();
  hideGlobalLoader();
}

// Initialization is handled by the page that loads this component
