import { fetchAPI } from '../utils/utils.js';

export async function initUserSubscriptionsUI() {
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

  const subscribedList = document.getElementById('user-subscribed-list');
  const allList = document.getElementById('all-products-list');
  const searchInput = document.getElementById('product-search');

  function createSubscribedItem(product, sub) {
    const li = document.createElement('li');
    li.className = 'list-group-item';
    li.dataset.productId = product.id;
    li.dataset.name = product.name.toLowerCase();

    const wrapper = document.createElement('div');
    wrapper.className = 'd-flex justify-content-between align-items-center';

    const info = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = product.name;
    const link = document.createElement('small');
    link.className = 'd-block text-muted';
    link.innerHTML = `<a href="${product.url}" target="_blank">${product.url} <i data-lucide="external-link" class="lucide-small"></i></a>`;
    info.appendChild(strong);
    info.appendChild(link);

    const controls = document.createElement('div');
    controls.className = 'd-flex align-items-center';
    controls.innerHTML = `
      <input type="time" class="form-control form-control-sm me-2 sub-start" value="${sub.start_time || '00:00'}">
      <input type="time" class="form-control form-control-sm me-2 sub-end" value="${sub.end_time || '23:59'}">
      <button class="btn btn-sm btn-outline-danger unsub-btn"><i data-lucide="x"></i></button>`;

    wrapper.appendChild(info);
    wrapper.appendChild(controls);
    li.appendChild(wrapper);
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
    link.innerHTML = `<a href="${product.url}" target="_blank">${product.url} <i data-lucide="external-link" class="lucide-small"></i></a>`;
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
      if (product) subscribedList.appendChild(createSubscribedItem(product, sub));
    }
    products.forEach(p => {
      if (!subscribedMap.has(p.id)) allList.appendChild(createAllProductItem(p));
    });
    if (window.lucide) window.lucide.createIcons();
    filterProducts(searchInput.value || '');
  }

  async function subscribe(productId) {
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
    }
  }

  async function unsubscribe(productId) {
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
    }
  }

  async function updateTimes(productId, start, end) {
    try {
      const res = await fetchAPI('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipient.id, product_id: productId, start_time: start, end_time: end })
      });
      subscribedMap.set(productId, res);
    } catch (err) {
      alert(err.message || 'Failed to update times');
    }
  }

  subscribedList.addEventListener('click', e => {
    const btn = e.target.closest('.unsub-btn');
    if (!btn) return;
    const li = btn.closest('li[data-product-id]');
    unsubscribe(li.dataset.productId);
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
    const items = allList.querySelectorAll('li');
    const lower = term.toLowerCase();
    items.forEach(item => {
      const name = item.dataset.name || '';
      item.style.display = name.includes(lower) ? '' : 'none';
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => filterProducts(searchInput.value));
  }

  render();
}

document.addEventListener('DOMContentLoaded', initUserSubscriptionsUI);
