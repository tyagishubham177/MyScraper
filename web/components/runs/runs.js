// JSZip is loaded globally via a script tag in index.html
import {API_RUNS, API_RUN, API_LOGS, API_ARTIFACT} from '../config/config.js';
import {cleanLogText, formatRunDate, getStatusBadge, extractCheckStockLog, fetchAPI} from '../utils/utils.js';

const logCache = new Map();

async function fetchRunLogBlob(runId) {
  if (logCache.has(runId)) {
    return logCache.get(runId);
  }
  const token = localStorage.getItem('authToken');
  const response = await fetch(`${API_LOGS}?id=${runId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch logs: ${response.status}`);
  }
  const blob = await response.blob();
  logCache.set(runId, blob);
  return blob;
}

function parseScraperDecisionsFromLog(logText) {
  if (!logText) return [];
  const lines = logText.split('\n');
  const decisions = [];
  // Regex for IN STOCK: ✅ Product '(.*?)' \(URL: (.*?)\) is IN STOCK.
  const inStockRegex = /✅ Product '(.*?)' \(URL: .*?\) is IN STOCK\./;
  // Regex for OUT OF STOCK: ❌ Product '(.*?)' \(URL: (.*?)\) is OUT OF STOCK.
  const outOfStockRegex = /❌ Product '(.*?)' \(URL: .*?\) is OUT OF STOCK\./;

  for (const line of lines) {
    const inStockMatch = line.match(inStockRegex);
    if (inStockMatch) {
      decisions.push({ name: inStockMatch[1], status: 'IN STOCK' });
      continue; // Check next line
    }

    const outOfStockMatch = line.match(outOfStockRegex);
    if (outOfStockMatch) {
      decisions.push({ name: outOfStockMatch[1], status: 'OUT OF STOCK' });
    }
  }
  return decisions;
}

function createSkeleton(count = 3) {
  let html = '';
  for (let i = 0; i < count; i++) {
    html += `
      <div class="accordion-item">
        <h2 class="accordion-header">
          <button class="accordion-button collapsed skeleton-item" type="button" disabled>
            <span class="skeleton-loader skeleton-icon-placeholder"></span>
            <span class="skeleton-loader skeleton-text" style="width: 40%;"></span>
            <span class="ms-auto skeleton-loader skeleton-badge" style="width: 20%;"></span>
          </button>
        </h2>
      </div>`;
  }
  return html;
}

function createAccordionItem(r, idx) {
  const headingId = `heading${idx}`;
  const collapseId = `collapse${idx}`;
  const formattedDate = formatRunDate(r.created_at);
  const badge = getStatusBadge(r.status, r.conclusion);
  return `
    <h2 class="accordion-header" id="${headingId}">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="false" aria-controls="${collapseId}">
        <i data-lucide="calendar-days" class="me-2"></i> ${formattedDate} ${badge}
      </button>
    </h2>
    <div id="${collapseId}" class="accordion-collapse collapse" aria-labelledby="${headingId}" data-run-id="${r.id}" data-run-url="${r.url}" data-run-created-at="${r.created_at}" data-run-conclusion="${r.conclusion || r.status}">
      <div class="accordion-body">
        <ul class="nav nav-tabs" id="runTabs-${idx}" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="overview-tab-${idx}" data-bs-toggle="tab" data-bs-target="#overview-${idx}" type="button" role="tab" aria-controls="overview-${idx}" aria-selected="true">Overview</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="logs-tab-${idx}" data-bs-toggle="tab" data-bs-target="#logs-${idx}" type="button" role="tab" aria-controls="logs-${idx}" aria-selected="false">Logs</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="artifacts-tab-${idx}" data-bs-toggle="tab" data-bs-target="#artifacts-${idx}" type="button" role="tab" aria-controls="artifacts-${idx}" aria-selected="false">Artifacts</button>
          </li>
        </ul>
        <div class="tab-content pt-2" id="runTabsContent-${idx}">
          <div class="tab-pane fade show active p-2" id="overview-${idx}" role="tabpanel" aria-labelledby="overview-tab-${idx}">Loading overview...</div>
          <div class="tab-pane fade p-2" id="logs-${idx}" role="tabpanel" aria-labelledby="logs-tab-${idx}">
            <input type="text" class="form-control form-control-sm my-2" placeholder="Search logs...">Loading logs...
          </div>
          <div class="tab-pane fade p-2" id="artifacts-${idx}" role="tabpanel" aria-labelledby="artifacts-tab-${idx}">Loading artifacts...</div>
        </div>
      </div>
    </div>`;
}

async function fetchScraperDecisions(runId) {
  const blob = await fetchRunLogBlob(runId);
  const zip = await JSZip.loadAsync(blob);
  let rawLogText = '';
  let foundLogFile = false;
  const normalizedStepName = 'runstockchecker';
  for (const fname of Object.keys(zip.files)) {
    const normalizedFname = fname.toLowerCase().replace(/[\s_]+/g, '');
    if (normalizedFname.includes(normalizedStepName)) {
      rawLogText = await zip.files[fname].async('string');
      foundLogFile = true;
      break;
    }
  }
  if (!foundLogFile) {
    for (const fname of Object.keys(zip.files)) {
      const lower = fname.toLowerCase();
      if (lower.includes('run_stock_checker') || lower.includes('stock checker') || lower.includes('stock-checker')) {
        rawLogText = await zip.files[fname].async('string');
        foundLogFile = true;
        break;
      }
    }
  }
  if (!foundLogFile) {
    const firstFile = Object.keys(zip.files)[0];
    rawLogText = firstFile ? await zip.files[firstFile].async('string') : 'No log file found in archive.';
  }
  const trimmed = extractCheckStockLog(rawLogText);
  const cleaned = cleanLogText(trimmed);
  return parseScraperDecisionsFromLog(cleaned);
}

function appendSummary(overviewTabPane, decisions) {
  let summaryHtml = '<h4 class="mt-3">Product Stock Summary:</h4>';
  if (decisions.length > 0) {
    summaryHtml += '<div>';
    decisions.forEach(decision => {
      let statusHtml = '';
      if (decision.status === 'IN STOCK') {
        statusHtml = `<span style="color: green;"><i data-lucide="check-circle" class="me-1"></i>IN STOCK</span>`;
      } else if (decision.status === 'OUT OF STOCK') {
        statusHtml = `<span style="color: red;"><i data-lucide="x-circle" class="me-1"></i>OUT OF STOCK</span>`;
      } else {
        statusHtml = `<span>${decision.status}</span>`;
      }
      summaryHtml += `<div class="mb-2"><span>${decision.name}: </span><strong>${statusHtml}</strong></div>`;
    });
    summaryHtml += '</div>';
    overviewTabPane.innerHTML += summaryHtml;
  } else {
    overviewTabPane.innerHTML += '<p class="mt-3 text-muted">No product stock decisions found in logs.</p>';
  }
  overviewTabPane.dataset.productSummaryLoaded = 'true';
  if (decisions.length > 0) {
    setTimeout(() => {
      if (typeof lucide !== 'undefined' && lucide && typeof lucide.replace === 'function') {
        lucide.replace();
      }
    }, 50);
  }
}

async function loadOverview(col, idx) {
  if (col.dataset.overviewLoaded) return;
  const runId = col.dataset.runId;
  const runUrl = col.dataset.runUrl;
  const overviewTabPane = col.querySelector(`#overview-${idx}`);
  overviewTabPane.innerHTML = 'Loading overview...';
  try {
    const info = await fetchAPI(`${API_RUN}?id=${runId}`);
    const githubLink = info.html_url || runUrl;
    let html = `<p><a href="${githubLink}" target="_blank" rel="noopener noreferrer">View on GitHub</a></p>`;
    html += `<p><strong>Status:</strong> ${info.status || (info.step ? info.step.status : 'N/A')}</p>`;
    html += `<p><strong>Conclusion:</strong> ${info.conclusion || (info.step ? info.step.conclusion : 'N/A')}</p>`;
    const started = info.started_at || (info.step ? info.step.started_at : null);
    html += `<p><strong>Started:</strong> ${started ? formatRunDate(started) : 'N/A'}</p>`;
    const completed = info.completed_at || (info.step ? info.step.completed_at : null);
    html += `<p><strong>Completed:</strong> ${completed ? formatRunDate(completed) : 'N/A'}</p>`;
    overviewTabPane.innerHTML = html;
    col.dataset.overviewLoaded = 'true';

    if (!overviewTabPane.dataset.productSummaryLoaded) {
      try {
        const decisions = await fetchScraperDecisions(runId);
        appendSummary(overviewTabPane, decisions);
      } catch (logErr) {
        console.error(`Error loading or parsing log for product summary (run ${runId}):`, logErr);
        overviewTabPane.innerHTML += `<p class="text-warning mt-3">Could not load product stock summary: ${logErr.message}</p>`;
        overviewTabPane.dataset.productSummaryLoaded = "true";
      }
    }
    overviewTabPane.classList.add('fade-in-content');
  } catch (err) {
    overviewTabPane.innerHTML = `<div class="text-danger">Error loading overview: ${err.message}</div>`;
    overviewTabPane.classList.add('fade-in-content');
  }
}

async function loadLogs(col, idx) {
  const logsTabPane = col.querySelector(`#logs-${idx}`);
  if (logsTabPane.dataset.loaded) return;
  logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs...">Loading logs...`;
  const runIdForLog = col.dataset.runId;
  try {
    const blob = await fetchRunLogBlob(runIdForLog);
    const zip = await JSZip.loadAsync(blob);
    let rawLogText = 'No relevant log file found.';
    let foundLog = false;
    const normalizedStepName = 'runstockchecker';
    for (const fname of Object.keys(zip.files)) {
      const lowerFname = fname.toLowerCase();
      const normalizedFname = lowerFname.replace(/[\s_]+/g, '');
      if (normalizedFname.includes(normalizedStepName)) {
        rawLogText = await zip.files[fname].async('string');
        foundLog = true;
        break;
      }
    }
    if (!foundLog) {
      for (const fname of Object.keys(zip.files)) {
        const lowerFname = fname.toLowerCase();
        if (lowerFname.includes('run_stock_checker') || lowerFname.includes('stock checker') || lowerFname.includes('stock-checker')) {
          rawLogText = await zip.files[fname].async('string');
          foundLog = true;
          break;
        }
      }
    }
    if (!foundLog) {
      const firstFile = Object.keys(zip.files)[0];
      if (firstFile) {
        rawLogText = await zip.files[firstFile].async('string');
      }
    }
    const trimmed = extractCheckStockLog(rawLogText);
    const cleanedLogText = cleanLogText(trimmed);
    logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs..."><pre class="bg-light border mt-2 p-2 small fade-in-content"></pre>`;
    const logLines = cleanedLogText.split('\n');
    const preElement = logsTabPane.querySelector('pre');
    preElement.textContent = cleanedLogText;

    const searchInput = logsTabPane.querySelector('input[type="text"]');
    searchInput.addEventListener('input', () => {
      const searchTerm = searchInput.value.toLowerCase();
      if (!searchTerm) {
        preElement.textContent = cleanedLogText;
        return;
      }
      const filteredLines = logLines.filter(line => line.toLowerCase().includes(searchTerm));
      preElement.textContent = filteredLines.join('\n');
    });

    logsTabPane.dataset.loaded = 'true';
  } catch (err) {
    logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs..."><div class="text-danger">Error loading logs: ${err.message}</div>`;
  }
}

async function loadArtifacts(col, idx) {
  const artifactsTabPane = col.querySelector(`#artifacts-${idx}`);
  if (artifactsTabPane.dataset.loaded) return;
  artifactsTabPane.textContent = 'Loading artifacts...';
  const runIdForArtifact = col.dataset.runId;
  try {
    const info = await fetchAPI(`${API_RUN}?id=${runIdForArtifact}`);
    if (info.artifacts && info.artifacts.length) {
      const carouselId = `carousel-${runIdForArtifact}`;
      let itemsHtml = '';
      let isFirstItem = true;
      let imageCount = 0;
      const token = localStorage.getItem('authToken');
      for (const art of info.artifacts) {
        const zipRes = await fetch(`${API_ARTIFACT}?id=${art.id}`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (zipRes.ok) {
          const blob = await zipRes.blob();
          const zip = await JSZip.loadAsync(blob);
          for (const fname of Object.keys(zip.files)) {
            if (fname.toLowerCase().endsWith('.png')) {
              const data = await zip.files[fname].async('base64');
              itemsHtml += `<div class="carousel-item ${isFirstItem ? 'active' : ''}"><img src="data:image/png;base64,${data}" class="d-block w-100"></div>`;
              isFirstItem = false;
              imageCount += 1;
            }
          }
        }
      }
      if (itemsHtml) {
        artifactsTabPane.innerHTML = `
          <div id="${carouselId}" class="carousel slide mt-3 fade-in-content" data-bs-touch="true">
            <div class="carousel-inner">${itemsHtml}</div>
            <button class="carousel-control-prev" type="button" data-bs-target="#${carouselId}" data-bs-slide="prev">
              <span class="carousel-control-prev-icon" aria-hidden="true"></span><span class="visually-hidden">Previous</span>
            </button>
            <button class="carousel-control-next" type="button" data-bs-target="#${carouselId}" data-bs-slide="next">
              <span class="carousel-control-next-icon" aria-hidden="true"></span><span class="visually-hidden">Next</span>
            </button>
            <div class="carousel-counter"></div>
          </div>`;
        const carouselEl = artifactsTabPane.querySelector(`#${carouselId}`);
        const counterEl = carouselEl.querySelector('.carousel-counter');
        const updateCounter = () => {
          const items = carouselEl.querySelectorAll('.carousel-item');
          const active = carouselEl.querySelector('.carousel-item.active');
          const index = Array.from(items).indexOf(active) + 1;
          counterEl.textContent = `${index}/${imageCount}`;
        };
        updateCounter();
        carouselEl.addEventListener('slid.bs.carousel', updateCounter);
      } else {
        artifactsTabPane.innerHTML = '<p class="fade-in-content">No PNG artifacts found.</p>';
      }
    } else {
      artifactsTabPane.innerHTML = '<p class="fade-in-content">No artifacts associated with this run.</p>';
    }
    artifactsTabPane.dataset.loaded = 'true';
  } catch (err) {
    artifactsTabPane.innerHTML = `<div class="text-danger">Error loading artifacts: ${err.message}</div>`;
  }
}

export async function fetchRuns() {
  const acc = document.getElementById('runsAccordion');
  acc.innerHTML = createSkeleton();
  try {
    const data = await fetchAPI(API_RUNS);
    if (!data.runs || !data.runs.length) {
      acc.innerHTML = '<div class="text-muted">No data</div>';
      return;
    }
    acc.innerHTML = '';
    data.runs.forEach((r, idx) => {
      const item = document.createElement('div');
      item.className = 'accordion-item';
      item.innerHTML = createAccordionItem(r, idx);
      acc.appendChild(item);
    });

    acc.querySelectorAll('.accordion-collapse').forEach(col => {
      const i = col.id.replace('collapse', '');
      col.addEventListener('show.bs.collapse', () => loadOverview(col, i));

      const logsTabTrigger = col.querySelector(`#logs-tab-${i}`);
      if (logsTabTrigger) {
        logsTabTrigger.addEventListener('shown.bs.tab', () => loadLogs(col, i), { once: true });
      }

      const artifactsTabTrigger = col.querySelector(`#artifacts-tab-${i}`);
      if (artifactsTabTrigger) {
        artifactsTabTrigger.addEventListener('shown.bs.tab', () => loadArtifacts(col, i), { once: true });
      }
    });
  } catch (e) {
    acc.innerHTML = `<div class="text-danger">Error loading runs. Details: ${e.message}</div>`;
  }
}

// Export internal helpers for testing
export {
  parseScraperDecisionsFromLog,
  createSkeleton,
  createAccordionItem,
  appendSummary,
  fetchScraperDecisions,
  loadOverview,
  loadLogs,
  loadArtifacts
};
