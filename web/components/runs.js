// JSZip is loaded globally via a script tag in index.html
import {API_RUNS, API_RUN, API_LOGS, API_ARTIFACT} from './config.js';
import {cleanLogText, formatRunDate, getStatusBadge} from './utils.js';

export async function fetchRuns() {
  const acc = document.getElementById('runsAccordion');
  let skeletonHTML = '';
  for (let i = 0; i < 3; i++) {
    skeletonHTML += `
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
  acc.innerHTML = skeletonHTML;
  try {
    const res = await fetch(API_RUNS);
    if (!res.ok) {
      acc.innerHTML = `<div class="text-danger">Error fetching runs: ${res.status} ${res.statusText}</div>`;
      return;
    }
    const data = await res.json();
    if (!data.runs || !data.runs.length) {
      acc.innerHTML = '<div class="text-muted">No data</div>';
      return;
    }
    acc.innerHTML = '';
    data.runs.forEach((r, idx) => {
      const item = document.createElement('div');
      item.className = 'accordion-item';
      const headingId = `heading${idx}`;
      const collapseId = `collapse${idx}`;
      const formattedDate = formatRunDate(r.created_at);
      const badge = getStatusBadge(r.status, r.conclusion);
      item.innerHTML = `
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
      acc.appendChild(item);
    });

    acc.querySelectorAll('.accordion-collapse').forEach(col => {
      const numericalIndex = col.id.replace('collapse', '');
      col.addEventListener('show.bs.collapse', async event => {
        const currentCollapse = event.target;
        if (currentCollapse.dataset.overviewLoaded) return;
        const runId = currentCollapse.dataset.runId;
        const runUrl = currentCollapse.dataset.runUrl;
        const overviewTabPane = currentCollapse.querySelector(`#overview-${numericalIndex}`);
        overviewTabPane.innerHTML = 'Loading overview...';
        try {
          const r = await fetch(`${API_RUN}?id=${runId}`);
          if (!r.ok) throw new Error(`Failed to fetch run details: ${r.status}`);
          const info = await r.json();
          const githubLink = info.html_url || runUrl;
          let html = `<p><a href="${githubLink}" target="_blank" rel="noopener noreferrer">View on GitHub</a></p>`;
          html += `<p><strong>Status:</strong> ${info.status || (info.step ? info.step.status : 'N/A')}</p>`;
          html += `<p><strong>Conclusion:</strong> ${info.conclusion || (info.step ? info.step.conclusion : 'N/A')}</p>`;
          const started = info.started_at || (info.step ? info.step.started_at : null);
          html += `<p><strong>Started:</strong> ${started ? formatRunDate(started) : 'N/A'}</p>`;
          const completed = info.completed_at || (info.step ? info.step.completed_at : null);
          html += `<p><strong>Completed:</strong> ${completed ? formatRunDate(completed) : 'N/A'}</p>`;
          overviewTabPane.innerHTML = html;
          overviewTabPane.classList.add('fade-in-content');
          currentCollapse.dataset.overviewLoaded = 'true';
        } catch (err) {
          overviewTabPane.innerHTML = `<div class="text-danger">Error loading overview: ${err.message}</div>`;
        }
      });

      const logsTabTrigger = col.querySelector(`#logs-tab-${numericalIndex}`);
      const logsTabPane = col.querySelector(`#logs-${numericalIndex}`);
      if (logsTabTrigger && logsTabPane) {
        logsTabTrigger.addEventListener('shown.bs.tab', async () => {
          if (logsTabPane.dataset.loaded) return;
          logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs...">Loading logs...`;
          const runIdForLog = col.dataset.runId;
          try {
            const logRes = await fetch(`${API_LOGS}?id=${runIdForLog}`);
            if (!logRes.ok) throw new Error(`Failed to fetch logs: ${logRes.status}`);
            const blob = await logRes.blob();
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
            const cleanedLogText = cleanLogText(rawLogText);
            logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs..."><pre class="bg-light border mt-2 p-2 small fade-in-content">${cleanedLogText}</pre>`;
            logsTabPane.dataset.loaded = 'true';
          } catch (err) {
            logsTabPane.innerHTML = `<input type="text" class="form-control form-control-sm my-2" placeholder="Search logs..."><div class="text-danger">Error loading logs: ${err.message}</div>`;
          }
        }, { once: true });
      }

      const artifactsTabTrigger = col.querySelector(`#artifacts-tab-${numericalIndex}`);
      const artifactsTabPane = col.querySelector(`#artifacts-${numericalIndex}`);
      if (artifactsTabTrigger && artifactsTabPane) {
        artifactsTabTrigger.addEventListener('shown.bs.tab', async () => {
          if (artifactsTabPane.dataset.loaded) return;
          artifactsTabPane.textContent = 'Loading artifacts...';
          const runIdForArtifact = col.dataset.runId;
          try {
            const r = await fetch(`${API_RUN}?id=${runIdForArtifact}`);
            if (!r.ok) throw new Error(`Failed to fetch run details for artifacts: ${r.status}`);
            const info = await r.json();
            if (info.artifacts && info.artifacts.length) {
              const carouselId = `carousel-${runIdForArtifact}`;
              let itemsHtml = '';
              let isFirstItem = true;
              let imageCount = 0;
              for (const art of info.artifacts) {
                const zipRes = await fetch(`${API_ARTIFACT}?id=${art.id}`);
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
        }, { once: true });
      }
    });
  } catch (e) {
    acc.innerHTML = `<div class="text-danger">Error loading runs. Details: ${e.message}</div>`;
  }
}
