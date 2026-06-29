// == KEV Vulnerability Dashboard Script ==
// Loads, filters, sorts, and displays enriched CVE data

let tableData = [];
let fullData = [];
let currentPage = 1;
const pageSize = 25;

function getAttackVector(cvssVector) {
  const vector = fieldText(cvssVector);
  if (!vector) return null;
  const match = vector.match(/AV:([NALP])/);
  return match ? match[1] : null;
}

// Load dashboard data from the Worker/R2 endpoint.
fetch('https://kev-dash-r2-test.austm999.workers.dev/kev_enriched.json')
  .then(res => {
    if (!res.ok) {
      throw new Error(`Data request failed with status ${res.status}`);
    }
    return res.json();
  })
  .then(data => {
    fullData = normalizeDashboardData(data);
    tableData = fullData;
    updateSummaryMetrics(fullData);
    renderTable();
  })
  .catch(error => {
    console.error('Error loading dashboard data:', error);
    showDashboardLoadError();
  });

function normalizeDashboardData(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.vulnerabilities)) return data.vulnerabilities;
  if (data && Array.isArray(data.data)) return data.data;
  return [];
}

function setMetricText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.classList.remove("is-loading", "is-error");
    element.removeAttribute("aria-label");
    element.textContent = Number(value || 0).toLocaleString();
  }
}

function setMetricError(id) {
  const element = document.getElementById(id);
  if (element) {
    element.classList.remove("is-loading");
    element.classList.add("is-error");
    element.setAttribute("aria-label", "Metric unavailable");
    element.textContent = "Error";
  }
}

function isRecentlyAdded(dateAdded) {
  if (!dateAdded) return false;

  const addedDate = new Date(dateAdded);
  if (isNaN(addedDate)) return false;

  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  return addedDate >= thirtyDaysAgo;
}

function hasKnownRansomwareUse(value) {
  if (!value) return false;

  const normalized = value.toString().trim().toLowerCase();
  return normalized === "known" || normalized === "yes" || normalized === "true";
}

function updateSummaryMetrics(data) {
  const records = normalizeDashboardData(data);

  setMetricText("metricTotal", records.length);
  setMetricText("metricCritical", records.filter(item => getSeverity(item) === "CRITICAL").length);
  setMetricText("metricHigh", records.filter(item => getSeverity(item) === "HIGH").length);
  setMetricText("metricNetwork", records.filter(item => fieldText(item.cvssVector).includes("AV:N")).length);
  setMetricText("metricRansomware", records.filter(item => hasKnownRansomwareUse(item.knownRansomwareCampaignUse)).length);
  setMetricText("metricRecent", records.filter(item => isRecentlyAdded(item.dateAdded)).length);
}

function getSeverity(item) {
  return item && item.cvssSeverity ? item.cvssSeverity.toString().trim().toUpperCase() : "";
}

function fieldText(value) {
  return value == null ? "" : value.toString();
}

function formatFixed(value, digits) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : "N/A";
}

function formatPercent(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${(number * 100).toFixed(2)}%` : "N/A";
}

function updateRecordCount() {
  const recordCount = document.getElementById("recordCount");
  if (recordCount) {
    const count = Array.isArray(tableData) ? tableData.length : 0;
    recordCount.classList.remove("is-loading", "is-error");
    recordCount.textContent = `${count.toLocaleString()} ${count === 1 ? "record" : "records"}`;
  }
}

function showDashboardLoadError() {
  [
    "metricTotal",
    "metricCritical",
    "metricHigh",
    "metricNetwork",
    "metricRansomware",
    "metricRecent",
  ].forEach(setMetricError);

  const recordCount = document.getElementById("recordCount");
  if (recordCount) {
    recordCount.classList.remove("is-loading");
    recordCount.classList.add("is-error");
    recordCount.textContent = "Data unavailable";
  }
}

function renderTable() {
  const tbody = document.querySelector("#kevTable tbody");
  tbody.innerHTML = "";
  updateRecordCount();

  const totalPages = Math.max(1, Math.ceil(tableData.length / pageSize));
  const start = (currentPage - 1) * pageSize;
  const end = start + pageSize;
  const pageData = tableData.slice(start, end);

  pageData.forEach(item => {
    const row = document.createElement("tr");
    const cvssVector = fieldText(item.cvssVector);
    const hasCvssVector = cvssVector && cvssVector !== "N/A";

    const cvssCellContent = item.cvssScore !== "N/A" && item.cvssScore != null
      ? item.cvssScore
      : `<a href="https://nvd.nist.gov/vuln/detail/${item.cveID}" target="_blank" title="View on NVD">N/A</a>`;

    const cvssVersionText = item.cvssVersion && item.cvssVersion !== "N/A"
      ? `<span class="cvss-version">(${item.cvssVersion})</span>`
      : '';

    row.innerHTML = `
      <td>
        <a href="https://nvd.nist.gov/vuln/detail/${item.cveID}" target="_blank">${item.cveID}</a>
        ${item.source !== "NVD" ? '<span class="kev-pill">KEV</span>' : ''}
      </td>
      <td>
        ${item.vendor ? `<div class="vendor-name">${item.vendor}</div>` : ''}
        ${item.product ? `<div class="product-name">${item.product}</div>` : ''}
      </td>
      <td>${item.cvssSeverity || ''}</td>
      <td title="${hasCvssVector ? cvssVector : ''}">
        ${cvssCellContent} ${cvssVersionText}
      </td>
      <td>${item.epssScore !== "N/A" && item.epssScore != null ? formatFixed(item.epssScore, 4) : 'N/A'}</td>
      <td>${item.epssPercentile !== "N/A" && item.epssPercentile != null ? formatPercent(item.epssPercentile) : 'N/A'}</td>
      <td>${item.dateAdded || ''}</td>
      <td class="${item.dueDate && new Date(item.dueDate) < new Date() ? 'overdue' : ''}">
        ${item.dueDate || ''}
      </td>
      
      <td class="attack-vector">
        <div class="attack-content">
          ${hasCvssVector ? cvssVector : 'N/A'}
        </div>
        ${hasCvssVector && cvssVector.length > 20
          ? '<span class="toggle-link">Show more</span>'
          : ''}
      </td>
      
      <td>
        <div class="description-cell">
          <div class="desc-content">
            ${item.description || ''}
          </div>
          ${item.description && item.description.length > 120
            ? '<span class="toggle-link">Show more</span>'
            : ''}
        </div>
      </td>

    `;

    tbody.appendChild(row);
  });

  document.getElementById("pageIndicator").textContent = `Page ${currentPage} of ${totalPages}`;
  document.getElementById("prevPage").disabled = currentPage === 1;
  document.getElementById("nextPage").disabled = currentPage === totalPages;
}

document.getElementById("searchBox").addEventListener("input", e => {
  const search = e.target.value.toLowerCase();
  const filtered = fullData.filter(item =>
    fieldText(item.cveID).toLowerCase().includes(search) ||
    fieldText(item.product).toLowerCase().includes(search) ||
    fieldText(item.vendor).toLowerCase().includes(search)
  );
  tableData = filtered;
  currentPage = 1;
  renderTable();
});

document.getElementById("severityFilter").addEventListener("change", applyFilters);
document.getElementById("dateFilter").addEventListener("change", applyFilters);
document.getElementById("attackVectorFilter").addEventListener("change", applyFilters);

function applyFilters() {
  const severityValue = document.getElementById("severityFilter").value;
  const dateValue = document.getElementById("dateFilter").value;
  const attackVectorValue = document.getElementById("attackVectorFilter").value;
  const now = new Date();

  tableData = fullData.filter(item => {
    const matchesSeverity = severityValue ? getSeverity(item) === severityValue : true;

    let matchesDate = true;
    if (dateValue) {
      const daysAgo = parseInt(dateValue);
      const itemDate = item.dateAdded ? new Date(item.dateAdded) : null;
      if (itemDate && !isNaN(itemDate)) {
        const cutoff = new Date(now.getTime() - daysAgo * 86400000);
        matchesDate = itemDate >= cutoff;
      } else {
        matchesDate = false;
      }
    }

    const av = getAttackVector(item.cvssVector);
    const matchesAV = attackVectorValue ? av === attackVectorValue : true;

    return matchesSeverity && matchesDate && matchesAV;
  });

  currentPage = 1;
  renderTable();
}

let sortDirections = {};

function sortTable(columnIndex) {
  const keyMap = {
    0: "cveID",
    1: "product",
    2: "cvssSeverity",
    3: "cvssScore",
    4: "epssScore",
    5: "epssPercentile",
    6: "dateAdded",
    7: "dueDate",
  };

  const key = keyMap[columnIndex];
  sortDirections[key] = !sortDirections[key];
  const direction = sortDirections[key] ? 1 : -1;

  document.querySelectorAll(".sort-indicator").forEach(el => el.textContent = "");
  const arrow = ["cvssScore", "epssScore", "epssPercentile", "dateAdded", "dueDate"].includes(key)
    ? (direction === 1 ? "▼" : "▲")
    : (direction === 1 ? "▲" : "▼");
  document.getElementById(`sort-${columnIndex}`).textContent = arrow;

  const sorted = [...tableData].sort((a, b) => {
    const valA = a[key];
    const valB = b[key];

    if (["cvssScore", "epssScore", "epssPercentile"].includes(key)) {
      const numA = parseFloat(valA) || 0;
      const numB = parseFloat(valB) || 0;
      return (numA - numB) * direction;
    }

    if (key === "dueDate" || key === "dateAdded") {
      const dateA = new Date(valA);
      const dateB = new Date(valB);
      return (dateA - dateB) * direction;
    }

    const strA = valA ? valA.toString().toLowerCase() : "";
    const strB = valB ? valB.toString().toLowerCase() : "";
    return strA.localeCompare(strB) * direction;
  });

  tableData = sorted;
  currentPage = 1;
  renderTable();
}

function exportToCSV() {
  const headers = ["CVE ID", "Product", "Severity", "CVSS", "Description", "Due Date"];
  const rows = tableData.map(item => [
    item.cveID, item.product, item.cvssSeverity,
    item.cvssScore, item.description, item.dueDate
  ]);
  const csv = [headers, ...rows].map(row => row.join(",")).join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "kev_enriched.csv";
  a.click();
  URL.revokeObjectURL(url);
}

document.getElementById("darkModeToggle").addEventListener("change", e => {
  document.body.classList.toggle("dark", e.target.checked);
});

document.getElementById("prevPage").addEventListener("click", () => {
  if (currentPage > 1) {
    currentPage--;
    renderTable();
    document.getElementById("pagination").scrollIntoView({ behavior: "smooth", block: "center" });
  }
});

document.getElementById("nextPage").addEventListener("click", () => {
  const totalPages = Math.max(1, Math.ceil(tableData.length / pageSize));
  if (currentPage < totalPages) {
    currentPage++;
    renderTable();
    document.getElementById("pagination").scrollIntoView({ behavior: "smooth", block: "center" });
  }
});

document.getElementById("toggleLegend").addEventListener("click", () => {
  document.getElementById("legendBox").classList.toggle("hidden");
});

document.addEventListener("click", function (e) {
  if (e.target.classList.contains("toggle-link")) {
    const content = e.target.previousElementSibling;

    content.classList.toggle("expanded");
    e.target.textContent = content.classList.contains("expanded")
      ? "Show less"
      : "Show more";
  }
});
