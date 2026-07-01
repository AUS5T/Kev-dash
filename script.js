// == KEV Vulnerability Dashboard Script ==
// Loads, filters, sorts, and displays enriched CVE data

let tableData = [];
let fullData = [];
let currentPage = 1;
let actorActivityData = [];
let filteredActorActivityData = [];
const pageSize = 25;
const themeStorageKey = "patchsignal-theme";
const columnVisibilityStorageKey = "patchsignal-visible-columns";
const lastUpdatedUrl = "https://kev-dash-r2-test.austm999.workers.dev/last_updated.txt";
const optionalColumns = [
  { id: "epssScore", index: 4 },
  { id: "epssPercentile", index: 5 },
  { id: "dateAdded", index: 6 },
  { id: "dueDate", index: 7 },
];

initTheme();
initDashboard();
initActorActivity();

function initTheme() {
  const savedTheme = getSavedTheme();
  const useDark = savedTheme === "dark";

  document.documentElement.classList.toggle("dark", useDark);
  document.body.classList.toggle("dark", useDark);

  document.querySelectorAll(".theme-toggle").forEach(toggle => {
    toggle.checked = useDark;
    toggle.addEventListener("change", e => {
      const darkEnabled = e.target.checked;
      saveTheme(darkEnabled ? "dark" : "light");
      document.documentElement.classList.toggle("dark", darkEnabled);
      document.body.classList.toggle("dark", darkEnabled);

      document.querySelectorAll(".theme-toggle").forEach(otherToggle => {
        otherToggle.checked = darkEnabled;
      });
    });
  });
}

function getSavedTheme() {
  try {
    return localStorage.getItem(themeStorageKey);
  } catch (error) {
    return null;
  }
}

function saveTheme(theme) {
  try {
    localStorage.setItem(themeStorageKey, theme);
  } catch (error) {}
}

function getVisibleColumnIds() {
  const defaultVisibleColumns = optionalColumns.map(column => column.id);

  try {
    const savedValue = localStorage.getItem(columnVisibilityStorageKey);
    if (!savedValue) return defaultVisibleColumns;

    const parsed = JSON.parse(savedValue);
    if (!Array.isArray(parsed)) return defaultVisibleColumns;

    return parsed.filter(columnId => optionalColumns.some(column => column.id === columnId));
  } catch (error) {
    return defaultVisibleColumns;
  }
}

function saveVisibleColumnIds(visibleColumnIds) {
  try {
    localStorage.setItem(columnVisibilityStorageKey, JSON.stringify(visibleColumnIds));
  } catch (error) {}
}

function initializeColumnControls() {
  const columnToggles = Array.from(document.querySelectorAll(".column-toggle"));
  if (!columnToggles.length) return;

  const visibleColumnIds = getVisibleColumnIds();

  columnToggles.forEach(toggle => {
    toggle.checked = visibleColumnIds.includes(toggle.dataset.columnId);
    toggle.addEventListener("change", () => {
      const selectedColumnIds = columnToggles
        .filter(columnToggle => columnToggle.checked)
        .map(columnToggle => columnToggle.dataset.columnId);

      saveVisibleColumnIds(selectedColumnIds);
      applyColumnVisibility();
    });
  });

  const showAllButton = document.getElementById("showAllColumns");
  if (showAllButton) {
    showAllButton.addEventListener("click", () => {
      columnToggles.forEach(toggle => {
        toggle.checked = true;
      });

      saveVisibleColumnIds(optionalColumns.map(column => column.id));
      applyColumnVisibility();
    });
  }

  applyColumnVisibility();
}

function applyColumnVisibility() {
  const table = document.getElementById("kevTable");
  if (!table) return;

  const visibleColumnIds = getVisibleColumnIds();
  const cols = table.querySelectorAll("colgroup col");
  const headerCells = table.tHead && table.tHead.rows[0]
    ? table.tHead.rows[0].cells
    : [];
  const rows = table.tBodies[0] ? table.tBodies[0].rows : [];

  optionalColumns.forEach(column => {
    const shouldShow = visibleColumnIds.includes(column.id);
    const displayValue = shouldShow ? "" : "none";

    if (cols[column.index]) {
      cols[column.index].style.display = displayValue;
    }

    if (headerCells[column.index]) {
      headerCells[column.index].style.display = displayValue;
    }

    Array.from(rows).forEach(row => {
      if (row.cells[column.index]) {
        row.cells[column.index].style.display = displayValue;
      }
    });
  });
}

function initDashboard() {
  if (!document.getElementById("kevTable")) return;

  initializeColumnControls();
  loadLastKevCheckTimestamp();
  loadDashboardData();

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
}

function initActorActivity() {
  if (!document.getElementById("actorActivityTable")) return;

  const searchBox = document.getElementById("actorSearchBox");
  const confidenceFilter = document.getElementById("actorConfidenceFilter");
  const actorTypeFilter = document.getElementById("actorTypeFilter");

  [searchBox, confidenceFilter, actorTypeFilter].forEach(control => {
    if (control) {
      control.addEventListener("input", applyActorActivityFilters);
      control.addEventListener("change", applyActorActivityFilters);
    }
  });

  loadActorActivityData();
}

function loadActorActivityData() {
  fetch("data/actor_cve_links.json")
    .then(response => {
      if (!response.ok) {
        throw new Error(`Actor activity request failed with status ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      actorActivityData = Array.isArray(data) ? data : [];
      filteredActorActivityData = actorActivityData;
      populateActorTypeFilter(actorActivityData);
      applyActorActivityFilters();
    })
    .catch(error => {
      console.error("Error loading actor activity data:", error);
      showActorActivityLoadError();
    });
}

function populateActorTypeFilter(data) {
  const actorTypeFilter = document.getElementById("actorTypeFilter");
  if (!actorTypeFilter) return;

  const currentValue = actorTypeFilter.value;
  const types = Array.from(new Set(data
    .map(item => fieldText(item.actor_type).trim())
    .filter(Boolean)))
    .sort((a, b) => a.localeCompare(b));

  actorTypeFilter.replaceChildren();

  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "All Actor Types";
  actorTypeFilter.appendChild(allOption);

  types.forEach(type => {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type;
    actorTypeFilter.appendChild(option);
  });

  actorTypeFilter.value = types.includes(currentValue) ? currentValue : "";
}

function applyActorActivityFilters() {
  const search = fieldText(document.getElementById("actorSearchBox")?.value).trim().toLowerCase();
  const confidenceValue = fieldText(document.getElementById("actorConfidenceFilter")?.value).trim().toLowerCase();
  const actorTypeValue = fieldText(document.getElementById("actorTypeFilter")?.value).trim();

  filteredActorActivityData = actorActivityData.filter(item => {
    const confidence = normalizedConfidence(item.confidence);
    const matchesConfidence = confidenceValue === "default"
      ? confidence !== "suspected"
      : (!confidenceValue || confidence === confidenceValue);
    const matchesActorType = actorTypeValue ? fieldText(item.actor_type).trim() === actorTypeValue : true;
    const searchableText = [
      item.cve,
      item.actor,
      item.actor_type,
      item.evidence_summary,
    ].map(fieldText).join(" ").toLowerCase();
    const matchesSearch = search ? searchableText.includes(search) : true;

    return matchesConfidence && matchesActorType && matchesSearch;
  });

  renderActorActivityTable();
}

function normalizedConfidence(value) {
  const confidence = fieldText(value).trim().toLowerCase();
  return ["confirmed", "reported", "suspected", "unattributed"].includes(confidence)
    ? confidence
    : "unattributed";
}

function confidenceLabel(value) {
  const confidence = normalizedConfidence(value);
  return confidence.charAt(0).toUpperCase() + confidence.slice(1);
}

function updateActorRecordCount() {
  const recordCount = document.getElementById("actorRecordCount");
  if (!recordCount) return;

  const count = Array.isArray(filteredActorActivityData) ? filteredActorActivityData.length : 0;
  recordCount.classList.remove("is-loading", "is-error");
  recordCount.textContent = `${count.toLocaleString()} ${count === 1 ? "record" : "records"}`;
}

function showActorActivityLoadError() {
  const recordCount = document.getElementById("actorRecordCount");
  if (recordCount) {
    recordCount.classList.remove("is-loading");
    recordCount.classList.add("is-error");
    recordCount.textContent = "Data unavailable";
  }

  const tbody = document.querySelector("#actorActivityTable tbody");
  if (tbody) {
    renderActorActivityMessage(tbody, "Actor activity data is unavailable.");
  }
}

function createSafeSourceLink(item) {
  const sourceName = fieldText(item.source_name).trim() || "Source";
  const sourceUrl = fieldText(item.source_url).trim();
  if (!sourceUrl) {
    return document.createTextNode(sourceName);
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(sourceUrl);
  } catch (error) {
    return document.createTextNode(sourceName);
  }

  if (!["https:", "http:"].includes(parsedUrl.protocol)) {
    return document.createTextNode(sourceName);
  }

  const link = document.createElement("a");
  link.href = parsedUrl.href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = sourceName;
  return link;
}

function createConfidenceCell(value) {
  const cell = document.createElement("td");
  const confidence = normalizedConfidence(value);
  const tag = document.createElement("span");
  tag.className = `detail-tag confidence-${confidence}`;
  tag.textContent = confidenceLabel(confidence);
  cell.appendChild(tag);
  return cell;
}

function renderActorActivityMessage(tbody, message) {
  tbody.replaceChildren();

  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.className = "empty-table-message";
  cell.textContent = message;
  row.appendChild(cell);
  tbody.appendChild(row);
}

function renderActorActivityTable() {
  const tbody = document.querySelector("#actorActivityTable tbody");
  if (!tbody) return;

  updateActorRecordCount();

  if (!actorActivityData.length) {
    renderActorActivityMessage(
      tbody,
      "No source-backed actor-to-CVE relationships are published yet. Add reviewed public-source links to data/actor_cve_links.json to populate this table."
    );
    return;
  }

  if (!filteredActorActivityData.length) {
    renderActorActivityMessage(tbody, "No actor activity records match the current filters.");
    return;
  }

  tbody.replaceChildren();

  filteredActorActivityData.forEach(item => {
    const row = document.createElement("tr");
    const confidence = normalizedConfidence(item.confidence);
    if (confidence === "suspected") {
      row.className = "is-deemphasized";
    }

    const cveCell = document.createElement("td");
    const cveText = fieldText(item.cve).trim();
    const cveLink = createNvdCveLink(cveText, isSafeCveId(cveText) ? normalizedCveId(cveText) : cveText);
    cveCell.appendChild(cveLink || document.createTextNode(cveText || "N/A"));
    row.appendChild(cveCell);

    row.appendChild(createTextCell(item.actor || "N/A"));
    row.appendChild(createTextCell(item.actor_type || "N/A"));
    row.appendChild(createTextCell(item.relationship || "N/A"));
    row.appendChild(createConfidenceCell(item.confidence));
    row.appendChild(createTextCell(item.evidence_summary || "N/A"));

    const sourceCell = document.createElement("td");
    sourceCell.appendChild(createSafeSourceLink(item));
    row.appendChild(sourceCell);

    row.appendChild(createTextCell(item.last_reviewed || "N/A"));

    tbody.appendChild(row);
  });
}

function getAttackVector(cvssVector) {
  const vector = fieldText(cvssVector);
  if (!vector) return null;
  const match = vector.match(/AV:([NALP])/);
  return match ? match[1] : null;
}

function loadDashboardData() {
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
}

function loadLastKevCheckTimestamp() {
  const timestampElement = document.getElementById("timestamp");
  const lastUpdatedElement = document.getElementById("last-updated");
  if (!timestampElement || !lastUpdatedElement) return;

  fetch(lastUpdatedUrl)
    .then(response => {
      if (!response.ok) {
        throw new Error(`Timestamp request failed with status ${response.status}`);
      }
      return response.text();
    })
    .then(timestamp => {
      timestampElement.textContent = formatLocalTimestamp(timestamp.trim());
    })
    .catch(error => {
      console.error("Error loading Worker last_updated timestamp:", error);
      lastUpdatedElement.textContent = "Last KEV check unavailable";
    });
}

function formatLocalTimestamp(timestamp) {
  const date = new Date(timestamp);
  if (isNaN(date)) {
    throw new Error("Invalid last_updated timestamp");
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

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

function isSafeCveId(value) {
  return /^CVE-\d{4}-\d{4,}$/i.test(fieldText(value).trim());
}

function normalizedCveId(value) {
  return fieldText(value).trim().toUpperCase();
}

function createNvdCveLink(cveId, label, title) {
  const normalized = normalizedCveId(cveId);
  if (!isSafeCveId(normalized)) {
    return null;
  }

  const link = document.createElement("a");
  link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(normalized)}`;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  if (title) {
    link.title = title;
  }
  link.textContent = label;
  return link;
}

function createTextCell(value) {
  const cell = document.createElement("td");
  cell.textContent = fieldText(value);
  return cell;
}

function cvssScoreText(value) {
  const text = fieldText(value).trim();
  if (!text || text === "N/A" || text.includes("<a ")) {
    return "N/A";
  }
  return text;
}

function vendorProductText(item) {
  const vendor = fieldText(item.vendor).trim();
  const product = fieldText(item.product).trim();

  if (vendor && product && vendor.toLowerCase() === product.toLowerCase()) {
    return vendor;
  }

  if (vendor && product) return `${vendor}/${product}`;
  return vendor || product || "Unknown product";
}

function titleCaseSeverity(value) {
  const severity = fieldText(value).trim().toLowerCase();
  if (!severity) return "Unknown severity";

  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function numberValue(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isDueDateOverdue(dueDate) {
  if (!dueDate) return false;

  const date = new Date(dueDate);
  if (isNaN(date)) return false;

  return date < new Date();
}

function isDueDateApproaching(dueDate) {
  if (!dueDate || isDueDateOverdue(dueDate)) return false;

  const date = new Date(dueDate);
  if (isNaN(date)) return false;

  const fourteenDaysFromNow = new Date();
  fourteenDaysFromNow.setDate(fourteenDaysFromNow.getDate() + 14);
  return date <= fourteenDaysFromNow;
}

function triageTags(item) {
  const tags = [];
  const epssPercentile = numberValue(item.epssPercentile);

  if (getAttackVector(item.cvssVector) === "N") {
    tags.push("Network");
  }

  if (epssPercentile !== null && epssPercentile >= 0.9) {
    tags.push("High EPSS");
  }

  if (hasKnownRansomwareUse(item.knownRansomwareCampaignUse)) {
    tags.push("Ransomware");
  }

  if (isDueDateOverdue(item.dueDate)) {
    tags.push("Overdue");
  } else if (isDueDateApproaching(item.dueDate)) {
    tags.push("Due soon");
  }

  return tags.length ? tags : ["Review"];
}

function detailSummaryText(item) {
  const cve = isSafeCveId(item.cveID) ? normalizedCveId(item.cveID) : fieldText(item.cveID).trim();
  return `${cve || "Unknown CVE"} | ${vendorProductText(item)} | ${titleCaseSeverity(getSeverity(item))} | ${triageTags(item).join(" · ")}`;
}

function investigationQueryText(item) {
  const values = [];
  [
    isSafeCveId(item.cveID) ? normalizedCveId(item.cveID) : fieldText(item.cveID).trim(),
    fieldText(item.vendor).trim(),
    fieldText(item.product).trim(),
  ].forEach(value => {
    if (!value) return;

    const isDuplicate = values.some(existingValue => existingValue.toLowerCase() === value.toLowerCase());
    if (!isDuplicate) {
      values.push(value);
    }
  });

  return values.map(value => `"${value.replaceAll('"', '\\"')}"`).join(" OR ");
}

function copyPlainText(text, button) {
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
    button.textContent = "Copy unavailable";
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.dataset.label || button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = originalText;
    }, 1200);
  }).catch(() => {
    button.textContent = "Copy failed";
  });
}

function createDetailActionButton(label, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "detail-action";
  button.dataset.label = label;
  button.textContent = label;
  button.addEventListener("click", onClick);
  return button;
}

function attackVectorText(cvssVector) {
  const vector = getAttackVector(cvssVector);
  const labels = {
    N: "Network",
    A: "Adjacent",
    L: "Local",
    P: "Physical",
  };

  return labels[vector] || "Unknown";
}

function appendDetailSection(panel, labelText, valueText, className) {
  const label = document.createElement("div");
  label.className = "detail-label";
  label.textContent = labelText;
  panel.appendChild(label);

  const content = document.createElement("div");
  content.className = className;
  content.textContent = valueText || "N/A";
  panel.appendChild(content);
}

function appendCompactTagList(parent, tags) {
  const tagList = document.createElement("div");
  tagList.className = "detail-tags table-triage-tags";
  tags.forEach(tagText => {
    const tag = document.createElement("span");
    tag.className = "detail-tag table-triage-tag";
    tag.textContent = tagText;
    tagList.appendChild(tag);
  });
  parent.appendChild(tagList);
}

function createDetailRow(item, columnCount) {
  const row = document.createElement("tr");
  row.className = "detail-row";

  const cell = document.createElement("td");
  cell.colSpan = columnCount;

  const panel = document.createElement("div");
  panel.className = "detail-panel";

  const header = document.createElement("div");
  header.className = "detail-header";
  const cve = isSafeCveId(item.cveID) ? normalizedCveId(item.cveID) : fieldText(item.cveID).trim();
  header.textContent = `${cve || "Unknown CVE"} · ${vendorProductText(item)} · ${titleCaseSeverity(getSeverity(item))}`;
  panel.appendChild(header);

  appendDetailSection(panel, "Full description", fieldText(item.description), "detail-description");

  const cvssVector = fieldText(item.cvssVector);
  appendDetailSection(panel, "Attack vector", attackVectorText(cvssVector), "detail-vector");
  appendDetailSection(panel, "CVSS vector", cvssVector && cvssVector !== "N/A" ? cvssVector : "N/A", "detail-vector");

  const actions = document.createElement("div");
  actions.className = "detail-actions";
  actions.appendChild(createDetailActionButton("Copy CVE", event => {
    copyPlainText(cve, event.currentTarget);
  }));
  actions.appendChild(createDetailActionButton("Copy summary", event => {
    copyPlainText(detailSummaryText(item), event.currentTarget);
  }));
  actions.appendChild(createDetailActionButton("Copy investigation query", event => {
    copyPlainText(investigationQueryText(item), event.currentTarget);
  }));

  const nvdLink = createNvdCveLink(item.cveID, "Open NVD");
  if (nvdLink) {
    nvdLink.className = "detail-action detail-link";
    actions.appendChild(nvdLink);
  }

  panel.appendChild(actions);
  cell.appendChild(panel);
  row.appendChild(cell);

  return row;
}

function collapseExpandedDetailRows(tbody) {
  tbody.querySelectorAll(".detail-row").forEach(row => row.remove());
  tbody.querySelectorAll(".details-toggle[aria-expanded='true']").forEach(button => {
    button.setAttribute("aria-expanded", "false");
    button.textContent = "Details";
  });
}

function toggleDetailRow(item, row, button) {
  const tbody = row.parentElement;
  const isExpanded = button.getAttribute("aria-expanded") === "true";

  collapseExpandedDetailRows(tbody);

  if (isExpanded) {
    return;
  }

  const detailRow = createDetailRow(item, row.cells.length);
  row.after(detailRow);
  button.setAttribute("aria-expanded", "true");
  button.textContent = "Hide";
}

function renderTable() {
  const tbody = document.querySelector("#kevTable tbody");
  tbody.replaceChildren();
  updateRecordCount();

  const totalPages = Math.max(1, Math.ceil(tableData.length / pageSize));
  const start = (currentPage - 1) * pageSize;
  const end = start + pageSize;
  const pageData = tableData.slice(start, end);

  pageData.forEach(item => {
    const row = document.createElement("tr");
    const cveIdText = fieldText(item.cveID);
    const safeCveId = isSafeCveId(cveIdText);
    const cvssVector = fieldText(item.cvssVector);
    const hasCvssVector = cvssVector && cvssVector !== "N/A";
    const cvssScore = cvssScoreText(item.cvssScore);

    const cveCell = document.createElement("td");
    const cveLink = createNvdCveLink(cveIdText, safeCveId ? normalizedCveId(cveIdText) : cveIdText);
    cveCell.appendChild(cveLink || document.createTextNode(cveIdText));
    if (item.source !== "NVD") {
      const kevPill = document.createElement("span");
      kevPill.className = "kev-pill";
      kevPill.textContent = "KEV";
      cveCell.appendChild(kevPill);
    }
    row.appendChild(cveCell);

    const productCell = document.createElement("td");
    if (item.vendor) {
      const vendor = document.createElement("div");
      vendor.className = "vendor-name";
      vendor.textContent = fieldText(item.vendor);
      productCell.appendChild(vendor);
    }
    if (item.product) {
      const product = document.createElement("div");
      product.className = "product-name";
      product.textContent = fieldText(item.product);
      productCell.appendChild(product);
    }
    row.appendChild(productCell);

    row.appendChild(createTextCell(item.cvssSeverity || ""));

    const cvssCell = document.createElement("td");
    if (hasCvssVector) {
      cvssCell.title = cvssVector;
    }
    if (cvssScore === "N/A") {
      const cvssLink = createNvdCveLink(cveIdText, "N/A", "View on NVD");
      cvssCell.appendChild(cvssLink || document.createTextNode("N/A"));
    } else {
      cvssCell.textContent = cvssScore;
    }
    if (item.cvssVersion && item.cvssVersion !== "N/A") {
      cvssCell.appendChild(document.createTextNode(" "));
      const cvssVersion = document.createElement("span");
      cvssVersion.className = "cvss-version";
      cvssVersion.textContent = `(${fieldText(item.cvssVersion)})`;
      cvssCell.appendChild(cvssVersion);
    }
    row.appendChild(cvssCell);

    row.appendChild(createTextCell(item.epssScore !== "N/A" && item.epssScore != null ? formatFixed(item.epssScore, 4) : "N/A"));
    row.appendChild(createTextCell(item.epssPercentile !== "N/A" && item.epssPercentile != null ? formatPercent(item.epssPercentile) : "N/A"));
    row.appendChild(createTextCell(item.dateAdded || ""));

    const dueDateCell = createTextCell(item.dueDate || "");
    if (item.dueDate && new Date(item.dueDate) < new Date()) {
      dueDateCell.className = "overdue";
    }
    row.appendChild(dueDateCell);

    const whyCell = document.createElement("td");
    whyCell.className = "why-cell";
    appendCompactTagList(whyCell, triageTags(item));
    row.appendChild(whyCell);

    const detailsCell = document.createElement("td");
    detailsCell.className = "details-control-cell";
    const detailsButton = document.createElement("button");
    detailsButton.type = "button";
    detailsButton.className = "details-toggle";
    detailsButton.setAttribute("aria-expanded", "false");
    detailsButton.textContent = "Details";
    detailsButton.addEventListener("click", () => {
      toggleDetailRow(item, row, detailsButton);
    });
    detailsCell.appendChild(detailsButton);
    row.appendChild(detailsCell);

    tbody.appendChild(row);
  });

  document.getElementById("pageIndicator").textContent = `Page ${currentPage} of ${totalPages}`;
  document.getElementById("prevPage").disabled = currentPage === 1;
  document.getElementById("nextPage").disabled = currentPage === totalPages;
  applyColumnVisibility();
}

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
