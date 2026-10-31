const alerts = [
  {
    id: "a-001", incident: "INC-2847", title: "Multiple failed logins followed by success",
    severity: "Critical", entity: "svc-backup-02", source: "Microsoft Sentinel", firstSeen: "09:42:18",
    status: "Investigating", assignee: "Jordan Davis", type: "Identity", tactic: "Credential Access",
    description: "A service account recorded 17 failed sign-in attempts from an unfamiliar IP, followed by a successful authentication. The source has not been seen in this environment in the past 30 days.",
    ip: "185.220.101.42", location: "Frankfurt, DE", confidence: "High",
    timeline: [["09:42:18", "Successful sign-in detected", "svc-backup-02 · unfamiliar source"], ["09:41:52", "17 failed attempts in 4 minutes", "Identity protection rule triggered"], ["09:38:04", "First attempt from this IP", "185.220.101.42 · Frankfurt, DE"]]
  },
  {
    id: "a-002", incident: "INC-2846", title: "PowerShell spawned by Office application",
    severity: "High", entity: "WS-FIN-044", source: "Microsoft Defender", firstSeen: "09:37:05",
    status: "Open", assignee: "Unassigned", type: "Endpoint", tactic: "Execution",
    description: "An Office application launched PowerShell with an encoded command line. Review the process ancestry and validate the user-reported document before containment.",
    ip: "10.24.8.44", location: "Finance · Workstation", confidence: "Medium",
    timeline: [["09:37:05", "Suspicious process chain observed", "WINWORD.EXE → powershell.exe"], ["09:36:51", "Document opened", "Quarterly_forecast_review.docm"], ["09:36:50", "Endpoint alert created", "Microsoft Defender for Endpoint"]]
  },
  {
    id: "a-003", incident: "INC-2845", title: "Potential data exfiltration over DNS",
    severity: "Critical", entity: "ENG-LT-019", source: "Darktrace", firstSeen: "09:31:42",
    status: "Escalated", assignee: "Maya Chen", type: "Network", tactic: "Exfiltration",
    description: "High-entropy DNS requests were observed from an engineering laptop, with an unusual increase in outbound query volume. Tier 2 is reviewing packet metadata.",
    ip: "10.24.12.19", location: "Engineering · Laptop", confidence: "High",
    timeline: [["09:35:10", "Escalated to Tier 2", "Maya Chen · incident response"], ["09:31:42", "Unusual DNS volume detected", "842 queries in 5 minutes"], ["09:28:03", "New domain observed", "cdn-cache-sync.net"]]
  },
  {
    id: "a-004", incident: "INC-2844", title: "Unusual mailbox forwarding rule created",
    severity: "High", entity: "a.mitchell", source: "Microsoft 365", firstSeen: "09:26:11",
    status: "Investigating", assignee: "Jordan Davis", type: "Identity", tactic: "Collection",
    description: "A new inbox rule forwards messages with invoice-related subjects to an external address. The rule was created from a session with an atypical sign-in location.",
    ip: "91.234.12.8", location: "Bucharest, RO", confidence: "Medium",
    timeline: [["09:26:11", "Forwarding rule created", "a.mitchell · Exchange Online"], ["09:23:48", "Atypical sign-in detected", "91.234.12.8 · Bucharest, RO"], ["09:20:01", "MFA challenge satisfied", "Microsoft Entra ID"]]
  },
  {
    id: "a-005", incident: "INC-2843", title: "New privileged role assignment",
    severity: "Medium", entity: "j.howard", source: "Entra ID", firstSeen: "09:18:54",
    status: "Open", assignee: "Unassigned", type: "Identity", tactic: "Privilege Escalation",
    description: "A Global Administrator role was assigned outside the normal access review window. Confirm the change request and the approver before taking action.",
    ip: "10.24.2.16", location: "Corporate VPN", confidence: "Medium",
    timeline: [["09:18:54", "Role assignment detected", "Global Administrator · eligible role"], ["09:18:42", "Privileged request approved", "Request record not yet correlated"], ["09:18:37", "Admin session began", "j.howard · Corporate VPN"]]
  },
  {
    id: "a-006", incident: "INC-2842", title: "Endpoint protection service stopped",
    severity: "High", entity: "HR-WS-008", source: "CrowdStrike", firstSeen: "09:12:07",
    status: "Open", assignee: "Unassigned", type: "Endpoint", tactic: "Defense Evasion",
    description: "Endpoint protection reported a service stop event that was not initiated by a software update. Validate the host health and recent administrative activity.",
    ip: "10.24.5.88", location: "Human Resources · Workstation", confidence: "High",
    timeline: [["09:12:07", "Protection service stopped", "Falcon Sensor · service state changed"], ["09:11:44", "Local admin activity observed", "Process attribution pending"], ["09:11:33", "Host health check failed", "HR-WS-008"]]
  },
  {
    id: "a-007", incident: "INC-2841", title: "Impossible travel sign-in detected",
    severity: "Medium", entity: "s.patel", source: "Entra ID", firstSeen: "08:58:31",
    status: "Open", assignee: "Unassigned", type: "Identity", tactic: "Initial Access",
    description: "Two successful sign-ins for the same user were recorded from geographically distant locations within 22 minutes. Verify with the user and review session risk.",
    ip: "203.0.113.82", location: "Singapore, SG", confidence: "Medium",
    timeline: [["08:58:31", "Second sign-in recorded", "203.0.113.82 · Singapore, SG"], ["08:36:12", "First sign-in recorded", "198.51.100.27 · Seattle, US"], ["08:58:32", "Impossible travel rule matched", "22 minutes between locations"]]
  },
  {
    id: "a-008", incident: "INC-2839", title: "Malware quarantined on user device",
    severity: "Low", entity: "MKT-LT-011", source: "Microsoft Defender", firstSeen: "08:43:09",
    status: "Resolved", assignee: "Alex Rivera", type: "Endpoint", tactic: "Execution",
    description: "A potentially unwanted application was blocked and quarantined by endpoint protection. A follow-up scan completed with no additional detections.",
    ip: "10.24.18.11", location: "Marketing · Laptop", confidence: "Low",
    timeline: [["09:02:14", "Incident resolved", "Alex Rivera · device scan clean"], ["08:45:22", "Follow-up scan completed", "No additional detections"], ["08:43:09", "File quarantined", "Endpoint protection action successful"]]
  }
];

const state = { filter: "all", query: "", selectedId: "a-001" };
let nextIncidentNumber = 2848;
const rowsElement = document.querySelector("#alert-rows");
const caseContent = document.querySelector("#case-content");
const caseActions = document.querySelector("#case-actions");

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[character]);

function renderAlerts() {
  const filtered = alerts.filter((alert) => {
    const matchesStatus = state.filter === "all" ||
      (state.filter === "open" && alert.status === "Open") ||
      (state.filter === "investigating" && alert.status === "Investigating");
    const searchable = `${alert.title} ${alert.incident} ${alert.entity} ${alert.source} ${alert.severity} ${alert.status}`.toLowerCase();
    return matchesStatus && searchable.includes(state.query.toLowerCase());
  });

  rowsElement.innerHTML = filtered.map((alert) => {
    const severity = alert.severity.toLowerCase();
    const status = alert.status.toLowerCase();
    return `<tr data-alert-id="${alert.id}" class="${alert.id === state.selectedId ? "selected-row" : ""}" tabindex="0" aria-selected="${alert.id === state.selectedId}">
      <td><div class="alert-name-cell"><span class="severity-marker severity-${severity}"></span><span><span class="alert-name">${escapeHtml(alert.title)}</span><span class="alert-id">${escapeHtml(alert.incident)}</span></span></div></td>
      <td><span class="severity-pill ${severity}">${escapeHtml(alert.severity)}</span></td>
      <td class="entity-cell">${escapeHtml(alert.entity)}</td>
      <td class="source-cell">${escapeHtml(alert.source)}</td>
      <td class="time-cell">${escapeHtml(alert.firstSeen)} UTC</td>
      <td><span class="status-pill status-${status}">${escapeHtml(alert.status)}</span></td>
    </tr>`;
  }).join("");

  document.querySelector("#empty-state").hidden = filtered.length !== 0;
  document.querySelector("#table-result-count").textContent = `Showing ${filtered.length} of ${alerts.length} alerts`;
  document.querySelector("#filter-all-count").textContent = String(alerts.length);
  document.querySelector("#nav-alert-count").textContent = String(alerts.filter((alert) => alert.status !== "Resolved").length).padStart(2, "0");
  document.querySelector("#metric-active").textContent = String(alerts.filter((alert) => alert.status !== "Resolved").length).padStart(2, "0");
  document.querySelector("#metric-critical").textContent = String(alerts.filter((alert) => alert.severity === "Critical" && alert.status !== "Resolved").length).padStart(2, "0");
  document.querySelector("#metric-investigating").textContent = String(alerts.filter((alert) => alert.status === "Investigating").length).padStart(2, "0");
  document.querySelector("#metric-assigned").textContent = `${alerts.filter((alert) => alert.status === "Investigating" && alert.assignee === "Jordan Davis").length} assigned to you`;
}

function renderCase() {
  const alert = alerts.find((item) => item.id === state.selectedId);
  if (!alert) return;
  document.querySelector("#case-id").textContent = alert.incident;
  const severity = alert.severity.toUpperCase();
  caseContent.innerHTML = `
    <div class="case-severity"><span class="severity-marker severity-${alert.severity.toLowerCase()}"></span>${escapeHtml(severity)} SEVERITY <span class="eyebrow-separator">·</span> ${escapeHtml(alert.type.toUpperCase())}</div>
    <h3 class="case-title">${escapeHtml(alert.title)}</h3>
    <p class="case-description">${escapeHtml(alert.description)}</p>
    <div class="case-meta">
      <div><span class="meta-label">Entity</span><span class="meta-value mono">${escapeHtml(alert.entity)}</span></div>
      <div><span class="meta-label">Assignee</span><span class="meta-value">${escapeHtml(alert.assignee)}</span></div>
      <div><span class="meta-label">Source IP</span><span class="meta-value mono">${escapeHtml(alert.ip)}</span></div>
      <div><span class="meta-label">Confidence</span><span class="meta-value">${escapeHtml(alert.confidence)}</span></div>
      <div><span class="meta-label">Location</span><span class="meta-value">${escapeHtml(alert.location)}</span></div>
      <div><span class="meta-label">MITRE tactic</span><span class="meta-value">${escapeHtml(alert.tactic)}</span></div>
    </div>
    <div class="case-timeline-heading"><span>Event timeline</span><span class="meta-value">${alert.timeline.length} events</span></div>
    <div class="timeline">${alert.timeline.map((event, index) => `<div class="timeline-event"><span class="timeline-marker ${index === 0 ? "" : "muted-marker"}"></span><div class="timeline-copy"><strong>${escapeHtml(event[1])}</strong><span>${escapeHtml(event[0])} UTC · ${escapeHtml(event[2])}</span></div></div>`).join("")}</div>`;

  if (alert.status === "Resolved") {
    caseActions.innerHTML = '<button class="button button-secondary" type="button" data-action="reopen">Reopen alert</button>';
  } else if (alert.status === "Investigating") {
    caseActions.innerHTML = '<button class="button button-secondary" type="button" data-action="assign">Assign to me</button><button class="button button-primary" type="button" data-action="resolve">Resolve alert</button>';
  } else {
    caseActions.innerHTML = '<button class="button button-secondary" type="button" data-action="assign">Assign to me</button><button class="button button-primary" type="button" data-action="investigate">Start investigation</button>';
  }
}

function selectAlert(id) {
  if (!alerts.some((alert) => alert.id === id)) return;
  state.selectedId = id;
  renderAlerts();
  renderCase();
}

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  document.querySelector("#toast-region").append(toast);
  window.setTimeout(() => toast.remove(), 3200);
}

rowsElement.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-alert-id]");
  if (row) selectAlert(row.dataset.alertId);
});
rowsElement.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("tr[data-alert-id]");
  if (row) {
    event.preventDefault();
    selectAlert(row.dataset.alertId);
  }
});

document.querySelector("#alert-search").addEventListener("input", (event) => {
  state.query = event.target.value.trim();
  renderAlerts();
});
document.querySelectorAll(".filter-button").forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll(".filter-button").forEach((item) => {
      const active = item === button;
      item.classList.toggle("selected", active);
      item.setAttribute("aria-pressed", String(active));
    });
    renderAlerts();
  });
});

caseActions.addEventListener("click", (event) => {
  const action = event.target.closest("[data-action]")?.dataset.action;
  const alert = alerts.find((item) => item.id === state.selectedId);
  if (!action || !alert) return;

  if (action === "assign") {
    alert.assignee = "Jordan Davis";
    if (alert.status === "Open") alert.status = "Investigating";
    showToast(`${alert.incident} assigned to you`);
  } else if (action === "investigate") {
    alert.status = "Investigating";
    alert.assignee = "Jordan Davis";
    showToast(`Investigation started for ${alert.incident}`);
  } else if (action === "resolve") {
    alert.status = "Resolved";
    showToast(`${alert.incident} marked as resolved`);
  } else if (action === "reopen") {
    alert.status = "Open";
    alert.assignee = "Unassigned";
    showToast(`${alert.incident} reopened`);
  }

  renderAlerts();
  renderCase();
});

document.querySelector("#refresh-button").addEventListener("click", (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.classList.add("is-refreshing");
  renderAlerts();
  window.setTimeout(() => {
    button.disabled = false;
    button.classList.remove("is-refreshing");
    document.querySelector(".data-source").innerHTML = '<span class="source-dot"></span> Data synced just now';
    showToast("Security data is up to date");
  }, 650);
});

document.querySelector("#new-case-button").addEventListener("click", () => {
  document.querySelector("#new-case-form").reset();
  document.querySelector("#new-case-dialog").showModal();
});

document.querySelector(".dialog-close").addEventListener("click", () => {
  document.querySelector("#new-case-dialog").close();
});
document.querySelector("[data-dialog-cancel]").addEventListener("click", () => {
  document.querySelector("#new-case-dialog").close();
});
document.querySelector("#new-case-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const title = String(form.get("title")).trim();
  const entity = String(form.get("entity")).trim();
  if (!title || !entity) return;
  const now = new Date();
  const id = `a-new-${Date.now()}`;
  const incident = `INC-${nextIncidentNumber++}`;
  alerts.unshift({
    id, incident, title, severity: String(form.get("severity")), entity,
    source: "Analyst created",
    firstSeen: new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(now),
    status: "Investigating", assignee: "Jordan Davis", type: "Analyst review",
    tactic: "Under review", description: "Manually created investigation. Review the event context, validate the affected entity, and document your findings.",
    ip: "Not available", location: "Analyst created", confidence: "Pending",
    timeline: [[new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(now), "Investigation created", "Jordan Davis · analyst review"]]
  });
  state.selectedId = id;
  state.filter = "all";
  state.query = "";
  document.querySelector("#alert-search").value = "";
  document.querySelectorAll(".filter-button").forEach((button) => {
    const active = button.dataset.filter === "all";
    button.classList.toggle("selected", active);
    button.setAttribute("aria-pressed", String(active));
  });
  document.querySelector("#new-case-dialog").close();
  renderAlerts();
  renderCase();
  document.querySelector("#alert-queue").scrollIntoView({ behavior: "smooth", block: "start" });
  showToast(`${incident} created and assigned to you`);
});

document.querySelector("#view-all-button").addEventListener("click", () => {
  state.filter = "all";
  document.querySelectorAll(".filter-button").forEach((button) => {
    const active = button.dataset.filter === "all";
    button.classList.toggle("selected", active);
    button.setAttribute("aria-pressed", String(active));
  });
  renderAlerts();
});

document.querySelectorAll("[data-alert-link]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    selectAlert(link.dataset.alertLink);
    document.querySelector("#investigation").scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => {
      item.classList.toggle("active", item === link);
      if (item === link) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
  });
});

document.querySelector("#alert-search").addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.currentTarget.value = "";
    state.query = "";
    renderAlerts();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    document.querySelector("#alert-search").focus();
  }
});

function updateClock() {
  document.querySelector("#utc-clock").textContent = `${new Intl.DateTimeFormat("en-GB", {
    timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  }).format(new Date())} UTC`;
}

updateClock();
window.setInterval(updateClock, 1000);
renderAlerts();
renderCase();
