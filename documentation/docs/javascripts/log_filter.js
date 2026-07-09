/**
 * log_filter.js — interactive level filtering for the Log Call-Site Directory page.
 *
 * Pure vanilla JS — no jQuery, no DataTables, no external dependencies.
 * Activated only on log-reference.md (URL pathname check).
 * Hooked into Material's document$.subscribe so it re-runs on instant navigation.
 *
 * One search bar + level filter set per Domain section (h2), filtering all
 * crate tables within that domain simultaneously.
 * Also colors inline <code> log-level badges throughout the page.
 */

(() => {

const LOG_REFERENCE_PATH = "log-reference";
const LEVELS = ["error", "warn", "info", "debug", "trace"];
const LEVEL_COLORS = {
  error: "#d32f2f",
  warn:  "#f57c00",
  info:  "#1565c0",
  debug: "#388e3c",
  trace: "#6a1b9a",
};
const ALL_COLOR = "#607d8b";

// ── Helpers ───────────────────────────────────────────────────────────────

function styleBtn(btn, color, active) {
  Object.assign(btn.style, {
    padding:        "3px 13px",
    borderRadius:   "12px",
    border:         `1.5px solid ${color}`,
    background:     active ? color : "transparent",
    color:          active ? "#fff" : color,
    fontSize:       "0.8em",
    fontWeight:     "600",
    cursor:         "pointer",
    transition:     "background 0.15s, color 0.15s",
    fontFamily:     "var(--md-code-font, monospace)",
    letterSpacing:  "0.03em",
    lineHeight:     "1.9",
    whiteSpace:     "nowrap",
  });
}

function applyFilters(tables, activeLevel, needle) {
  tables.forEach((tableEl) => {
    const tbody = tableEl.querySelector("tbody");
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll("tr"));

    rows.forEach((row) => {
      const cells = Array.from(row.querySelectorAll("td"));
      if (!cells.length) return;
      const levelText = cells[0].textContent.trim().toLowerCase();
      const matchesLevel  = activeLevel === "" || levelText === activeLevel;
      const matchesSearch = needle === "" ||
        cells.some((td) => td.textContent.toLowerCase().includes(needle));
      row.style.display = matchesLevel && matchesSearch ? "" : "none";
    });

    // Re-sort visible rows by severity (error first → trace last)
    const visible = rows.filter(r => r.style.display !== "none");
    visible.sort((a, b) => {
      const la = a.querySelector("td")?.textContent.trim().toLowerCase() || "";
      const lb = b.querySelector("td")?.textContent.trim().toLowerCase() || "";
      return (LEVELS.indexOf(la) ?? 99) - (LEVELS.indexOf(lb) ?? 99);
    });
    visible.forEach(r => tbody.appendChild(r));
  });
}

// ── Domain section discovery ──────────────────────────────────────────────
// Returns [{heading: h2El, tables: [tableEl, ...]}, ...]

function getDomainSections(content) {
  const sections = [];
  let current = null;
  content.querySelectorAll("h2, table").forEach((el) => {
    if (el.tagName === "H2") {
      current = el.textContent.includes("Domain:") ? { heading: el, tables: [] } : null;
      if (current) sections.push(current);
    } else if (el.tagName === "TABLE" && current) {
      if (el.querySelectorAll("thead th").length >= 5) current.tables.push(el);
    }
  });
  return sections;
}

// ── Controls builder (one per domain) ────────────────────────────────────

function buildDomainControls(tables) {
  const wrap = document.createElement("div");
  Object.assign(wrap.style, {
    display:       "flex",
    flexDirection: "column",
    gap:           "10px",
    padding:       "14px 18px",
    margin:        "18px 0 22px",
    borderRadius:  "8px",
    border:        "1px solid var(--md-default-fg-color--lightest, rgba(0,0,0,0.12))",
    background:    "var(--md-code-bg-color, rgba(0,0,0,0.03))",
  });

  // Search row
  const searchRow = document.createElement("div");
  searchRow.style.cssText = "display:flex;align-items:center;gap:10px;";

  const searchLabel = document.createElement("span");
  searchLabel.textContent = "Search:";
  searchLabel.style.cssText = "font-size:0.82em;opacity:0.6;white-space:nowrap;";

  const searchInput = document.createElement("input");
  searchInput.type = "search";
  searchInput.placeholder = "Filter all tables in this domain…";
  Object.assign(searchInput.style, {
    flex:         "1",
    maxWidth:     "420px",
    padding:      "5px 12px",
    borderRadius: "6px",
    border:       "1px solid var(--md-default-fg-color--lighter, #ccc)",
    background:   "transparent",
    color:        "inherit",
    fontSize:     "0.85em",
    outline:      "none",
  });

  searchRow.appendChild(searchLabel);
  searchRow.appendChild(searchInput);

  // Level filter row
  const filterRow = document.createElement("div");
  filterRow.style.cssText = "display:flex;gap:7px;flex-wrap:wrap;align-items:center;";

  const filterLabel = document.createElement("span");
  filterLabel.textContent = "Level:";
  filterLabel.style.cssText = "font-size:0.82em;opacity:0.6;white-space:nowrap;margin-right:2px;";
  filterRow.appendChild(filterLabel);

  let activeLevel = "error";
  let searchText  = "";

  const levelBtns = new Map();

  // "All" button — clears the level filter
  const allBtn = document.createElement("button");
  allBtn.textContent = "all";
  styleBtn(allBtn, ALL_COLOR, activeLevel === "");
  levelBtns.set("", allBtn);
  filterRow.appendChild(allBtn);

  for (const level of LEVELS) {
    const btn = document.createElement("button");
    btn.textContent = level;
    styleBtn(btn, LEVEL_COLORS[level], level === "error");
    levelBtns.set(level, btn);
    filterRow.appendChild(btn);
  }

  function setActive(level) {
    for (const [l, b] of levelBtns) {
      const color = l === "" ? ALL_COLOR : LEVEL_COLORS[l];
      styleBtn(b, color, l === "" ? level === "" : l === level);
    }
  }

  filterRow.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    const entry = [...levelBtns.entries()].find(([, b]) => b === btn);
    if (!entry) return;
    // Toggle: clicking the already-active level clears the filter (shows all rows)
    activeLevel = entry[0] === activeLevel ? "" : entry[0];
    setActive(activeLevel);
    applyFilters(tables, activeLevel, searchText);
  });

  searchInput.addEventListener("input", () => {
    searchText = searchInput.value.toLowerCase();
    applyFilters(tables, activeLevel, searchText);
  });

  // Apply default filter immediately when controls are built
  applyFilters(tables, activeLevel, searchText);

  wrap.appendChild(searchRow);
  wrap.appendChild(filterRow);
  return wrap;
}

// ── GitHub file link injection ────────────────────────────────────────────
// Transforms plain <code>src/foo.rs</code> cells in the File column (3rd td)
// into clickable GitHub source links using window.KMS_VERSION set by hooks.py.

const GITHUB_BASE = "https://github.com/Cosmian/kms/blob";

function getCratePath(tableEl) {
  // Walk backwards from the table to find the nearest "Crate path: `...`" paragraph.
  let node = tableEl.previousElementSibling;
  while (node) {
    if (node.tagName === "P" || node.tagName === "DIV") {
      const text = node.textContent || "";
      if (text.includes("Crate path:")) {
        const code = node.querySelector("code");
        if (code) return code.textContent.trim().replace(/\/$/, "");
      }
    }
    // Stop at section headings
    if (node.tagName === "H2" || node.tagName === "H3") break;
    node = node.previousElementSibling;
  }
  return null;
}

function linkifyFileCells(content) {
  const version = (window.KMS_VERSION || "develop").trim();

  content.querySelectorAll("table").forEach((tableEl) => {
    // Only act on 5-column tables (our log tables)
    if (tableEl.querySelectorAll("thead th").length < 5) return;
    if (tableEl.dataset.linksInjected === "true") return;
    tableEl.dataset.linksInjected = "true";

    const cratePath = getCratePath(tableEl);
    if (!cratePath) return;

    tableEl.querySelectorAll("tbody tr").forEach((row) => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 3) return;
      const fileCell = cells[2]; // File is the 3rd column (0-indexed)
      const code = fileCell.querySelector("code");
      if (!code) return;
      if (fileCell.querySelector("a")) return; // already linked

      const fileRel = code.textContent.trim();
      const href = `${GITHUB_BASE}/${version}/${cratePath}/${fileRel}`;

      const link = document.createElement("a");
      link.href = href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.appendChild(code.cloneNode(true));

      fileCell.replaceChildren(link);
    });
  });
}

// ── Inline badge coloring ─────────────────────────────────────────────────
// Colors <code>error</code>, <code>trace</code>, etc. throughout the page.

function colorLevelBadges(content) {
  content.querySelectorAll("code").forEach((el) => {
    const text = el.textContent.trim().toLowerCase();
    const color = LEVEL_COLORS[text];
    if (!color) return;
    if (el.dataset.levelColored === "true") return;

    // Only color in prose (outside a <td>) or in the Level column (first <td>).
    // Variables / Message / File / Notes columns must not be affected.
    const parentTd = el.closest("td");
    if (parentTd) {
      const row = parentTd.closest("tr");
      if (!row || row.querySelector("td") !== parentTd) return;
    }

    el.dataset.levelColored = "true";
    Object.assign(el.style, {
      color:          color,
      border:         `1px solid ${color}`,
      borderRadius:   "10px",
      padding:        "2px 6px",
      background:     "transparent",
      fontWeight:     "600",
      whiteSpace:     "nowrap",
      display:        "inline-block",
    });
  });
}

// ── Version banner ────────────────────────────────────────────────────────
// Inserts a prominent notice at the top of the page linking to the tagged
// tree on GitHub. Injected once; guarded against re-injection on navigation.

function injectVersionBanner(content) {
  if (content.dataset.versionBanner === "true") return;
  content.dataset.versionBanner = "true";

  const version  = (window.KMS_VERSION || "develop").trim();
  const treeUrl  = `https://github.com/Cosmian/kms/tree/${version}`;
  const isDev    = version === "develop";

  const banner = document.createElement("div");
  Object.assign(banner.style, {
    display:       "flex",
    alignItems:    "flex-start",
    gap:           "12px",
    padding:       "14px 18px",
    margin:        "0 0 28px",
    borderRadius:  "8px",
    border:        `1.5px solid ${isDev ? "#f57c00" : "#1565c0"}`,
    background:    isDev
      ? "rgba(245,124,0,0.06)"
      : "rgba(21,101,192,0.06)",
    fontSize:      "0.88em",
    lineHeight:    "1.6",
  });

  const icon = document.createElement("span");
  icon.textContent = isDev ? "⚠️" : "📖";
  icon.style.cssText = "font-size:1.3em;flex-shrink:0;margin-top:1px;";

  const text = document.createElement("span");
  if (isDev) {
    text.innerHTML =
      `<strong>Development build</strong> — source links point to the ` +
      `<a href="${treeUrl}" target="_blank" rel="noopener noreferrer">` +
      `<code>develop</code> branch</a>. ` +
      `Links may not match a released version.`;
  } else {
    text.innerHTML =
      `This log index covers <strong>KMS ${version}</strong>. ` +
      `Each file link points to the exact source line in ` +
      `<a href="${treeUrl}" target="_blank" rel="noopener noreferrer">` +
      `the <code>${version}</code> tree on GitHub</a>.`;
  }

  banner.appendChild(icon);
  banner.appendChild(text);

  // Insert before the <h1> (first heading in the article)
  const article = content.querySelector(".md-content__inner, article, .md-typeset");
  const h1 = article ? article.querySelector("h1") : null;
  if (h1) {
    h1.insertAdjacentElement("afterend", banner);
  } else if (article) {
    article.prepend(banner);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────

function initPage() {
  if (!window.location.pathname.includes(LOG_REFERENCE_PATH)) return;

  const content = document.querySelector(".md-content");
  if (!content) return;

  // 1. Version banner
  injectVersionBanner(content);

  // 2. Color inline level badges everywhere on the page
  colorLevelBadges(content);

  // 3. Inject GitHub links into File column cells
  linkifyFileCells(content);

  // 4. Insert one control block per domain section
  getDomainSections(content).forEach(({ heading, tables }) => {
    if (!tables.length) return;
    if (heading.dataset.logFilter === "true") return;
    heading.dataset.logFilter = "true";

    const controls = buildDomainControls(tables);
    // Insert after the h2 element
    heading.insertAdjacentElement("afterend", controls);
  });
}

// Material instant navigation hook
if (typeof document$ !== "undefined") {
  document$.subscribe(initPage);
} else {
  document.addEventListener("DOMContentLoaded", initPage);
}

})(); // end IIFE
