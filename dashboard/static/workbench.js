(() => {
  "use strict";

  const caseStates = new Map();
  const palette = {
    authorized_target: "#7ab8ff",
    public_source: "#63779c",
    public_profile: "#9a7cff",
    public_resource: "#52d6d2",
    username_observation: "#8d9cff",
    email_observation: "#e63946",
    phone_observation: "#2dd4bf",
    service: "#f4b400",
    breach_event: "#ff4d4f",
    public_observation: "#a9b8d4",
    cluster: "#53698f",
  };
  const entityIcons = {
    authorized_target: "P",
    public_source: "S",
    public_profile: "@",
    public_resource: "R",
    username_observation: "U",
    email_observation: "E",
    phone_observation: "T",
    service: "✓",
    breach_event: "!",
    public_observation: "O",
    cluster: "C",
  };
  const plainRelationshipLabels = {
    candidate_profile: "Possible public profile",
    candidate_observation: "Possible public observation",
    publishes_attribute: "Discovery tool returned this result",
    breach_association: "Breach metadata reference",
    service_registration: "Service registration signal",
  };

  const html = (value = "") => String(value).replace(
    /[&<>"']/g,
    character => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#039;",
    }[character]),
  );
  const titleCase = value => String(value || "observation")
    .replaceAll("_", " ")
    .replace(/\b\w/g, character => character.toUpperCase());
  const percent = value => Number.isFinite(Number(value))
    ? `${Math.round(Number(value) * 100)}%`
    : "not scored";
  const confidenceColor = value => {
    const score = Number(value || 0);
    if (score >= 0.9) return "#2ecc71";
    if (score >= 0.7) return "#f4b400";
    if (score >= 0.4) return "#ff8c42";
    return "#e63946";
  };
  const safeUrl = value => {
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) ? url.href : null;
    } catch (_) {
      return null;
    }
  };
  const unique = values => [...new Set(values.filter(Boolean))];
  const relationshipLabel = value => plainRelationshipLabels[value]
    || titleCase(value || "cited relationship");
  const emailForDisplay = value => {
    const [local, domain] = String(value || "").split("@");
    if (!local || !domain) return value || "";
    return `${local.slice(0, 2)}${"*".repeat(Math.min(5, Math.max(2, local.length - 2)))}@${domain}`;
  };
  const evidenceReferences = (values, limit = 3) => {
    const cited = unique(values || []);
    if (!cited.length) return `<span class="evidence-reference">No evidence ID</span>`;
    const visible = cited.slice(0, limit).map(value => `<code>${html(value)}</code>`).join(" ");
    return `<span class="evidence-reference">${visible}${cited.length > limit
      ? ` <small>+${cited.length - limit} more</small>` : ""}</span>`;
  };
  const confidenceLabel = node => node.confidenceLabel
    || ({
      supported: "Supported",
      review_first: "Check first",
      low_signal: "Unverified lead",
      suppressed: "Hidden by default",
    }[node.reviewPriority])
    || titleCase(node.identityStatus || "insufficient_evidence");
  const isGenericEndpoint = value => {
    const url = safeUrl(value);
    if (!url) return false;
    const parsed = new URL(url);
    const host = parsed.hostname.toLocaleLowerCase().replace(/^www\./, "");
    const path = parsed.pathname.replace(/\/+$/, "") || "/";
    return (host === "discord.com" && path === "/")
      || (host === "scholar.google.com" && path.toLocaleLowerCase() === "/scholar")
      || (host === "op.gg" && path.toLocaleLowerCase() === "/lol/summoners/search");
  };

  function currentState(caseId) {
    if (!caseStates.has(caseId)) {
      caseStates.set(caseId, {
        tab: "overview",
        source: "all",
        type: "all",
        minimumConfidence: 0,
        showLabels: false,
        collapsed: false,
        simpleGraph: true,
        showSuppressed: false,
        focusNodeId: null,
        selectedIds: new Set(),
        positions: new Map(),
        viewport: {x: 0, y: 0, zoom: 1},
        graphDocument: null,
        graphLoading: false,
        graphLoaded: false,
        graphVersion: null,
      });
    }
    return caseStates.get(caseId);
  }

  function graphData(item, state) {
    const graph = state.graphDocument?.graph || item.report?.identity_graph || {};
    const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const edges = Array.isArray(graph.edges) ? graph.edges : [];
    const hypotheses = Array.isArray(graph.hypotheses) ? graph.hypotheses : [];
    const pivots = Array.isArray(graph.pivots) ? graph.pivots : [];
    const evidence = Array.isArray(item.report?.evidence_ledger)
      ? item.report.evidence_ledger
      : (Array.isArray(item.evidence_preview) ? item.evidence_preview : []);
    const evidenceById = Object.fromEntries(
      evidence.filter(entry => entry?.id).map(entry => [entry.id, entry]),
    );
    const hypothesisByNode = Object.fromEntries(
      hypotheses
        .filter(entry => entry?.object_node_id)
        .map(entry => [entry.object_node_id, entry]),
    );
    const nodeById = Object.fromEntries(nodes.map(node => [node.id, node]));
    const normalizedByNode = Object.fromEntries(
      (state.graphDocument?.entities || [])
        .filter(entity => entity?.entity_id)
        .map(entity => [entity.entity_id, entity]),
    );
    const relationshipSourcesByNode = {};
    edges.forEach(edge => {
      const sources = unique((edge.provenance_chain || [])
        .map(step => step?.source));
      [edge.source_node_id, edge.target_node_id].forEach(nodeId => {
        if (!nodeId) return;
        relationshipSourcesByNode[nodeId] = unique([
          ...(relationshipSourcesByNode[nodeId] || []),
          ...sources,
        ]);
      });
    });
    const records = nodes.map(node => {
      const cited = (node.evidence_ids || []).map(id => evidenceById[id]).filter(Boolean);
      const hypothesis = hypothesisByNode[node.id] || {};
      const normalized = normalizedByNode[node.id] || {};
      const isTarget = node.id === graph.target_node_id;
      const isSource = node.kind === "public_source";
      const attributes = node.attributes || {};
      const qualityStatus = normalized.quality_status
        || attributes.verification_status
        || "unverified";
      const sources = unique([
        ...cited.map(entry => entry.source),
        ...(relationshipSourcesByNode[node.id] || []),
      ]);
      const genericEndpoint = normalized.generic_endpoint
        ?? isGenericEndpoint(attributes.url || node.label);
      const sensitive = normalized.sensitive
        ?? Boolean(attributes.sensitive || qualityStatus === "quarantined");
      const suppressed = qualityStatus === "rejected"
        || qualityStatus === "quarantined"
        || genericEndpoint;
      let reviewPriority = normalized.review_priority;
      if (!reviewPriority && !isTarget && !isSource) {
        if (suppressed) reviewPriority = "suppressed";
        else if (["confirmed", "highly_probable", "probable"].includes(
          hypothesis.identity_status,
        )) reviewPriority = "supported";
        else if (hypothesis.identity_status === "possible"
          || node.kind === "service"
          || sources.length > 1) reviewPriority = "review_first";
        else reviewPriority = "low_signal";
      }
      return {
        ...node,
        attributes,
        confidence: isTarget || isSource ? 1 : Number(hypothesis.confidence || 0),
        identityStatus: isTarget
          ? "authorized_target"
          : (hypothesis.identity_status || "insufficient_evidence"),
        sources,
        sourceUrls: unique(cited.map(entry => entry.source_url)),
        publisherCount: normalized.publisher_count ?? sources.length,
        qualityStatus,
        reviewPriority,
        confidenceLabel: normalized.confidence_label,
        plainLanguageExplanation: normalized.plain_language_explanation,
        sensitive,
        genericEndpoint,
        hypothesis,
        cited,
      };
    });
    return {
      graph,
      nodes,
      edges,
      hypotheses,
      pivots,
      evidence,
      evidenceById,
      nodeById,
      records,
      reviewSummary: state.graphDocument?.review_summary || null,
    };
  }

  function availableFilters(data) {
    return {
      sources: unique(data.evidence.map(entry => entry.source)).sort(),
      types: unique(data.records.map(node => node.kind)).sort(),
    };
  }

  function layoutNodes(nodes, state) {
    const target = nodes.find(node => node.kind === "authorized_target");
    const others = nodes.filter(node => node !== target);
    if (target && !state.positions.has(target.id)) {
      state.positions.set(target.id, {x: 500, y: 325});
    }
    const groups = Object.groupBy
      ? Object.groupBy(others, node => node.kind)
      : others.reduce((output, node) => {
          (output[node.kind] ||= []).push(node);
          return output;
        }, {});
    const orderedGroups = Object.entries(groups).sort(([left], [right]) =>
      left.localeCompare(right));
    orderedGroups.forEach(([kind, members], groupIndex) => {
      const radius = 150 + groupIndex * 72;
      members.forEach((node, index) => {
        if (state.positions.has(node.id)) return;
        const angle = (Math.PI * 2 * index / Math.max(members.length, 1))
          + groupIndex * 0.62;
        state.positions.set(node.id, {
          x: 500 + Math.cos(angle) * radius,
          y: 325 + Math.sin(angle) * Math.min(radius, 270),
        });
      });
    });
  }

  function filteredGraph(data, state) {
    const candidates = data.records.filter(node =>
      !["authorized_target", "public_source"].includes(node.kind)
      && node.reviewPriority !== "suppressed");
    const prioritized = candidates.filter(node =>
      ["supported", "review_first"].includes(node.reviewPriority));
    const simpleCandidates = prioritized.length
      ? prioritized
      : [...candidates]
        .sort((left, right) =>
          Number(right.confidence || 0) - Number(left.confidence || 0)
          || String(left.label).localeCompare(String(right.label)))
        .slice(0, 12);
    const simpleIds = new Set(simpleCandidates.map(node => node.id));
    let records = data.records.filter(node => {
      const keepTarget = node.kind === "authorized_target";
      const simpleMatch = !state.simpleGraph
        || keepTarget
        || simpleIds.has(node.id);
      const privacyMatch = state.showSuppressed
        || node.reviewPriority !== "suppressed"
        || keepTarget;
      const sourceMatch = keepTarget
        || state.source === "all"
        || node.sources.includes(state.source)
        || (node.kind === "public_source"
          && node.label.toLocaleLowerCase() === state.source.toLocaleLowerCase());
      const typeMatch = keepTarget || state.type === "all" || node.kind === state.type;
      const confidenceMatch = node.confidence >= state.minimumConfidence
        || node.kind === "authorized_target"
        || node.kind === "public_source";
      return simpleMatch && privacyMatch && sourceMatch && typeMatch && confidenceMatch;
    });
    let allowed = new Set(records.map(node => node.id));
    if (state.focusNodeId) {
      const neighborhood = new Set([state.focusNodeId]);
      data.edges.forEach(edge => {
        if (edge.source_node_id === state.focusNodeId) {
          neighborhood.add(edge.target_node_id);
        }
        if (edge.target_node_id === state.focusNodeId) {
          neighborhood.add(edge.source_node_id);
        }
      });
      records = records.filter(node => neighborhood.has(node.id));
      allowed = new Set(records.map(node => node.id));
    }
    let edges = data.edges.filter(edge =>
      allowed.has(edge.source_node_id) && allowed.has(edge.target_node_id));
    if (!state.collapsed) return {nodes: records, edges};

    const targetNodes = records.filter(node => node.kind === "authorized_target");
    const groups = records
      .filter(node => node.kind !== "authorized_target")
      .reduce((output, node) => {
        (output[node.kind] ||= []).push(node);
        return output;
      }, {});
    const mappedIds = new Map(targetNodes.map(node => [node.id, node.id]));
    const collapsedNodes = [...targetNodes];
    Object.entries(groups).forEach(([kind, members]) => {
      if (members.length === 1) {
        collapsedNodes.push(members[0]);
        mappedIds.set(members[0].id, members[0].id);
        return;
      }
      const clusterId = `CLUSTER::${kind}`;
      members.forEach(node => mappedIds.set(node.id, clusterId));
      collapsedNodes.push({
        id: clusterId,
        kind: "cluster",
        clusterKind: kind,
        label: `${titleCase(kind)} (${members.length})`,
        attributes: {},
        evidence_ids: unique(members.flatMap(node => node.evidence_ids || [])),
        confidence: Math.max(...members.map(node => node.confidence || 0)),
        identityStatus: "cluster",
        sources: unique(members.flatMap(node => node.sources)),
        members,
      });
    });
    const aggregated = new Map();
    edges.forEach(edge => {
      const source = mappedIds.get(edge.source_node_id);
      const target = mappedIds.get(edge.target_node_id);
      if (!source || !target || source === target) return;
      const key = `${source}|${target}|${edge.relationship}`;
      const previous = aggregated.get(key);
      if (previous) {
        previous.evidence_ids = unique([
          ...previous.evidence_ids,
          ...(edge.evidence_ids || []),
        ]);
        previous.confidence = Math.max(
          Number(previous.confidence || 0),
          Number(edge.confidence || 0),
        );
        previous.count += 1;
      } else {
        aggregated.set(key, {
          ...edge,
          id: `CLUSTER-EDGE::${key}`,
          source_node_id: source,
          target_node_id: target,
          evidence_ids: [...(edge.evidence_ids || [])],
          count: 1,
        });
      }
    });
    return {nodes: collapsedNodes, edges: [...aggregated.values()]};
  }

  function fallbackReviewSummary(data, item) {
    const candidates = data.records.filter(node =>
      !["authorized_target", "public_source"].includes(node.kind));
    const grouped = priority => candidates.filter(
      node => node.reviewPriority === priority,
    );
    const supported = grouped("supported");
    const reviewFirst = grouped("review_first");
    const lowSignal = grouped("low_signal");
    const suppressed = grouped("suppressed");
    const allEvidence = unique(candidates.flatMap(node => node.evidence_ids || []));
    const overlap = candidates.filter(node =>
      node.publisherCount > 1 && node.reviewPriority !== "suppressed");
    const serviceSignals = candidates.filter(node =>
      node.kind === "service" && node.reviewPriority !== "suppressed");
    const priorityRank = {supported: 0, review_first: 1, low_signal: 2};
    const priorityLeads = candidates
      .filter(node => node.reviewPriority !== "suppressed")
      .sort((left, right) =>
        (priorityRank[left.reviewPriority] ?? 9)
          - (priorityRank[right.reviewPriority] ?? 9)
        || right.publisherCount - left.publisherCount
        || right.confidence - left.confidence
        || String(left.label).localeCompare(String(right.label)))
      .slice(0, 12)
      .map(node => ({
        entity_id: node.id,
        entity_type: node.kind,
        label: node.label,
        public_url: safeUrl(node.attributes?.url || node.label),
        review_priority: node.reviewPriority,
        confidence_label: confidenceLabel(node),
        technical_confidence: node.confidence,
        source_tools: node.sources,
        publisher_count: node.publisherCount,
        explanation: node.plainLanguageExplanation
          || (node.kind === "service"
            ? "A public registration check returned a signal. It does not prove account access or current ownership."
            : node.publisherCount > 1
              ? "Multiple discovery tools returned this page, but shared catalogues can produce the same result."
              : "A discovery tool returned a username match. Compare public profile details before attribution."),
        evidence_ids: node.evidence_ids || [],
      }));
    const sourceCoverage = item.report?.source_coverage || [];
    const coverage = {observed: [], no_results: [], unavailable: [], not_run: []};
    sourceCoverage.forEach(entry => {
      const status = String(entry.status || "not_run").toLocaleLowerCase();
      let group = "not_run";
      if (Number(entry.evidence_count || 0) > 0) group = "observed";
      else if (["unavailable", "not_configured", "missing_configuration"].includes(status)) {
        group = "unavailable";
      } else if (["no_results", "no_result", "covered_no_results"].includes(status)) {
        group = "no_results";
      }
      coverage[group].push(entry);
    });
    const hasSupported = supported.length > 0;
    const hasReviewFirst = reviewFirst.length > 0;
    return {
      verdict: {
        status: hasSupported
          ? "supported_matches"
          : (hasReviewFirst ? "manual_verification_required" : "no_verified_identity_match"),
        title: hasSupported
          ? "Supported identity matches require analyst review"
          : (hasReviewFirst ? "No verified identity match yet" : "No verified identity match"),
        explanation: hasSupported
          ? `${supported.length} candidates reached probable or stronger support. Confirm every cited public record before use.`
          : (hasReviewFirst
            ? `${reviewFirst.length} candidates should be checked first, but none is safe to attribute automatically.`
            : "The collected observations are low-signal leads. More independent public evidence is needed."),
        evidence_ids: allEvidence,
      },
      counts: {
        candidate_observations: candidates.length,
        supported: supported.length,
        review_first: reviewFirst.length,
        low_signal: lowSignal.length,
        suppressed: suppressed.length,
        relationships: data.edges.length,
      },
      priority_leads: priorityLeads,
      key_points: [
        {
          title: "Candidate observations",
          statement: `${candidates.length} public observations were retained; ${supported.length} reached probable or stronger identity support.`,
          evidence_ids: allEvidence,
        },
        ...(overlap.length ? [{
          title: "Cross-tool overlap",
          statement: `${overlap.length} public pages were returned by more than one discovery tool. Catalogue overlap prioritizes review; it does not verify identity.`,
          evidence_ids: unique(overlap.flatMap(node => node.evidence_ids || [])),
        }] : []),
        ...(serviceSignals.length ? [{
          title: "Service-registration signals",
          statement: `${serviceSignals.length} public service signal was returned. It does not prove access or current ownership.`,
          evidence_ids: unique(serviceSignals.flatMap(node => node.evidence_ids || [])),
        }] : []),
      ],
      coverage,
      cautions: [
        {
          statement: "A matching username or public page does not by itself prove that the investigated person owns the account.",
          evidence_ids: allEvidence,
        },
        ...(overlap.length ? [{
          statement: "Agreement between username discovery tools may come from shared site catalogues and is not independent identity proof.",
          evidence_ids: unique(overlap.flatMap(node => node.evidence_ids || [])),
        }] : []),
      ],
    };
  }

  function coverageMarkup(coverage) {
    const definitions = [
      ["observed", "Returned evidence", "The source ran and returned at least one observation."],
      ["no_results", "Ran, no public result", "No result is not proof that an account does not exist."],
      ["unavailable", "Unavailable", "Configuration or subscription was missing; this is a coverage gap."],
      ["not_run", "Not run / not applicable", "These tools did not contribute evidence to this case."],
    ];
    return definitions.map(([key, title, description]) => {
      const entries = coverage?.[key] || [];
      if (!entries.length) return "";
      return `<div class="coverage-group">
        <strong>${html(title)}</strong>
        <p>${html(description)}</p>
        <div class="chip-row">${entries.map(entry =>
          `<span class="chip">${html(entry.source || "unknown")}${entry.evidence_count
            ? ` · ${html(entry.evidence_count)}` : ""}</span>`).join("")}</div>
      </div>`;
    }).join("") || `<p class="sub">No source-execution details were recorded.</p>`;
  }

  function overviewMarkup(item, data) {
    if (!item.report) {
      return `<div class="empty-tab">
        The plain-language assessment will appear when evidence collection and normalization finish.
      </div>`;
    }
    const summary = data.reviewSummary || fallbackReviewSummary(data, item);
    const verdict = summary.verdict || {};
    const counts = summary.counts || {};
    const leads = summary.priority_leads || [];
    const cautions = (summary.cautions || []).filter(
      entry => (entry.evidence_ids || []).length,
    );
    return `<section class="plain-overview">
      <article class="verdict-card verdict-${html(verdict.status || "unknown")}">
        <div>
          <p class="eyebrow">Plain-language assessment</p>
          <h3>${html(verdict.title || "Assessment pending")}</h3>
          <p>${html(verdict.explanation || "The evidence graph is still loading.")}</p>
          ${evidenceReferences(verdict.evidence_ids || [])}
        </div>
        <div class="verdict-counts">
          <div><strong>${html(counts.supported || 0)}</strong><span>Supported</span></div>
          <div><strong>${html(counts.review_first || 0)}</strong><span>Check first</span></div>
          <div><strong>${html(counts.low_signal || 0)}</strong><span>Unverified</span></div>
          <div><strong>${html(counts.suppressed || 0)}</strong><span>Hidden noise</span></div>
        </div>
      </article>
      <div class="overview-callout">
        <strong>How to read this result</strong>
        <p>A candidate means “a tool found a public trace worth checking.” It does not mean DeepVault verified that the person owns it.</p>
      </div>
      <section class="priority-section">
        <div class="section-heading"><div><p class="eyebrow">Review queue</p>
          <h3>What to check first</h3></div>
          <p class="sub">Ordered by evidence quality and cross-tool overlap, never by how dramatic a site appears.</p></div>
        <div class="lead-list">${leads.slice(0, 10).map((lead, index) => {
          const url = safeUrl(lead.public_url || lead.label);
          return `<article class="lead-card lead-${html(lead.review_priority)}">
            <span class="lead-rank">${index + 1}</span>
            <div class="lead-copy">
              <div class="lead-heading"><strong>${html(lead.label || lead.entity_id)}</strong>
                <span class="review-badge">${html(lead.confidence_label || "Unverified lead")}</span></div>
              <p>${html(lead.explanation)}</p>
              <div class="lead-meta"><span>${html((lead.source_tools || []).join(" + ") || "unknown source")}</span>
                <span>${html(percent(lead.technical_confidence))} technical confidence</span></div>
              ${evidenceReferences(lead.evidence_ids || [])}
            </div>
            <div class="lead-actions">
              <button class="secondary overview-focus" type="button"
                data-node-id="${html(lead.entity_id)}">View on graph</button>
              ${url ? `<a class="secondary" href="${html(url)}" target="_blank"
                rel="noreferrer">Open public page</a>` : ""}
            </div>
          </article>`;
        }).join("") || `<div class="empty-tab compact-empty">No candidate is ready for prioritized review.</div>`}</div>
      </section>
      <section class="overview-grid">
        <article class="panel"><p class="eyebrow">What was actually found</p>
          ${(summary.key_points || []).map(point => `<div class="plain-finding">
            <strong>${html(point.title)}</strong><p>${html(point.statement)}</p>
            ${evidenceReferences(point.evidence_ids || [])}</div>`).join("")
            || `<p class="sub">No cited observations are available.</p>`}</article>
        <article class="panel"><p class="eyebrow">What you must not conclude</p>
          ${cautions.map(caution => `<div class="plain-finding caution">
            <p>${html(caution.statement)}</p>${evidenceReferences(caution.evidence_ids)}</div>`).join("")
            || `<p class="sub">No evidence-backed cautions were generated.</p>`}
          ${Number(counts.suppressed || 0) ? `<div class="privacy-note">
            ${html(counts.suppressed)} misleading, generic, rejected, or sensitive candidate(s) are hidden by default.
            They remain in the evidence ledger for authorized audit.</div>` : ""}
        </article>
        <article class="panel overview-wide"><p class="eyebrow">Tool coverage — not person facts</p>
          <p class="sub">Unavailable and no-result sources reduce what DeepVault can conclude. They are not evidence about the person.</p>
          <div class="coverage-groups">${coverageMarkup(summary.coverage)}</div>
        </article>
        <article class="panel overview-wide next-step-panel"><p class="eyebrow">Recommended manual check</p>
          <ol>
            <li>Open a prioritized public page.</li>
            <li>Compare biography, location, employer, profile links, and stable public identifiers.</li>
            <li>Record supporting or contradictory evidence before changing identity status.</li>
            <li>Do not use account recovery, passwords, cookies, private messages, or leaked credentials.</li>
          </ol>
        </article>
      </section>
    </section>`;
  }

  function graphMarkup(item, state, data) {
    const filters = availableFilters(data);
    const visible = filteredGraph(data, state);
    const suppressedCount = data.records.filter(
      node => node.reviewPriority === "suppressed",
    ).length;
    return `
      <div class="graph-mode-banner">
        <div><strong>${state.simpleGraph ? "Simplified evidence map" : "Full technical graph"}</strong>
          <span>Showing ${visible.nodes.length} of ${data.records.length} entities</span></div>
        <button class="secondary" id="graph-mode" type="button">${state.simpleGraph
          ? "Show full technical graph" : "Return to simplified graph"}</button>
      </div>
      <section class="graph-toolbar">
        <label>Source
          <select id="graph-source-filter">
            <option value="all">All cited sources</option>
            ${filters.sources.map(source => `<option value="${html(source)}"
              ${state.source === source ? "selected" : ""}>${html(source)}</option>`).join("")}
          </select>
        </label>
        <label>Entity type
          <select id="graph-type-filter">
            <option value="all">All entity types</option>
            ${filters.types.map(type => `<option value="${html(type)}"
              ${state.type === type ? "selected" : ""}>${html(titleCase(type))}</option>`).join("")}
          </select>
        </label>
        <label class="confidence-filter">Minimum confidence
          <span id="confidence-value">${Math.round(state.minimumConfidence * 100)}%</span>
          <input id="graph-confidence-filter" type="range" min="0" max="100"
            value="${Math.round(state.minimumConfidence * 100)}">
        </label>
        <div class="graph-buttons">
          <button class="secondary" id="graph-fit" type="button">Fit</button>
          <button class="secondary ${state.collapsed ? "active" : ""}"
            id="graph-collapse" type="button">${state.collapsed ? "Expand clusters" : "Collapse clusters"}</button>
          <button class="secondary ${state.showLabels ? "active" : ""}"
            id="graph-labels" type="button">Edge labels</button>
          ${!state.simpleGraph && suppressedCount ? `<button class="secondary ${state.showSuppressed ? "active" : ""}"
            id="graph-suppressed" type="button">${state.showSuppressed
              ? "Hide suppressed results" : `Show ${suppressedCount} suppressed`}</button>` : ""}
          <button class="secondary" id="graph-save" type="button">Save layout</button>
        </div>
      </section>
      <section class="graph-shell">
        <div class="graph-stage">
          <svg id="identity-map" viewBox="0 0 1000 650"
            role="img" aria-label="Evidence-backed identity graph"></svg>
          <div class="graph-help">
            Wheel to zoom · drag background to pan · drag nodes to arrange ·
            double-click for neighborhood · Shift-click to compare
          </div>
          <div class="graph-legend">
            <span><i class="solid"></i> evidence-supported relationship</span>
            <span><i class="dashed"></i> unverified candidate</span>
            <span><b class="legend-target">P</b> authorized target</span>
            <span><b class="legend-breach">!</b> breach metadata</span>
            <span>Confidence helps order review; it does not prove ownership</span>
          </div>
        </div>
        <aside class="node-inspector" id="node-inspector">
          ${inspectorMarkup(item, state, data)}
        </aside>
      </section>`;
  }

  function nodeSourcesMarkup(node) {
    return (node.sources || []).length
      ? `<div class="chip-row">${node.sources.map(source =>
          `<span class="chip">${html(source)}</span>`).join("")}</div>`
      : `<p class="sub">No publisher metadata on this node.</p>`;
  }

  function inspectorMarkup(item, state, data) {
    const selectedIds = [...state.selectedIds];
    const selected = selectedIds
      .map(id => data.records.find(node => node.id === id))
      .filter(Boolean);
    if (selected.length > 1) {
      const commonEvidence = selected
        .map(node => new Set(node.evidence_ids || []))
        .reduce((common, values) =>
          new Set([...common].filter(value => values.has(value))));
      return `
        <p class="eyebrow">Compare entities</p>
        <h3>${selected.length} selected nodes</h3>
        ${selected.map(node => `<article class="inspector-entity">
          <strong>${html(node.label)}</strong>
          <span>${html(titleCase(node.kind))} · ${html(confidenceLabel(node))}</span>
        </article>`).join("")}
        <h4>Shared evidence</h4>
        <p class="evidence">${[...commonEvidence].map(html).join(" · ") || "No shared evidence IDs"}</p>
        <p class="inspector-warning">Shared identifiers are analyst leads, not proof that one person owns every account.</p>`;
    }
    const selectedId = selectedIds[0] || state.focusNodeId;
    const node = data.records.find(entry => entry.id === selectedId)
      || filteredGraph(data, state).nodes.find(entry => entry.id === selectedId);
    if (!node) {
      return `
        <p class="eyebrow">Node inspector</p>
        <h3>Select an entity</h3>
        <p class="sub">Click a node to inspect its confidence, cited evidence, provenance, attributes, and authorized pivot options.</p>
        <div class="inspector-warning">Every visible relationship is a source observation or an explicitly uncertain hypothesis. It is never an automatic ownership claim.</div>`;
    }
    if (node.kind === "cluster") {
      return `
        <p class="eyebrow">Collapsed entity cluster</p>
        <h3>${html(node.label)}</h3>
        <p>${html(node.members?.length || 0)} entities are grouped by type for visual clarity. Their individual evidence records and confidence values remain unchanged.</p>
        ${nodeSourcesMarkup(node)}
        <h4>Evidence IDs</h4>
        <p class="evidence">${(node.evidence_ids || []).map(html).join(" · ")}</p>
        <button class="secondary" id="expand-selected-cluster" type="button">Expand this graph</button>`;
    }
    const adjacent = data.edges.filter(edge =>
      edge.source_node_id === node.id || edge.target_node_id === node.id);
    const pivots = data.pivots.filter(pivot => pivot.node_id === node.id);
    const attributes = Object.entries(node.attributes || {}).filter(
      ([key]) => !["password", "token", "cookie", "secret"].some(
        blocked => key.toLocaleLowerCase().includes(blocked),
      ),
    );
    const profileUrl = safeUrl(node.attributes?.url || node.label);
    return `
      <p class="eyebrow">${html(titleCase(node.kind))}</p>
      <h3>${html(node.label)}</h3>
      <div class="inspector-score">
        <strong>${html(confidenceLabel(node))}</strong>
        <span>${html(percent(node.confidence))} technical confidence ·
          ${html(titleCase(node.identityStatus))}</span>
      </div>
      ${nodeSourcesMarkup(node)}
      ${profileUrl ? `<a class="secondary inspector-link" href="${html(profileUrl)}"
        target="_blank" rel="noreferrer">Open cited public page</a>` : ""}
      <h4>Why this match?</h4>
      <p>${html(node.plainLanguageExplanation || node.hypothesis?.claim
        || "A cited source produced this observation. It is not an automatic identity or ownership claim.")}</p>
      ${(node.hypothesis?.limitations || []).length
        ? `<ul class="compact-list">${node.hypothesis.limitations.map(value =>
            `<li>${html(value)}</li>`).join("")}</ul>` : ""}
      <h4>Evidence IDs</h4>
      <p class="evidence">${(node.evidence_ids || []).map(html).join(" · ")
        || "Target context supplied by the authorized analyst"}</p>
      ${attributes.length ? `<h4>Public attributes</h4>
        <dl class="attribute-list">${attributes.map(([key, value]) =>
          `<dt>${html(titleCase(key))}</dt><dd>${html(
            typeof value === "object" ? JSON.stringify(value) : value,
          )}</dd>`).join("")}</dl>` : ""}
      <h4>Relationships (${adjacent.length})</h4>
      ${adjacent.slice(0, 12).map(edge => {
        const peerId = edge.source_node_id === node.id
          ? edge.target_node_id : edge.source_node_id;
        const peer = data.nodeById[peerId];
        return `<article class="relationship-card">
          <strong>${html(relationshipLabel(edge.relationship))}</strong>
          <span>${html(peer?.label || peerId)} · ${html(percent(edge.confidence))}</span>
          <small>${html(edge.explanation || "")}</small>
          <em>${(edge.evidence_ids || []).map(html).join(" · ")}</em>
        </article>`;
      }).join("") || `<p class="sub">No visible adjacent relationship.</p>`}
      <div class="inspector-actions">
        <button class="secondary" id="focus-node" type="button">Show neighborhood</button>
        ${state.focusNodeId
          ? `<button class="secondary" id="clear-focus" type="button">Show full graph</button>`
          : ""}
      </div>
      ${pivots.length ? `<h4>Evidence-backed analyst pivots</h4>
        ${pivots.slice(0, 5).map(pivot => `<article class="pivot-card">
          <strong>#${html(pivot.rank)} · ${html(pivot.title)}</strong>
          <p>${html(pivot.rationale)}</p>
          <small>${html(pivot.action)}</small>
          <em>${(pivot.evidence_ids || []).map(html).join(" · ")}</em>
        </article>`).join("")}` : ""}
      ${pivotActionsMarkup(item, node)}
      <div id="pivot-status" class="sub"></div>`;
  }

  function pivotActionsMarkup(item, node) {
    if (item.status !== "completed") return "";
    const allowed = new Set(item.permitted_sources || []);
    const definitions = {
      username_observation: {
        entityType: "username",
        value: node.label,
        transforms: ["sherlock", "maigret", "spiderfoot", "blackbird"],
      },
      email_observation: {
        entityType: "email",
        value: item.target_email,
        transforms: ["holehe", "spiderfoot", "blackbird", "ghunt"],
      },
    };
    const definition = definitions[node.kind];
    if (!definition?.value) return "";
    const transforms = definition.transforms.filter(name => allowed.has(name));
    if (!transforms.length) return "";
    return `<h4>Authorized transforms</h4>
      <p class="sub">Each run stays inside this case scope and cites this node’s evidence.</p>
      <div class="inspector-actions">${transforms.map(transform =>
        `<button class="secondary graph-pivot" type="button"
          data-transform="${html(transform)}"
          data-entity-type="${html(definition.entityType)}"
          data-value="${html(encodeURIComponent(definition.value))}"
          data-node-id="${html(node.id)}">Run ${html(transform)}</button>`).join("")}</div>`;
  }

  function evidenceMarkup(data) {
    return `<section class="panel workbench-table-panel">
      <div class="section-heading"><div><p class="eyebrow">Evidence ledger</p>
        <h3>${data.evidence.length} normalized observations</h3></div>
        <p class="sub">Every row is redacted for display and retains its immutable evidence ID.</p></div>
      <div class="table-wrap"><table class="evidence-table">
        <thead><tr><th>Evidence</th><th>Type</th><th>Source</th><th>Confidence</th>
          <th>Identity status</th><th>Observed</th><th>Public source</th></tr></thead>
        <tbody>${data.evidence.map(entry => {
          const url = safeUrl(entry.source_url);
          return `<tr><td><code>${html(entry.id)}</code><small>${html(entry.value)}</small></td>
            <td>${html(entry.type)}</td><td>${html(entry.source)}</td>
            <td>${html(percent(entry.confidence))}</td>
            <td>${html(titleCase(entry.identity_status || "insufficient_evidence"))}</td>
            <td>${entry.observed_at ? html(new Date(entry.observed_at).toLocaleString()) : "—"}</td>
            <td>${url ? `<a href="${html(url)}" target="_blank" rel="noreferrer">Open</a>` : "—"}</td></tr>`;
        }).join("") || `<tr><td colspan="7">No normalized evidence yet.</td></tr>`}</tbody>
      </table></div></section>`;
  }

  function timelineMarkup(item) {
    const timeline = item.report?.timeline || [];
    return `<section class="timeline-board">
      <div class="section-heading"><div><p class="eyebrow">Evidence-derived timeline</p>
        <h3>${timeline.length} source-stated events</h3></div>
        <p class="sub">Collection timestamps are not presented as person-history events.</p></div>
      ${timeline.map(event => `<article class="timeline-event">
        <time>${html(new Date(event.occurred_at).toLocaleString())}</time>
        <div><h4>${html(event.description)}</h4>
          <p class="evidence">${(event.evidence_ids || []).map(html).join(" · ")}</p></div>
      </article>`).join("") || `<div class="empty-tab">No source-stated event dates are available.</div>`}
    </section>`;
  }

  function reportMarkup(item, helpers, data) {
    const report = item.report;
    if (!report) {
      return `<div class="empty-tab">The evidence-linked report is not ready.</div>`;
    }
    const coverage = report.source_coverage || [];
    const contradictions = report.contradictions || [];
    const recommendations = report.recommendations || [];
    return `
      <section class="report-grid">
        <article class="panel report-summary"><p class="eyebrow">Executive assessment</p>
          <h3>${html(item.target_name)}</h3><p class="summary">${html(report.executive_summary)}</p>
          <div class="metric-strip"><span>Identity <b>${html(report.identity_confidence)}</b></span>
            <span>Exposure <b>${html(report.overall_risk)}</b></span>
            <span>Coverage <b>${html(report.coverage_assessment)}</b></span></div></article>
        <article class="panel"><p class="eyebrow">Source coverage</p>
          <div class="chip-row">${coverage.map(source =>
            `<span class="chip">${html(source.source)} · ${html(source.evidence_count)} · ${html(source.status)}</span>`
          ).join("") || `<span class="sub">No coverage records.</span>`}</div></article>
        <article class="panel report-wide"><p class="eyebrow">Evidence-linked findings</p>
          ${helpers.renderFindingGroups(report.findings || [])
            || `<p class="sub">No evidence-backed findings.</p>`}</article>
        <article class="panel"><p class="eyebrow">Contradictions</p>
          ${contradictions.map(entry => `<div class="finding"><p>${html(entry.description)}</p>
            <small>${html(entry.recommendation)}</small>
            <em class="evidence">${(entry.evidence_ids || []).map(html).join(" · ")}</em></div>`
          ).join("") || `<p class="sub">No evidence-backed contradictions.</p>`}</article>
        <article class="panel"><p class="eyebrow">Recommendations</p>
          <ol class="compact-list">${recommendations.map(entry =>
            `<li>${html(entry)}</li>`).join("")}</ol></article>
        <article class="panel report-wide"><p class="eyebrow">Analyst-triggered transforms</p>
          <p class="sub">Transforms execute only after an explicit click and remain authorization-gated.</p>
          <div class="actions">${helpers.transformActions(item).join("")
            || `<span class="sub">No applicable target transforms are approved.</span>`}</div>
          <p class="sub">${data.pivots.length} evidence-backed manual review pivots are available in the graph inspector.</p>
        </article>
      </section>`;
  }

  function renderGraphSvg(item, state, data) {
    const previousSvg = document.querySelector("#identity-map");
    if (!previousSvg) return;
    const svg = previousSvg.cloneNode(false);
    previousSvg.replaceWith(svg);
    const visible = filteredGraph(data, state);
    layoutNodes(visible.nodes, state);
    const marker = `<defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5"
        markerWidth="5" markerHeight="5" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#60749a"></path>
      </marker>
      <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"></feGaussianBlur>
        <feMerge><feMergeNode in="blur"></feMergeNode><feMergeNode in="SourceGraphic"></feMergeNode></feMerge></filter>
      </defs>`;
    const edgeMarkup = visible.edges.map(edge => {
      const source = state.positions.get(edge.source_node_id);
      const target = state.positions.get(edge.target_node_id);
      if (!source || !target) return "";
      const dashed = ["possible", "insufficient_evidence"].includes(edge.identity_status);
      const middleX = (source.x + target.x) / 2;
      const middleY = (source.y + target.y) / 2;
      return `<g class="graph-edge ${dashed ? "possible" : ""}"
        data-source-node="${html(edge.source_node_id)}"
        data-target-node="${html(edge.target_node_id)}">
        <line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"
          marker-end="url(#arrow)"><title>${html(edge.explanation || edge.relationship)} ·
          Evidence ${(edge.evidence_ids || []).map(html).join(", ")}</title></line>
        ${state.showLabels ? `<text x="${middleX}" y="${middleY - 6}">${html(
          edge.count > 1
            ? `${relationshipLabel(edge.relationship)} ×${edge.count}`
            : relationshipLabel(edge.relationship),
        )}</text>` : ""}
      </g>`;
    }).join("");
    const nodeMarkup = visible.nodes.map(node => {
      const position = state.positions.get(node.id);
      const selected = state.selectedIds.has(node.id);
      const color = palette[node.kind] || palette.public_observation;
      const confidence = Math.max(0, Math.min(1, Number(node.confidence || 0)));
      const circumference = 2 * Math.PI * 31;
      const dash = circumference * confidence;
      return `<g class="graph-node ${selected ? "selected" : ""}"
        data-node-id="${html(node.id)}" transform="translate(${position.x} ${position.y})"
        tabindex="0" role="button" aria-label="${html(node.label)}">
        <circle class="node-halo" r="38"></circle>
        <circle class="node-body" r="30" fill="${color}"></circle>
        <circle class="confidence-ring" r="34"
          stroke="${confidenceColor(node.confidence)}"
          stroke-dasharray="${dash} ${circumference - dash}"
          transform="rotate(-90)"></circle>
        <text class="node-icon" y="6">${html(entityIcons[node.kind] || "O")}</text>
        <text class="node-label" y="52">${html(String(node.label).slice(0, 34))}</text>
        <text class="node-score" y="67">${html(confidenceLabel(node))}</text>
        <title>${html(node.label)} · Evidence ${(node.evidence_ids || []).map(html).join(", ")}</title>
      </g>`;
    }).join("");
    const transform = state.viewport;
    svg.innerHTML = `${marker}<g id="graph-world"
      transform="translate(${transform.x} ${transform.y}) scale(${transform.zoom})">
      ${edgeMarkup}${nodeMarkup}</g>`;
    bindGraphInteractions(item, state, data, visible);
  }

  function bindGraphInteractions(item, state, data, visible) {
    const svg = document.querySelector("#identity-map");
    if (!svg) return;
    let pan = null;
    let dragging = null;
    const point = event => {
      const bounds = svg.getBoundingClientRect();
      return {
        x: (event.clientX - bounds.left) * 1000 / bounds.width,
        y: (event.clientY - bounds.top) * 650 / bounds.height,
      };
    };
    const updateViewport = () => {
      const world = svg.querySelector("#graph-world");
      if (world) {
        world.setAttribute(
          "transform",
          `translate(${state.viewport.x} ${state.viewport.y}) scale(${state.viewport.zoom})`,
        );
      }
    };
    const updateNodeGeometry = nodeId => {
      const position = state.positions.get(nodeId);
      const nodeElement = [...svg.querySelectorAll(".graph-node")]
        .find(element => element.dataset.nodeId === nodeId);
      if (nodeElement && position) {
        nodeElement.setAttribute("transform", `translate(${position.x} ${position.y})`);
      }
      svg.querySelectorAll(".graph-edge").forEach(edgeElement => {
        const source = state.positions.get(edgeElement.dataset.sourceNode);
        const target = state.positions.get(edgeElement.dataset.targetNode);
        if (!source || !target) return;
        const line = edgeElement.querySelector("line");
        line?.setAttribute("x1", source.x);
        line?.setAttribute("y1", source.y);
        line?.setAttribute("x2", target.x);
        line?.setAttribute("y2", target.y);
        const label = edgeElement.querySelector("text");
        label?.setAttribute("x", (source.x + target.x) / 2);
        label?.setAttribute("y", (source.y + target.y) / 2 - 6);
      });
    };
    svg.addEventListener("wheel", event => {
      event.preventDefault();
      const cursor = point(event);
      const previous = state.viewport.zoom;
      const next = Math.max(0.35, Math.min(3, previous * (event.deltaY < 0 ? 1.12 : 0.89)));
      state.viewport.x = cursor.x - (cursor.x - state.viewport.x) * next / previous;
      state.viewport.y = cursor.y - (cursor.y - state.viewport.y) * next / previous;
      state.viewport.zoom = next;
      updateViewport();
    }, {passive: false});
    svg.addEventListener("pointerdown", event => {
      if (event.target.closest(".graph-node")) return;
      pan = {pointer: point(event), viewport: {...state.viewport}};
      svg.setPointerCapture(event.pointerId);
    });
    svg.addEventListener("pointermove", event => {
      if (dragging) {
        const cursor = point(event);
        state.positions.set(dragging.id, {
          x: (cursor.x - state.viewport.x) / state.viewport.zoom - dragging.offset.x,
          y: (cursor.y - state.viewport.y) / state.viewport.zoom - dragging.offset.y,
        });
        updateNodeGeometry(dragging.id);
        return;
      }
      if (!pan) return;
      const cursor = point(event);
      state.viewport.x = pan.viewport.x + cursor.x - pan.pointer.x;
      state.viewport.y = pan.viewport.y + cursor.y - pan.pointer.y;
      updateViewport();
    });
    svg.addEventListener("pointerup", event => {
      pan = null;
      dragging = null;
      try { svg.releasePointerCapture(event.pointerId); } catch (_) {}
    });
    svg.querySelectorAll(".graph-node").forEach(element => {
      const nodeId = element.dataset.nodeId;
      element.addEventListener("pointerdown", event => {
        event.stopPropagation();
        const cursor = point(event);
        const position = state.positions.get(nodeId);
        dragging = {
          id: nodeId,
          offset: {
            x: (cursor.x - state.viewport.x) / state.viewport.zoom - position.x,
            y: (cursor.y - state.viewport.y) / state.viewport.zoom - position.y,
          },
        };
        svg.setPointerCapture(event.pointerId);
      });
      element.addEventListener("click", event => {
        event.stopPropagation();
        if (event.shiftKey) {
          if (state.selectedIds.has(nodeId)) state.selectedIds.delete(nodeId);
          else state.selectedIds.add(nodeId);
        } else {
          state.selectedIds = new Set([nodeId]);
        }
        updateInspector(item, state, data);
        renderGraphSvg(item, state, data);
      });
      element.addEventListener("dblclick", event => {
        event.preventDefault();
        state.focusNodeId = nodeId;
        state.selectedIds = new Set([nodeId]);
        drawActiveGraph(item, state, data);
      });
    });
    if (!visible.nodes.length) {
      svg.innerHTML += `<text x="500" y="325" class="graph-empty"
        text-anchor="middle">No entities match the active filters.</text>`;
    }
  }

  function updateInspector(item, state, data) {
    const inspector = document.querySelector("#node-inspector");
    if (!inspector) return;
    inspector.innerHTML = inspectorMarkup(item, state, data);
    bindInspector(item, state, data);
  }

  function bindInspector(item, state, data) {
    document.querySelector("#expand-selected-cluster")?.addEventListener("click", () => {
      state.collapsed = false;
      state.selectedIds = new Set();
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#focus-node")?.addEventListener("click", () => {
      state.focusNodeId = [...state.selectedIds][0] || null;
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#clear-focus")?.addEventListener("click", () => {
      state.focusNodeId = null;
      drawActiveGraph(item, state, data);
    });
    document.querySelectorAll(".graph-pivot").forEach(button =>
      button.addEventListener("click", async () => {
        const status = document.querySelector("#pivot-status");
        button.disabled = true;
        if (status) status.textContent = `Queueing ${button.dataset.transform}…`;
        const node = data.records.find(entry => entry.id === button.dataset.nodeId);
        try {
          await state.helpers.api(`/api/investigations/${item.id}/transforms`, {
            method: "POST",
            body: JSON.stringify({
              transform: button.dataset.transform,
              entity_type: button.dataset.entityType,
              value: decodeURIComponent(button.dataset.value),
              evidence_ids: node?.evidence_ids || [],
              pivot_depth: 1,
            }),
          });
          if (status) status.textContent = "Transform queued with cited evidence.";
        } catch (error) {
          if (status) status.textContent = error.message;
        } finally {
          button.disabled = false;
        }
      }));
  }

  function drawActiveGraph(item, state, data) {
    const panel = document.querySelector("[data-tab-panel='graph']");
    if (!panel) return;
    panel.innerHTML = graphMarkup(item, state, data);
    bindGraphControls(item, state, data);
    renderGraphSvg(item, state, data);
  }

  function bindGraphControls(item, state, data) {
    document.querySelector("#graph-mode")?.addEventListener("click", () => {
      state.simpleGraph = !state.simpleGraph;
      if (state.simpleGraph) state.showSuppressed = false;
      state.source = "all";
      state.type = "all";
      state.minimumConfidence = 0;
      state.focusNodeId = null;
      state.selectedIds = new Set();
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-source-filter")?.addEventListener("change", event => {
      state.source = event.target.value;
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-type-filter")?.addEventListener("change", event => {
      state.type = event.target.value;
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-confidence-filter")?.addEventListener("input", event => {
      state.minimumConfidence = Number(event.target.value) / 100;
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-fit")?.addEventListener("click", () => {
      state.viewport = {x: 0, y: 0, zoom: 1};
      renderGraphSvg(item, state, data);
    });
    document.querySelector("#graph-collapse")?.addEventListener("click", () => {
      state.collapsed = !state.collapsed;
      state.focusNodeId = null;
      state.selectedIds = new Set();
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-labels")?.addEventListener("click", () => {
      state.showLabels = !state.showLabels;
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-suppressed")?.addEventListener("click", () => {
      state.showSuppressed = !state.showSuppressed;
      state.focusNodeId = null;
      state.selectedIds = new Set();
      drawActiveGraph(item, state, data);
    });
    document.querySelector("#graph-save")?.addEventListener("click", async event => {
      const button = event.currentTarget;
      button.disabled = true;
      const validIds = new Set(data.nodes.map(node => node.id));
      const nodes = [...state.positions.entries()]
        .filter(([id]) => validIds.has(id))
        .map(([id, position]) => ({id, x: position.x, y: position.y, collapsed: false}));
      try {
        await state.helpers.api(`/api/investigations/${item.id}/graph-layout`, {
          method: "POST",
          body: JSON.stringify({nodes, viewport: state.viewport}),
        });
        button.textContent = "Layout saved";
      } catch (error) {
        button.textContent = error.message;
      } finally {
        setTimeout(() => {
          button.disabled = false;
          button.textContent = "Save layout";
        }, 1800);
      }
    });
    bindInspector(item, state, data);
  }

  function drawActiveOverview(item, state, data) {
    const panel = document.querySelector("[data-tab-panel='overview']");
    if (!panel) return;
    panel.innerHTML = overviewMarkup(item, data);
    panel.querySelectorAll(".overview-focus").forEach(button =>
      button.addEventListener("click", () => {
        state.tab = "graph";
        state.simpleGraph = true;
        state.focusNodeId = button.dataset.nodeId;
        state.selectedIds = new Set([button.dataset.nodeId]);
        showTab(item, state, data);
      }));
  }

  function showTab(item, state, data) {
    document.querySelectorAll("[data-result-tab]").forEach(button =>
      button.classList.toggle("active", button.dataset.resultTab === state.tab));
    document.querySelectorAll("[data-tab-panel]").forEach(panel => {
      panel.hidden = panel.dataset.tabPanel !== state.tab;
    });
    if (state.tab === "overview") drawActiveOverview(item, state, data);
    if (state.tab === "graph") drawActiveGraph(item, state, data);
  }

  function hydrateGraphDocument(item, state) {
    if (state.graphLoaded || state.graphLoading || !item.has_report) return;
    state.graphLoading = true;
    state.helpers.api(`/api/investigations/${item.id}/graph`)
      .then(document => {
        state.graphDocument = document;
        state.graphLoaded = true;
        const savedNodes = document.layout?.nodes;
        if (Array.isArray(savedNodes)) {
          savedNodes.forEach(node => {
            if (node?.id && Number.isFinite(node.x) && Number.isFinite(node.y)) {
              state.positions.set(node.id, {x: node.x, y: node.y});
            }
          });
        }
        const savedViewport = document.layout?.viewport;
        if (savedViewport && Number.isFinite(savedViewport.zoom)) {
          state.viewport = {
            x: Number(savedViewport.x || 0),
            y: Number(savedViewport.y || 0),
            zoom: Number(savedViewport.zoom || 1),
          };
        }
        const freshData = graphData(item, state);
        if (state.tab === "overview") drawActiveOverview(item, state, freshData);
        if (state.tab === "graph") drawActiveGraph(item, state, freshData);
      })
      .catch(() => {})
      .finally(() => {
        state.graphLoading = false;
      });
  }

  function render(item, helpers) {
    const state = currentState(item.id);
    const graphVersion = item.report
      ? [
          item.report.report_id || "report",
          item.report.evidence_count || 0,
          item.report.identity_graph?.nodes?.length || 0,
          item.report.identity_graph?.edges?.length || 0,
        ].join(":")
      : "pending";
    if (state.graphVersion !== graphVersion) {
      state.graphVersion = graphVersion;
      state.graphDocument = null;
      state.graphLoaded = false;
    }
    state.item = item;
    state.helpers = helpers;
    const data = graphData(item, state);
    const report = item.report;
    const reviewSummary = data.reviewSummary || fallbackReviewSummary(data, item);
    const progress = item.progress || {};
    const progressPercent = Math.max(0, Math.min(100, Number(progress.percent) || 0));
    const stats = state.graphDocument?.stats || {
      entity_count: data.nodes.length,
      relationship_count: data.edges.length,
      evidence_count: data.evidence.length,
      source_count: unique(data.evidence.map(entry => entry.source)).length,
    };
    const workspace = document.querySelector("#workspace");
    workspace.innerHTML = `
      <div class="case-commandbar">
        <div><p class="eyebrow">CASE ${html(item.authorization_reference || "—")}</p>
          <h2>${html(item.target_name)}</h2>
          <p class="sub">${html(item.target_username || "")}${item.target_email
            ? ` · ${html(emailForDisplay(item.target_email))}` : ""}</p></div>
        <div class="actions export-actions">
          <a class="secondary ${item.has_report ? "" : "disabled"}"
            href="/api/investigations/${item.id}/report.html">Download report</a>
          <details class="export-menu"><summary class="secondary">Export graph</summary>
            <div><a href="/api/investigations/${item.id}/graph.json">JSON</a>
              <a href="/api/investigations/${item.id}/graph.graphml">GraphML</a>
              <a href="/api/investigations/${item.id}/graph.gexf">GEXF</a>
              <a href="/api/investigations/${item.id}/graph.csv">CSV</a>
              <a href="/api/investigations/${item.id}/mapping.osint.json">Mapping schema</a></div>
          </details>
        </div>
      </div>
      <div class="intel-metrics">
        <div><span>Status</span><strong>${helpers.badge(item.status)}</strong></div>
        <div><span>Entities</span><strong>${html(stats.entity_count)}</strong></div>
        <div><span>Relationships</span><strong>${html(stats.relationship_count)}</strong></div>
        <div><span>Evidence</span><strong>${html(stats.evidence_count)}</strong></div>
        <div><span>Sources</span><strong>${html(stats.source_count)}</strong></div>
        <div><span>Identity</span><strong>${html(report?.identity_confidence || "—")}</strong></div>
        <div><span>Exposure</span><strong>${html(report?.overall_risk || item.risk_score || "—")}</strong></div>
      </div>
      ${item.error ? `<div class="notice">${html(item.error)}</div>` : ""}
      ${!report ? `<section class="panel live-progress"><div>
        <p class="eyebrow">Live progress · ${progressPercent}%</p>
        <h3>${html(progress.message || "Waiting for an available worker")}</h3>
        <p class="sub">${html(progress.stage || item.status)}</p></div>
        <div class="progress-track"><div class="progress-bar" style="width:${progressPercent}%"></div></div>
      </section>` : ""}
      <nav class="result-tabs" aria-label="Investigation result views">
        ${[
          ["overview", "Overview", reviewSummary.counts?.review_first || 0],
          ["graph", "Graph", data.nodes.length],
          ["evidence", "Evidence", data.evidence.length],
          ["timeline", "Timeline", report?.timeline?.length || 0],
          ["report", "Report", report?.findings?.length || 0],
        ].map(([name, label, count]) => `<button type="button" data-result-tab="${name}"
          class="${state.tab === name ? "active" : ""}">${label}<span>${count}</span></button>`).join("")}
      </nav>
      <div data-tab-panel="overview"></div>
      <div data-tab-panel="graph"></div>
      <div data-tab-panel="evidence" hidden>${evidenceMarkup(data)}</div>
      <div data-tab-panel="timeline" hidden>${timelineMarkup(item)}</div>
      <div data-tab-panel="report" hidden>${reportMarkup(item, helpers, data)}</div>`;
    document.querySelectorAll("[data-result-tab]").forEach(button =>
      button.addEventListener("click", () => {
        state.tab = button.dataset.resultTab;
        showTab(item, state, data);
      }));
    document.querySelectorAll(".transform-action").forEach(button =>
      button.addEventListener("click", () => helpers.queueTransform(button)));
    showTab(item, state, data);
    hydrateGraphDocument(item, state);
  }

  window.DeepVaultWorkbench = {render};
})();
