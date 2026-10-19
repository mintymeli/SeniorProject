(function () {
  const COLORS = {
    High: { bg: "#ffb3b3", border: "#d93025" },
    Medium: { bg: "#ffd9a0", border: "#e37400" },
    Low: { bg: "#fff3a3", border: "#b8a000" },
  };
  const RANK = { High: 3, Medium: 2, Low: 1 };

  function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Gmail renders the message text inside div.a3s (the message body container).
  function messageBodies() {
    return Array.from(document.querySelectorAll("div.a3s"));
  }

  function clearHighlights() {
    document.querySelectorAll("mark.phishcatcher-hl").forEach((mark) => {
      const parent = mark.parentNode;
      if (!parent) return;
      parent.replaceChild(document.createTextNode(mark.textContent), mark);
      parent.normalize();
    });
  }

  // Collect one highlight target per phrase (keeping the most severe reason).
  function collectTargets(findings) {
    const byPhrase = new Map();
    for (const finding of findings || []) {
      for (const item of finding.evidence || []) {
        if (!item.phrase) continue;
        const key = item.phrase.toLowerCase().replace(/\s+/g, " ").trim();
        const existing = byPhrase.get(key);
        if (!existing || RANK[finding.severity] > RANK[existing.severity]) {
          byPhrase.set(key, {
            phrase: item.phrase,
            type: finding.type,
            severity: finding.severity || "Low",
          });
        }
      }
    }
    // Longest first so a long phrase is wrapped before a shorter one inside it.
    return Array.from(byPhrase.values()).sort((a, b) => b.phrase.length - a.phrase.length);
  }

  function highlightInNode(root, target) {
    // Spaces in the phrase match any whitespace (Gmail text nodes can differ from our cleaned text).
    const pattern = escapeRegex(target.phrase.trim()).replace(/\s+/g, "\\s+");
    const regex = new RegExp(pattern, "gi");
    const color = COLORS[target.severity] || COLORS.Low;
    let count = 0;

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest("mark.phishcatcher-hl, script, style")) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });

    const textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);

    for (const node of textNodes) {
      const text = node.nodeValue;
      regex.lastIndex = 0;
      let match;
      let last = 0;
      const fragment = document.createDocumentFragment();
      let changed = false;

      while ((match = regex.exec(text)) !== null) {
        if (match[0].length === 0) { regex.lastIndex++; continue; }
        changed = true;
        fragment.appendChild(document.createTextNode(text.slice(last, match.index)));
        const mark = document.createElement("mark");
        mark.className = "phishcatcher-hl";
        mark.textContent = match[0];
        mark.title = "PhishCatcher: " + target.type;
        mark.style.cssText =
          "background:" + color.bg + ";border-bottom:2px solid " + color.border +
          ";color:inherit;padding:0 1px;border-radius:2px;";
        fragment.appendChild(mark);
        last = match.index + match[0].length;
        count++;
      }

      if (changed) {
        fragment.appendChild(document.createTextNode(text.slice(last)));
        node.parentNode.replaceChild(fragment, node);
      }
    }
    return count;
  }

  function highlight(findings) {
    clearHighlights();
    const targets = collectTargets(findings);
    const bodies = messageBodies();
    let total = 0;
    for (const body of bodies) {
      for (const target of targets) total += highlightInNode(body, target);
    }
    const first = document.querySelector("mark.phishcatcher-hl");
    if (first) first.scrollIntoView({ block: "center", behavior: "smooth" });
    return total;
  }

  window.phishcatcherHighlight = highlight;
  window.phishcatcherClearHighlights = clearHighlights;
})();