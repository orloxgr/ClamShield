// This trusted script renders validated language data as text. No language text is
// parsed as HTML, CSS, JavaScript, a selector, a URL, or an event handler.
(() => {
  'use strict';
  const runtime = window.ClamShieldLocalization;
  window.englishText = runtime.englishText;
  const original = new WeakMap();
  const attributes = new WeakMap();
  let observer;
  const translate = () => {
    observer?.disconnect();
    const language = runtime.getLanguage();
    document.documentElement.lang = language.code;
    document.documentElement.dir = language.direction;
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
    for (let node; (node = walker.nextNode());) {
      if (node.parentElement?.closest('script,style,pre,code,[data-no-localize]')) continue;
      const previous = original.get(node);
      const source = previous && node.textContent === previous.rendered ? previous.source : node.textContent;
      const leading = source.match(/^\s*/)[0], trailing = source.match(/\s*$/)[0];
      const rendered = source.trim() ? leading + runtime.localizeText(source.trim()) + trailing : source;
      node.textContent = rendered;
      original.set(node, { source, rendered });
    }
    for (const element of document.querySelectorAll('[title],[aria-label],[placeholder],[alt]')) {
      const saved = attributes.get(element) || {};
      for (const name of ['title', 'aria-label', 'placeholder', 'alt']) {
        if (!element.hasAttribute(name)) continue;
        const value = element.getAttribute(name), previous = saved[name];
        const source = previous && value === previous.rendered ? previous.source : value;
        const rendered = runtime.localizeText(source);
        element.setAttribute(name, rendered); saved[name] = { source, rendered };
      }
      attributes.set(element, saved);
    }
    observer?.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['title', 'aria-label', 'placeholder', 'alt'] });
  };
  const apply = pack => { try { runtime.setLanguage(pack); translate(); } catch { /* Keep trusted English on invalid data. */ } };
  const start = async () => {
    observer = new MutationObserver(translate);
    translate();
    window.clamshieldLanguage?.onChange(apply);
    try { const pack = await window.clamshieldLanguage?.get(); if (pack) apply(pack); } catch { /* English remains usable. */ }
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
})();
