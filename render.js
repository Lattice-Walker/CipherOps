const articleContainerId = 'article-container';
const landingId          = 'landing';          // index.html uniquement
const contentPanelId     = 'main-content';

// ── Helpers pour gérer les deux contextes (index / articles) ──────

const hideLandingShowArticle = () => {
  // Contexte index.html
  const landing = document.getElementById(landingId);
  if (landing) landing.style.display = 'none';

  // Contexte articles.html
  const articlesLanding = document.getElementById('articles-landing');
  const articleLayout   = document.getElementById('article-layout');
  if (articlesLanding) articlesLanding.style.display = 'none';
  if (articleLayout)   articleLayout.style.display   = 'flex';
};

const injectArticleDate = (container, date) => {
  if (!container || !date) return;

  const existingDate = container.querySelector('.article-date');
  if (existingDate) existingDate.remove();

  const titleHeading = container.querySelector('h1, h2, h3');
  if (!titleHeading) return;

  const dateElement = document.createElement('p');
  dateElement.className = 'article-date';
  dateElement.textContent = date;
  titleHeading.insertAdjacentElement('afterend', dateElement);
};

const findManifestEntry = (manifest, filePath) => {
  if (!Array.isArray(manifest)) return null;

  for (const category of manifest) {
    if (!category || !Array.isArray(category.articles)) continue;
    for (const article of category.articles) {
      if (article && article.file === filePath) return article;
    }
  }

  return null;
};

const fetchManifestEntry = async (filePath) => {
  const currentPageUrl = new URL(window.location.href);
  const manifestCandidates = [
    new URL('./manifest.json', currentPageUrl).href,
    new URL('./practicalprojects-manifest.json', currentPageUrl).href,
  ];

  if (window.location.pathname.includes('/display_practicalprojects/')) {
    manifestCandidates.unshift(new URL('./practicalprojects-manifest.json', currentPageUrl).href);
  }

  const uniqueCandidates = [...new Set(manifestCandidates)];

  for (const manifestPath of uniqueCandidates) {
    try {
      const response = await fetch(manifestPath, { cache: 'no-cache' });
      if (!response.ok) continue;

      const manifest = await response.json();
      const entry = findManifestEntry(manifest, filePath);
      if (entry) return entry;
    } catch (error) {
      console.warn(`Unable to load manifest ${manifestPath}:`, error);
    }
  }

  return null;
};

const resolveResourceUrl = (rawUrl, sourceFilePath) => {
  if (!rawUrl || rawUrl.startsWith('#') || rawUrl.startsWith('data:')) return rawUrl;
  if (/^(?:[a-z]+:)?\/\//i.test(rawUrl) || /^[a-z]+:/i.test(rawUrl)) return rawUrl;

  try {
    const sourceDir = new URL('../', window.location.href).href;
    const sourceUrl = new URL(sourceFilePath || '.', sourceDir);
    return new URL(rawUrl, sourceUrl.href).href;
  } catch (error) {
    console.warn('Unable to resolve resource URL:', rawUrl, sourceFilePath, error);
    return rawUrl;
  }
};

const rewriteRelativeMediaUrls = (html, sourceFilePath) => {
  if (!html) return html;

  return html.replace(/(src|href)=(['"])(.*?)\2/gi, (match, attribute, quote, value) => {
    const resolvedValue = resolveResourceUrl(value, sourceFilePath);
    return `${attribute}=${quote}${resolvedValue}${quote}`;
  });
};

// Les tableaux larges (formules MathJax, colonnes nombreuses) faisaient
// déborder toute la page horizontalement sur mobile, collant la dernière
// colonne au bord de l'écran. On les enferme dans un conteneur défilable
// pour garder la même marge à droite qu'à gauche.
const wrapTables = (container) => {
  if (!container) return;

  container.querySelectorAll('table').forEach((table) => {
    const parent = table.parentNode;
    if (!parent || (parent.classList && parent.classList.contains('table-wrap'))) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'table-wrap';
    parent.insertBefore(wrapper, table);
    wrapper.appendChild(table);
  });
};

// ── Animated figures: SMIL support, reduced motion, manual toggle ──

// Figures that ship as an animated SVG. `still` is the static SVG shown when
// the reader has asked for reduced motion or pauses the loop; `gif` is the
// original raster animation, used only where SMIL is unavailable.
const ANIMATED_FIGURES = {
  '1Topology.svg': { still: '1Topology-still.svg', gif: '1Topology.gif' }
};

// Browsers without SMIL return a plain SVGElement for <animate>; those with it
// return an SVGAnimateElement. This is the long-standing Modernizr check.
const supportsSMIL = () => {
  if (!document.createElementNS) return false;
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
  return /SVGAnimate/.test(Object.prototype.toString.call(el));
};

const prefersReducedMotion = () =>
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const enhanceAnimatedFigures = (container) => {
  if (!container) return;

  const smil = supportsSMIL();

  container.querySelectorAll('img').forEach((img) => {
    const src  = img.getAttribute('src') || '';
    const name = src.split('/').pop().split('?')[0];
    const spec = ANIMATED_FIGURES[name];
    if (!spec) return;

    const base      = src.slice(0, src.length - name.length);
    const animated  = src;
    const stillSrc  = base + spec.still;
    const gifSrc    = base + spec.gif;

    // No SMIL: fall back to the original GIF and offer no controls, since the
    // browser cannot pause that either.
    if (!smil) {
      img.src = gifSrc;
      return;
    }

    const wrap = document.createElement('figure');
    wrap.className = 'anim-figure';
    img.parentNode.insertBefore(wrap, img);
    wrap.appendChild(img);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'anim-toggle';
    wrap.appendChild(button);

    let playing = !prefersReducedMotion();

    const apply = () => {
      img.src = playing ? animated : stillSrc;
      button.textContent = playing ? 'Pause' : 'Play animation';
      button.setAttribute('aria-pressed', String(playing));
      button.setAttribute(
        'aria-label',
        playing ? 'Pause the topology animation' : 'Play the topology animation'
      );
    };

    button.addEventListener('click', () => { playing = !playing; apply(); });
    apply();
  });
};

const renderMarkdown = (markdown, sourceFilePath = '') => {
  if (typeof marked === 'undefined' || !marked.parse) return markdown;

  const mathExpressions = [];
  // Les corps mathematiques peuvent contenir des dollars echappes (\$, par ex.
  // \xleftarrow{\$}) : on consomme toute sequence \x comme une unite, sinon un
  // tel dollar desynchronise l'appariement pour tout le reste du document.
  const mathBody = String.raw`(?:\\[\s\S]|[^\\])*?`;
  const mathPattern = new RegExp(
    `\\$\\$${mathBody}\\$\\$` +
    `|\\\\\\[${mathBody}\\\\\\]` +
    `|\\\\\\(${mathBody}\\\\\\)` +
    `|(?<!\\$)\\$(?!\\$)(?:\\\\[\\s\\S]|[^\\\\$])+?\\$(?!\\$)`,
    'g',
  );

  // Le code (blocs et spans) peut contenir des dollars qui ne sont pas des
  // mathematiques : on le met de cote avant le scan, puis on le restitue tel
  // quel pour que marked le traite normalement.
  const codeSegments = [];
  const codePattern = /(^|\n) {0,3}(`{3,}|~{3,})[\s\S]*?\n {0,3}\2[^\n]*|(`+)[\s\S]*?\3/g;
  const withoutCode = markdown.replace(codePattern, (segment) => {
    const token = `CIPHEROPSCODE${codeSegments.length}END`;
    codeSegments.push(segment);
    return token;
  });

  const protectedMarkdown = withoutCode
    .replace(mathPattern, (expression) => {
      const token = `CIPHEROPSMATH${mathExpressions.length}END`;
      mathExpressions.push(expression);
      return token;
    })
    .replace(/CIPHEROPSCODE(\d+)END/g, (_, index) => codeSegments[Number(index)] || '');

  const html = marked.parse(protectedMarkdown);
  const htmlWithResolvedUrls = rewriteRelativeMediaUrls(html, sourceFilePath);
  return htmlWithResolvedUrls.replace(/CIPHEROPSMATH(\d+)END/g, (_, index) => mathExpressions[Number(index)] || '');
};

const resolveMarkdownInclude = (includePath, sourceFilePath) => {
  const baseUrl = new URL('../', window.location.href);
  const repositoryPath = includePath.match(/(?:^|\/)((?:articles|courses|practicalprojects)\/.*)$/);
  const normalizedPath = repositoryPath ? repositoryPath[1] : includePath;
  const sourceUrl = new URL(sourceFilePath || '.', baseUrl);
  const url = new URL(normalizedPath, repositoryPath || !sourceFilePath ? baseUrl : sourceUrl);
  const rootPath = new URL(baseUrl).pathname;
  const path = decodeURIComponent(url.pathname).slice(rootPath.length);

  return { path, url };
};

const expandMarkdownIncludes = async (markdown, sourceFilePath, includeStack = new Set()) => {
  const includePattern = /{%\s*include-markdown\s+"([^"]+)"\s*%}/g;
  const matches = [...markdown.matchAll(includePattern)];
  if (!matches.length) return markdown;

  let expanded = '';
  let lastIndex = 0;

  for (const match of matches) {
    expanded += markdown.slice(lastIndex, match.index);

    const include = resolveMarkdownInclude(match[1], sourceFilePath);
    if (includeStack.has(include.path)) {
      throw new Error(`Circular Markdown include: ${[...includeStack, include.path].join(' -> ')}`);
    }

    const response = await fetch(include.url, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(`Unable to load included Markdown: ${response.statusText} (${include.url})`);
    }

    const nextStack = new Set(includeStack);
    nextStack.add(include.path);
    expanded += await expandMarkdownIncludes(await response.text(), include.path, nextStack);
    lastIndex = match.index + match[0].length;
  }

  return expanded + markdown.slice(lastIndex);
};

// ─────────────────────────────────────────────────────────────────

const loadArticle = async (filePath) => {
  const articleContainer = document.getElementById(articleContainerId);
  const contentPanel     = document.getElementById(contentPanelId);
  if (!articleContainer) return;

  try {
    const baseUrl    = new URL('../', window.location.href).href;
    const articleUrl = new URL(filePath, baseUrl).href;
    const response   = await fetch(articleUrl, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(`Unable to load article: ${response.statusText} (${articleUrl})`);
    }

    const markdown = await expandMarkdownIncludes(await response.text(), filePath, new Set([filePath]));
    const html     = renderMarkdown(markdown, filePath);
    const manifestEntry = await fetchManifestEntry(filePath);

    articleContainer.innerHTML = html;
    wrapTables(articleContainer);
    injectArticleDate(articleContainer, manifestEntry && manifestEntry.date);
    injectArticleHexagons(articleContainer);
    enhanceAnimatedFigures(articleContainer);

    hideLandingShowArticle();

    articleContainer.style.display = 'block';
    articleContainer.classList.remove('fade-in');
    void articleContainer.offsetWidth;
    articleContainer.classList.add('fade-in');

    if (contentPanel) contentPanel.scrollTop = 0;
    window.scrollTo({ top: 0, behavior: 'smooth' });

    await renderMath();
    renderPDFs();
    highlightCode();
    buildArticleTOC();

    requestAnimationFrame(() => { renderGraphs(); });

  } catch (error) {
    console.error(error);
    if (articleContainer) {
      articleContainer.innerHTML = `<p>Failed to load article.</p>`;
      articleContainer.style.display = 'block';
      hideLandingShowArticle();
    }
  }
};

// ─────────────────────────────────────────────────────────────────

const renderMath = async () => {
  const articleContainer = document.getElementById(articleContainerId);
  if (!articleContainer || typeof MathJax === 'undefined' || !MathJax.typesetPromise) return;
  try {
    await MathJax.typesetPromise([articleContainer]);
  } catch (error) {
    console.warn('MathJax rendering failed:', error);
  }
};

const highlightCode = () => {
  const articleContainer = document.getElementById(articleContainerId);
  if (!articleContainer || typeof hljs === 'undefined') return;
  articleContainer.querySelectorAll('pre code').forEach((block) => hljs.highlightElement(block));
};

const buildArticleTOC = () => {
  const articleContainer = document.getElementById(articleContainerId);
  const articleToc       = document.getElementById('article-toc');
  if (!articleContainer || !articleToc) return;

  if (buildArticleTOC._observer) {
    buildArticleTOC._observer.disconnect();
    buildArticleTOC._observer = null;
  }

  const headings = articleContainer.querySelectorAll('h2, h3');
  articleToc.innerHTML = '';

  if (headings.length === 0) {
    articleToc.style.display = 'none';
    return;
  }

  articleToc.style.display = 'block';

  const title = document.createElement('p');
  title.className   = 'article-toc-title';
  title.textContent = 'On this page';
  articleToc.appendChild(title);

  const linkMap = new Map();

  headings.forEach((heading, i) => {
    if (!heading.id) {
      heading.id = `section-${i}-${heading.textContent
        .trim().toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w-]/g, '')}`;
    }

    const link       = document.createElement('a');
    link.href        = `#${heading.id}`;
    link.textContent = heading.textContent;
    link.className   = `article-toc-${heading.tagName.toLowerCase()}`;

    link.addEventListener('click', (e) => {
      e.preventDefault();
      heading.scrollIntoView({ behavior: 'smooth' });
    });

    articleToc.appendChild(link);
    linkMap.set(heading.id, link);
  });

  let activeId = null;
  const setActive = (id) => {
    if (id === activeId) return;
    if (activeId && linkMap.has(activeId)) linkMap.get(activeId).classList.remove('toc-active');
    activeId = id;
    if (activeId && linkMap.has(activeId)) linkMap.get(activeId).classList.add('toc-active');
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => { if (entry.isIntersecting) setActive(entry.target.id); });
  }, { rootMargin: '0px 0px -80% 0px', threshold: 0 });

  headings.forEach((h) => observer.observe(h));
  buildArticleTOC._observer = observer;
  if (headings.length > 0) setActive(headings[0].id);
};

// ─────────────────────────────────────────────────────────────────

const renderGraphs = () => {
  const articleContainer = document.getElementById(articleContainerId);
  if (!articleContainer || typeof d3 === 'undefined') return;

  const graphDefs = Array.from(articleContainer.querySelectorAll('.graph-definition'));
  graphDefs.forEach((graphDef) => {
    const jsonText = graphDef.textContent.trim();
    let graphData;
    try { graphData = JSON.parse(jsonText); }
    catch (error) { console.warn('Invalid graph JSON:', error); return; }

    const width     = graphDef.clientWidth || 720;
    const paddingX  = 16;
    const paddingY  = 10;
    const fontSize  = 12;
    const fontFamily = 'Georgia, serif';

    const measureText = (text) => {
      const tempSvg  = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      tempSvg.style.visibility = 'hidden';
      tempSvg.style.position   = 'absolute';
      document.body.appendChild(tempSvg);
      const tempText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      tempText.setAttribute('font-family', fontFamily);
      tempText.setAttribute('font-size', fontSize);
      tempText.textContent = text;
      tempSvg.appendChild(tempText);
      const w = tempText.getBBox().width;
      document.body.removeChild(tempSvg);
      return w;
    };

    const nodeMap = {};
    graphData.nodes.forEach((node) => {
      const textWidth = measureText(node.label || node.id);
      node.boxW = textWidth + paddingX * 2;
      node.boxH = fontSize  + paddingY * 2;
      nodeMap[node.id] = node;
    });

    const isTree = () => {
      const parentCount = {};
      graphData.nodes.forEach((n) => { parentCount[n.id] = 0; });
      graphData.edges.forEach((e) => { parentCount[e.to] = (parentCount[e.to] || 0) + 1; });
      if (Object.values(parentCount).some((c) => c > 1)) return false;
      const roots = graphData.nodes.filter((n) => parentCount[n.id] === 0);
      if (roots.length !== 1) return false;
      const childrenMap = {};
      graphData.edges.forEach((e) => {
        if (!childrenMap[e.from]) childrenMap[e.from] = [];
        childrenMap[e.from].push(e.to);
      });
      const visited = new Set();
      const hasCycle = (id) => {
        if (visited.has(id)) return true;
        visited.add(id);
        for (const child of (childrenMap[id] || [])) { if (hasCycle(child)) return true; }
        visited.delete(id);
        return false;
      };
      return !hasCycle(roots[0].id);
    };

    const createSvg = (height) => {
      const svg = d3.create('svg')
        .attr('width', '100%').attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`)
        .style('overflow', 'visible');
      const arrowId = `arrow-${Math.random().toString(36).substr(2, 9)}`;
      svg.append('defs').append('marker')
        .attr('id', arrowId).attr('viewBox', '0 -5 10 10')
        .attr('refX', 10).attr('refY', 0)
        .attr('markerWidth', 8).attr('markerHeight', 8)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#87A878');
      return { svg, arrowId };
    };

    const getRectBorderPoint = (sx, sy, tx, ty, boxW, boxH) => {
      const dx = tx - sx; const dy = ty - sy;
      const angle = Math.atan2(dy, dx);
      const halfW = boxW / 2; const halfH = boxH / 2;
      const absCos = Math.abs(Math.cos(angle)); const absSin = Math.abs(Math.sin(angle));
      const t = (halfW * absSin <= halfH * absCos) ? halfW / absCos : halfH / absSin;
      return { x: tx - Math.cos(angle) * t, y: ty - Math.sin(angle) * t };
    };

    const drawNodes = (svg, nodesData, getX, getY, getData) => {
      const nodeElements = svg.append('g').selectAll('g').data(nodesData).enter().append('g')
        .attr('transform', (d) => `translate(${getX(d)}, ${getY(d)})`)
        .attr('cursor', 'pointer')
        .on('click', (event, d) => {
          const data = getData(d);
          if (event.target.tagName === 'A') return;
          if (data.link) {
            if (data.link.startsWith('http')) window.open(data.link, '_blank');
            else loadArticle(data.link);
          }
        });

      nodeElements.append('rect')
        .attr('width',  (d) => getData(d).boxW)
        .attr('height', (d) => getData(d).boxH)
        .attr('x', (d) => -getData(d).boxW / 2)
        .attr('y', (d) => -getData(d).boxH / 2)
        .attr('rx', 4).attr('ry', 4)
        .attr('fill', '#FFFFFF').attr('stroke', '#87A878').attr('stroke-width', 2);

      nodeElements.append('foreignObject')
        .attr('width',  (d) => getData(d).boxW)
        .attr('height', (d) => getData(d).boxH)
        .attr('x', (d) => -getData(d).boxW / 2)
        .attr('y', (d) => -getData(d).boxH / 2)
        .append('xhtml:div')
        .style('width', '100%').style('height', '100%')
        .style('display', 'flex').style('align-items', 'center').style('justify-content', 'center')
        .style('font-family', fontFamily).style('font-size', `${fontSize}px`)
        .style('color', '#000000').style('text-align', 'center')
        .style('padding', '0 4px').style('box-sizing', 'border-box')
        .style('pointer-events', 'auto')
        .html((d) => getData(d).html || getData(d).label || getData(d).id);

      return nodeElements;
    };

    const renderTree = () => {
      const levelHeight = 100;
      const childrenMap = {}; const hasParent = new Set();
      graphData.edges.forEach((edge) => {
        if (!childrenMap[edge.from]) childrenMap[edge.from] = [];
        childrenMap[edge.from].push(edge.to);
        hasParent.add(edge.to);
      });
      const rootId = graphData.nodes.find((n) => !hasParent.has(n.id)).id;
      const buildHierarchy = (id) => {
        const node = { ...nodeMap[id] };
        if (childrenMap[id]) node.children = childrenMap[id].map(buildHierarchy);
        return node;
      };
      const hierarchyData = d3.hierarchy(buildHierarchy(rootId));
      const treeLayout = d3.tree().nodeSize([120, levelHeight]);
      treeLayout(hierarchyData);
      let minX = Infinity; let maxX = -Infinity; let maxY = -Infinity;
      hierarchyData.each((d) => {
        if (d.x < minX) minX = d.x; if (d.x > maxX) maxX = d.x; if (d.y > maxY) maxY = d.y;
      });
      const treeWidth = maxX - minX;
      const height    = maxY + levelHeight;
      const offsetX   = (width / 2) - (treeWidth / 2) - minX;
      const offsetY   = levelHeight / 2;
      hierarchyData.each((d) => { d.x += offsetX; d.y += offsetY; });
      const { svg, arrowId } = createSvg(height);
      svg.append('g').selectAll('line').data(hierarchyData.links()).enter().append('line')
        .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
        .attr('x2', (d) => getRectBorderPoint(d.source.x, d.source.y, d.target.x, d.target.y, d.target.data.boxW, d.target.data.boxH).x)
        .attr('y2', (d) => getRectBorderPoint(d.source.x, d.source.y, d.target.x, d.target.y, d.target.data.boxW, d.target.data.boxH).y)
        .attr('stroke', '#B8A9C9').attr('stroke-width', 1.5)
        .attr('marker-end', `url(#${arrowId})`);
      drawNodes(svg, hierarchyData.descendants(), (d) => d.x, (d) => d.y, (d) => d.data);
      graphDef.replaceWith(svg.node());
    };

    const renderForce = () => {
      const height = 420;
      const nodes  = graphData.nodes.map((node, idx) => ({ ...node, index: idx }));
      const links  = graphData.edges.map((edge) => ({ source: edge.from, target: edge.to, directed: edge.directed }));
      const maxBoxW = Math.max(...nodes.map((n) => n.boxW));
      const maxBoxH = Math.max(...nodes.map((n) => n.boxH));
      const collideRadius = Math.sqrt((maxBoxW / 2) ** 2 + (maxBoxH / 2) ** 2) + 10;
      const { svg, arrowId } = createSvg(height);
      const simulation = d3.forceSimulation(nodes)
        .force('link',    d3.forceLink(links).id((d) => d.id).distance(160).strength(0.5))
        .force('charge',  d3.forceManyBody().strength(-300))
        .force('center',  d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide(collideRadius));
      const edgeElements = svg.append('g').selectAll('line').data(links).enter().append('line')
        .attr('stroke', '#B8A9C9').attr('stroke-width', 1.5)
        .attr('marker-end', (d) => (d.directed ? `url(#${arrowId})` : null));
      const nodeElements = drawNodes(svg, nodes, (d) => d.x || 0, (d) => d.y || 0, (d) => d);
      simulation.on('tick', () => {
        edgeElements
          .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
          .attr('x2', (d) => { if (!d.directed) return d.target.x; return getRectBorderPoint(d.source.x, d.source.y, d.target.x, d.target.y, d.target.boxW, d.target.boxH).x; })
          .attr('y2', (d) => { if (!d.directed) return d.target.y; return getRectBorderPoint(d.source.x, d.source.y, d.target.x, d.target.y, d.target.boxW, d.target.boxH).y; });
        nodeElements.attr('transform', (d) => `translate(${d.x}, ${d.y})`);
      });
      simulation.alpha(1).restart();
      setTimeout(() => simulation.stop(), 800);
      graphDef.replaceWith(svg.node());
    };

    if (isTree()) renderTree(); else renderForce();
  });
};

// ─────────────────────────────────────────────────────────────────

const supportsPdfIframe = () => {
  if (typeof navigator === 'undefined' || !navigator.mimeTypes) return false;
  return !!navigator.mimeTypes['application/pdf'];
};

const renderPDFUsingPDFJS = async (url, container) => {
  if (typeof pdfjsLib === 'undefined' || !pdfjsLib.getDocument) {
    container.innerHTML = '<p>PDF preview is unavailable.</p>';
    return;
  }
  const pdfContainer = document.createElement('div');
  pdfContainer.style.display = 'grid';
  pdfContainer.style.gap     = '1rem';
  try {
    const pdf = await pdfjsLib.getDocument(url).promise;
    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum += 1) {
      const page     = await pdf.getPage(pageNum);
      const viewport = page.getViewport({ scale: 1.25 });
      const canvas   = document.createElement('canvas');
      canvas.width   = viewport.width;
      canvas.height  = viewport.height;
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      pdfContainer.appendChild(canvas);
    }
  } catch (error) {
    pdfContainer.innerHTML = `<p>Unable to render PDF: ${error.message}</p>`;
  }
  container.appendChild(pdfContainer);
};

const renderPDFs = () => {
  const articleContainer = document.getElementById(articleContainerId);
  if (!articleContainer) return;
  Array.from(articleContainer.querySelectorAll('.pdf-embed')).forEach(async (embed) => {
    const src = embed.dataset.src;
    if (!src) return;
    const wrapper = document.createElement('div');
    wrapper.className    = 'pdf-wrapper';
    wrapper.style.display = 'grid';
    wrapper.style.gap     = '0.75rem';
    wrapper.style.margin  = '1.5rem 0';
    const iframe = document.createElement('iframe');
    iframe.src    = src; iframe.width = '100%'; iframe.height = '600';
    iframe.style.border = '1px solid rgba(135, 168, 120, 0.3)';
    iframe.style.borderRadius = '12px'; iframe.style.minHeight = '420px';
    const button = document.createElement('a');
    button.href = src; button.textContent = 'Download PDF';
    button.target = '_blank'; button.rel = 'noopener noreferrer';
    button.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;padding:0.85rem 1.25rem;background:#87A878;color:#FFFFFF;border-radius:999px;text-decoration:none;width:fit-content;';
    wrapper.appendChild(iframe);
    wrapper.appendChild(button);
    embed.replaceWith(wrapper);
    if (!supportsPdfIframe()) {
      wrapper.removeChild(iframe);
      await renderPDFUsingPDFJS(src, wrapper);
    }
  });
};

// ─────────────────────────────────────────────────────────────────

const showLanding = () => {
  const articleContainer = document.getElementById(articleContainerId);
  const articleToc       = document.getElementById('article-toc');

  if (articleContainer) articleContainer.style.display = 'none';

  // Contexte index.html
  const landing = document.getElementById(landingId);
  if (landing) landing.style.display = 'block';

  // Contexte articles.html
  const articlesLanding = document.getElementById('articles-landing');
  const articleLayout   = document.getElementById('article-layout');
  if (articlesLanding) articlesLanding.style.display = 'block';
  if (articleLayout)   articleLayout.style.display   = 'none';

  if (articleToc) { articleToc.innerHTML = ''; articleToc.style.display = 'none'; }
  document.querySelectorAll('.toc-article.active').forEach((l) => l.classList.remove('active'));
};

const loadArticleFromHash = () => {
  const hash = window.location.hash;
  if (!hash.startsWith('#article=')) return;
  const filePath = decodeURIComponent(hash.slice('#article='.length));
  if (!filePath) return;
  loadArticle(filePath);
};

const whenReady = (callback) => {
  if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', callback);
  else callback();
};

window.addEventListener('hashchange', loadArticleFromHash);
whenReady(loadArticleFromHash);

window.loadArticle = loadArticle;
window.showLanding = showLanding;

// ─────────────────────────────────────────────────────────────────

const makeHexSVG = (size, strokeColour, extraClass) => {
  const r      = size / 2;
  const points = Array.from({ length: 6 }, (_, i) => {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    return `${r + Math.cos(angle) * r},${r + Math.sin(angle) * r}`;
  }).join(' ');
  const svg  = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.classList.add('article-hex', extraClass);
  const poly = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
  poly.setAttribute('points', points); poly.setAttribute('fill', 'none');
  poly.setAttribute('stroke', strokeColour); poly.setAttribute('stroke-width', '2');
  svg.appendChild(poly);
  return svg;
};

const injectArticleHexagons = (container) => {
  container.querySelectorAll('.article-hex').forEach((el) => el.remove());
  container.appendChild(makeHexSVG(72, '#87A878', 'article-hex-tl-1'));
  container.appendChild(makeHexSVG(72, '#B8A9C9', 'article-hex-tl-2'));
  container.appendChild(makeHexSVG(72, '#B8A9C9', 'article-hex-tr-1'));
  container.appendChild(makeHexSVG(72, '#87A878', 'article-hex-tr-2'));
};

export { loadArticle, showLanding };
