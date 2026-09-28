const manifestPath = './practicalprojects-manifest.json';
const tocRootId = 'toc';
let currentActiveLink = null;

const fetchManifest = async () => {
  const response = await fetch(manifestPath, { cache: 'no-cache' });
  if (!response.ok) {
    throw new Error(`Failed to fetch manifest: ${response.statusText}`);
  }
  return response.json();
};

const closeMobileTOC = () => {
  if (window.innerWidth <= 768) {
    const toc = document.getElementById(tocRootId);
    if (toc) {
      toc.classList.remove('open', 'toc-open');
    }
  }
};

const setActiveLink = (link) => {
  const tocRoot = document.getElementById(tocRootId);
  // On relit le DOM : showLanding() peut avoir retiré la classe de son côté.
  (tocRoot || document).querySelectorAll('.toc-article.active')
    .forEach((el) => el.classList.remove('active'));
  currentActiveLink = link || null;
  if (currentActiveLink) currentActiveLink.classList.add('active');
};

const fileFromHash = () => {
  const hash = window.location.hash;
  if (!hash.startsWith('#article=')) return null;
  return decodeURIComponent(hash.slice('#article='.length)) || null;
};

// Source de vérité = l'URL, pas le clic : couvre l'ouverture directe d'un lien,
// les boutons précédent/suivant et les liens internes aux articles.
const syncActiveFromHash = () => {
  const tocRoot = document.getElementById(tocRootId);
  if (!tocRoot) return;
  const file = fileFromHash();
  const match = file
    ? Array.from(tocRoot.querySelectorAll('.toc-article'))
        .find((link) => link.dataset.file === file)
    : null;
  setActiveLink(match);
};

const handleCategoryToggle = (categoryEl) => {
  const isExpanded = categoryEl.getAttribute('aria-expanded') === 'true';
  categoryEl.setAttribute('aria-expanded', String(!isExpanded));
  categoryEl.classList.toggle('collapsed', isExpanded);
};

const createArticleLink = (article) => {
  const link = document.createElement('a');
  link.className = 'toc-article';
  link.href = `#article=${encodeURIComponent(article.file)}`;
  link.dataset.file = article.file;
  link.innerHTML = `<span class="toc-article-title">${article.title}</span>`;

  link.addEventListener('click', (event) => {
    event.preventDefault();
    const file = article.file;
    if (typeof loadArticle === 'function') loadArticle(file);
    window.location.hash = `article=${encodeURIComponent(file)}`;
    setActiveLink(link);
    closeMobileTOC();
  });

  return link;
};

const createCategoryNode = (category) => {
  const categoryWrapper = document.createElement('div');
  categoryWrapper.className = 'toc-category';
  categoryWrapper.setAttribute('aria-expanded', 'true');

  const categoryHeader = document.createElement('button');
  categoryHeader.type = 'button';
  categoryHeader.className = 'toc-category-header';
  categoryHeader.addEventListener('click', () => handleCategoryToggle(categoryWrapper));

  const categoryLabel = document.createElement('span');
  categoryLabel.className = 'toc-category-label';
  categoryLabel.textContent = category.category;

  const categoryArrow = document.createElement('span');
  categoryArrow.className = 'toc-category-arrow';
  categoryArrow.setAttribute('aria-hidden', 'true');
  categoryArrow.textContent = '\u25BE';

  categoryHeader.appendChild(categoryLabel);
  categoryHeader.appendChild(categoryArrow);

  const articleList = document.createElement('div');
  articleList.className = 'toc-article-list';

  category.articles.forEach((article) => {
    const item = document.createElement('div');
    item.className = 'toc-article-item';
    item.appendChild(createArticleLink(article));
    articleList.appendChild(item);
  });

  categoryWrapper.appendChild(categoryHeader);
  categoryWrapper.appendChild(articleList);
  return categoryWrapper;
};

const buildTOC = async () => {
  const tocRoot = document.getElementById(tocRootId);
  if (!tocRoot) {
    console.warn(`TOC root element with id '${tocRootId}' not found.`);
    return;
  }

  try {
    const manifest = await fetchManifest();
    manifest.forEach((category) => {
      tocRoot.appendChild(createCategoryNode(category));
    });
    syncActiveFromHash();
  } catch (error) {
    console.error('Error building TOC:', error);
    tocRoot.textContent = 'Unable to load table of contents.';
  }
};

window.addEventListener('hashchange', syncActiveFromHash);

export { buildTOC };
