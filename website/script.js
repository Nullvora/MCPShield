const menuBtn = document.querySelector('.menu-btn');
const mobileNav = document.querySelector('.mobile-nav');
if (menuBtn && mobileNav) {
  menuBtn.addEventListener('click', () => {
    const isOpen = mobileNav.classList.toggle('open');
    menuBtn.setAttribute('aria-expanded', String(isOpen));
  });
  mobileNav.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
    mobileNav.classList.remove('open');
    menuBtn.setAttribute('aria-expanded', 'false');
  }));
}

const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.reveal').forEach((el) => observer.observe(el));

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const target = document.querySelector(button.dataset.copy);
    if (!target) return;
    const text = target.innerText;
    try {
      await navigator.clipboard.writeText(text);
      const old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => button.textContent = old, 1400);
    } catch {
      button.textContent = 'Select & copy';
      target.focus?.();
    }
  });
}
