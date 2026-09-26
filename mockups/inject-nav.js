// Вставка общего бокового меню в статичные макеты (чтобы не дублировать разметку).
// Подсвечивает активный пункт по имени текущей страницы.
(function () {
  var links = {
    'dashboard.html': 'Обзор',
    'interfaces.html': 'Сеть',
    'apply.html': 'Обзор'
  };
  var current = location.pathname.split('/').pop() || 'dashboard.html';
  var activeName = links[current] || 'Обзор';

  fetch('nav.html')
    .then(function (r) { return r.text(); })
    .then(function (html) {
      var tmp = document.createElement('div');
      tmp.innerHTML = html;
      var aside = tmp.querySelector('aside');
      aside.querySelectorAll('.nav a').forEach(function (a) {
        a.classList.remove('active');
        if (a.textContent.trim().indexOf(activeName) === 0) a.classList.add('active');
      });
      document.body.insertBefore(aside, document.body.firstChild);
    });
})();
