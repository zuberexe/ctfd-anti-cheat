/* ctfd_anti_cheat — minimal client-side helpers
 * Pure vanilla; no jQuery / no external libs (CTFd already loads its own).
 */
(function () {
    'use strict';

    // Prevent double-submission of the "Run" form by disabling the button
    // immediately after click. Detector runs can take a few seconds on
    // large CTFd corpora.
    document.querySelectorAll('form[action$="/run"]').forEach(function (f) {
        f.addEventListener('submit', function () {
            var btn = f.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Running…';
            }
        });
    });

    // Click-to-copy on user IDs / fingerprints (helpful when triaging)
    document.querySelectorAll('.cm-table code').forEach(function (el) {
        el.style.cursor = 'pointer';
        el.title = 'Click to copy';
        el.addEventListener('click', function () {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(el.textContent).catch(function () {});
            }
        });
    });
})();
