(function(global){
  const icons={
    'info':'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    'refresh-cw':'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.49-3.36L23 10"/><path d="M20.49 15a9 9 0 01-14.49 3.36L1 14"/>',
    'play-circle':'<circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>',
    'stop-circle':'<circle cx="12" cy="12" r="10"/><rect x="9" y="9" width="6" height="6"/>',
    'chevron-down':'<polyline points="6 9 12 15 18 9"/>',
    'user-plus':'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="8" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="17" y1="11" x2="23" y2="11"/>',
    'x':'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    'package-plus':'<rect x="3" y="3" width="18" height="14" rx="2"/><polyline points="3 7 12 12 21 7"/><line x1="12" y1="22" x2="12" y2="12"/><line x1="9" y1="19" x2="15" y2="19"/>',
    'edit':'<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>',
    'trash-2':'<polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>',
    'external-link':'<path d="M18 13v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    'settings-2':'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83l-1 1a2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33A1.65 1.65 0 0 0 13 21v.09a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2V21a1.65 1.65 0 0 0-.38-1.06 1.65 1.65 0 0 0-1.82-.33l-.06.06a2 2 0 0 1-2.83 0l-1-1a2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82A1.65 1.65 0 0 0 3 13H2a2 2 0 0 1-2-2v-2a2 2 0 0 1 2-2h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83l1-1a2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9A1.65 1.65 0 0 0 10 3V2a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0l1 1a2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c0 .8.48 1.52 1.21 1.83A2 2 0 0 1 22 13v2a2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>'
  };
  global.lucide={
    createIcons:function(){
      document.querySelectorAll('[data-lucide]').forEach(function(el){
        const name=el.getAttribute('data-lucide');
        const svg=icons[name];
        if(svg){
          el.innerHTML='<svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'+svg+'</svg>';
        }
      });
    }
  };
})(this);
