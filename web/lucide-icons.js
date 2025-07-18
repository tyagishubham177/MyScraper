(function(global){
  const icons={
    'info':'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    'refresh-cw':'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.49-3.36L23 10"/><path d="M20.49 15a9 9 0 01-14.49 3.36L1 14"/>',
    'play-circle':'<circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>',
    'stop-circle':'<circle cx="12" cy="12" r="10"/><rect x="9" y="9" width="6" height="6"/>',
    'play':'<polygon points="5 3 19 12 5 21 5 3"/>',
    'pause':'<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
    'chevron-down':'<polyline points="6 9 12 15 18 9"/>',
    'chevron-up':'<polyline points="18 15 12 9 6 15"/>',
    'user-plus':'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="8" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="17" y1="11" x2="23" y2="11"/>',
    'shield':'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'user':'<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    'mail':'<rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 5 12 13 21 5"/>',
    'lock':'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    'eye':'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off':'<path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-5 0-9.27-3.11-11-7.5a10.95 10.95 0 0 1 5-5.77"/><path d="M1 1l22 22"/><path d="M3.35 3.35A10.94 10.94 0 0 1 12 4c5 0 9.27 3.11 11 7.5a10.94 10.94 0 0 1-1.52 2.96"/><path d="M9.53 9.53a3 3 0 0 0 4.24 4.24"/>',
    'log-in':'<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>',
    'log-out':'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    'message-circle':'<path d="M21 11.5a8.38 8.38 0 0 1-9 8.4 8.5 8.5 0 0 1-4-1l-5 1 1-5a8.5 8.5 0 1 1 17 0z"/>',
    'zap':'<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    'x':'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    'plus':'<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    'package-plus':'<rect x="3" y="3" width="18" height="14" rx="2"/><polyline points="3 7 12 12 21 7"/><line x1="12" y1="22" x2="12" y2="12"/><line x1="9" y1="19" x2="15" y2="19"/>',
    'edit':'<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>',
    'trash-2':'<polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>',
    'external-link':'<path d="M18 13v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    'sliders':'<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    'settings-2':'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83l-1 1a2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33A1.65 1.65 0 0 0 13 21v.09a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2V21a1.65 1.65 0 0 0-.38-1.06 1.65 1.65 0 0 0-1.82-.33l-.06.06a2 2 0 0 1-2.83 0l-1-1a2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82A1.65 1.65 0 0 0 3 13H2a2 2 0 0 1-2-2v-2a2 2 0 0 1 2-2h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83l1-1a2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9A1.65 1.65 0 0 0 10 3V2a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0l1 1a2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c0 .8.48 1.52 1.21 1.83A2 2 0 0 1 22 13v2a2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    'calendar-days':'<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
    'help-circle':'<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 1 1 5.82 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    'check-circle':'<circle cx="12" cy="12" r="10"/><polyline points="9 12 12 15 17 10"/>',
    'x-circle':'<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    'loader-2':'<circle cx="12" cy="12" r="10" stroke-dasharray="60" stroke-dashoffset="-30"/><path d="M12 2a10 10 0 0 1 10 10"/>'
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
