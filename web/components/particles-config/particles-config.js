export function initParticles() {
  particlesJS('particles-js', {
    particles: {
      number: {
        value: 80,
        density: { enable: true, value_area: 1000 }
      },
      color: { value: ['#ffffff', '#60A5FA', '#FCD34D'] },
      shape: { type: 'circle' },
      opacity: { value: 0.3, random: true, anim: { enable: true, speed: 0.2, opacity_min: 0.05, sync: false } },
      size: { value: 3, random: true, anim: { enable: true, speed: 1, size_min: 0.1, sync: false } },
      line_linked: { enable: true, distance: 150, color: '#ffffff', opacity: 0.05, width: 1 },
      move: { enable: true, speed: 0.6, direction: 'none', random: true, straight: false, out_mode: 'out', bounce: false }
    },
    interactivity: {
      detect_on: 'canvas',
      events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: true, mode: 'push' }, resize: true },
      modes: {
        grab: { distance: 200, line_linked: { opacity: 0.15 } },
        push: { particles_nb: 2 }
      }
    },
    retina_detect: true
  });
}
