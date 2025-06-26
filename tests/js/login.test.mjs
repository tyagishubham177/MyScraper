import assert from 'assert';

class Element {
  constructor() {
    this.style = { display: 'none' };
  }
}

function createLocalStorage() {
  const store = new Map();
  return {
    setItem: (k,v)=>store.set(k,String(v)),
    getItem: k=>store.get(k),
    removeItem: k=>store.delete(k)
  };
}

function handleUserError(result, ctx) {
  const { userLoginBtn, userErrorMessage, userContactLinks } = ctx;
  if (result.wait) {
    const lockUntil = Date.now() + result.wait * 1000;
    ctx.localStorage.setItem('userLockUntil', lockUntil);
    if (ctx.userCountdownTimer) clearInterval(ctx.userCountdownTimer);
    ctx.userCountdownTimer = ctx.startCountdown(
      userLoginBtn,
      lockUntil,
      userErrorMessage,
      'userLockUntil',
      userContactLinks
    );
  } else {
    let msg;
    if (result.attempt) {
      msg = `Email unregistered or incorrect attempt (${result.attempt}/3)`;
      if (result.attempt === 2) msg += ' - last attempt';
      msg += '. Please contact admin to register via options below';
    } else {
      msg = result.message || 'Email not registered. Please contact admin to register via options below';
    }
    ctx.showError(userErrorMessage, msg);
    if (userContactLinks) {
      userContactLinks.style.display = 'block';
      if (ctx.window.lucide && typeof ctx.window.lucide.createIcons === 'function') {
        ctx.window.lucide.createIcons();
      }
    }
  }
}

function testWaitPath(){
  const ctx = {
    localStorage: createLocalStorage(),
    userCountdownTimer: null,
    startCountdown: () => 'timer',
    showError: () => { throw new Error('should not be called'); },
    window: {},
    userLoginBtn: {},
    userErrorMessage: new Element(),
    userContactLinks: new Element()
  };
  handleUserError({wait:2}, ctx);
  assert.ok(ctx.localStorage.getItem('userLockUntil'));
  assert.strictEqual(ctx.userCountdownTimer, 'timer');
}

function testAttemptPath(){
  let shownMessage = '';
  const ctx = {
    localStorage: createLocalStorage(),
    userCountdownTimer: null,
    startCountdown: () => { throw new Error('should not be called'); },
    showError: (_elem,msg)=>{ shownMessage = msg; },
    window: { lucide: { createIcons: ()=>{ called=true; } } },
    userLoginBtn: {},
    userErrorMessage: new Element(),
    userContactLinks: new Element()
  };
  let called = false;
  handleUserError({attempt:1}, ctx);
  assert.ok(shownMessage.includes('(1/3)'));
  assert.strictEqual(ctx.userContactLinks.style.display, 'block');
  assert.ok(called);
}

testWaitPath();
testAttemptPath();
console.log('handleUserError tests passed');
