import assert from 'assert';
import { createRipple } from '../../web/components/utils/utils.js';

class Element {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.style = {};
    this.classList = new Set();
    this.dataset = {};
    this.parent = null;
    this.clientWidth = 0;
    this.clientHeight = 0;
    this.disabled = false;
    this.id = '';
  }

  appendChild(el) {
    el.parent = this;
    this.children.push(el);
  }

  remove() {
    if (this.parent) {
      const idx = this.parent.children.indexOf(this);
      if (idx >= 0) this.parent.children.splice(idx, 1);
      this.parent = null;
    }
  }

  getElementsByClassName(name) {
    return this.children.filter(c => c.classList.has(name));
  }

  matches(selector) {
    if (selector.startsWith('.')) return this.classList.has(selector.slice(1));
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    return this.tagName.toLowerCase() === selector.toLowerCase();
  }

  closest(selector) {
    let el = this;
    while (el) {
      if (el.matches(selector)) return el;
      el = el.parent;
    }
    return null;
  }

  querySelector(selector) {
    const search = (node) => {
      for (const child of node.children) {
        if (child.matches(selector)) return child;
        const found = search(child);
        if (found) return found;
      }
      return null;
    };
    return search(this);
  }

  getBoundingClientRect() {
    return { left: this.left || 0, top: this.top || 0 };
  }
}

const documentStub = {
  createElement: tag => new Element(tag)
};

global.document = documentStub;

function testCreateRipple() {
  const btn = new Element('button');
  btn.clientWidth = 100;
  btn.clientHeight = 50;
  btn.left = 10;
  btn.top = 20;

  const evt = { currentTarget: btn, clientX: 40, clientY: 60 };

  createRipple(evt);

  assert.strictEqual(btn.children.length, 1);
  const rip1 = btn.children[0];
  assert.ok(rip1.classList.has('ripple'));
  assert.strictEqual(rip1.style.width, '100px');
  assert.strictEqual(rip1.style.height, '100px');
  assert.strictEqual(rip1.style.left, `${40 - 10 - 50}px`);
  assert.strictEqual(rip1.style.top, `${60 - 20 - 50}px`);

  // second call should replace ripple
  createRipple(evt);
  assert.strictEqual(btn.children.length, 1);
  assert.notStrictEqual(btn.children[0], rip1);
}

testCreateRipple();
console.log('createRipple tests passed');
