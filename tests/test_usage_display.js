// Render the production LuCI helpers with distinct raw/billed regression data.
// No router state is changed. Formatting and E() output are exercised together.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const context = vm.createContext({
  E: (tag, attrs, children) => ({tag, attrs, children: children || []}),
  _: text => text,
  rpc: {declare: () => () => Promise.reject(new Error('Unexpected RPC'))},
  document: {createElementNS: (_, tag) => ({tag, attrs:{}, children:[],
    setAttribute(key, value) {this.attrs[key]=value;},
    appendChild(child) {this.children.push(child);}
  })},
  baseclass: {extend: object => object},
  ui: {}
});
vm.runInContext("String.prototype.format = function(...args) { let i=0; return this.replace(/%[sd]/g, () => String(args[i++])); };", context);
const source = fs.readFileSync(path.join(root, 'luci-app-netquota/htdocs/luci-static/resources/netquota.js'), 'utf8');
const nq = vm.runInContext('(function(){\n' + source + '\n})()', context);
const text = node => typeof node === 'object' && node !== null
  ? node.children.map(text).join(' ') : String(node);
const findClass = (node, cls) => node && typeof node === 'object'
  ? ((node.attrs.class || '').split(' ').includes(cls) ? [node] : []).concat(node.children.flatMap(child => findClass(child, cls))) : [];

const accounts = [
  {username:'GH33O', total_bytes:16440000000, billed_bytes:16900000000, quota_bytes:40000000000, usage_percent:42.25},
  {username:'Other', total_bytes:1000000000, billed_bytes:1200000000, quota_bytes:20000000000, usage_percent:6}
];
const before = JSON.stringify(accounts);
const cards = nq.trafficTotalCards(accounts);
const values = findClass(cards, 'nq-stat-value').map(text);
assert.deepEqual(values, ['17.44 GB', '18.1 GB']);
assert.match(text(cards), /本周期实际总量/);
assert.match(text(cards), /本周期计费总量/);
// Current multiplier must not be applied retroactively to accumulated raw usage.
accounts.forEach(a => {a.traffic_multiplier_percent=150;});
assert.deepEqual(findClass(nq.trafficTotalCards(accounts), 'nq-stat-value').map(text), values);
accounts.forEach(a => {delete a.traffic_multiplier_percent;});
assert.equal(JSON.stringify(accounts), before);
const cell = nq.usageCell(accounts[0]);
assert.match(text(cell), /16\.9 GB/);
assert.match(text(cell), /实际 16\.44 GB/);
assert.equal(findClass(cell, 'nq-usage-text')[0].children[0].children[0], '16.9 GB');
assert.deepEqual(findClass(nq.trafficTotalCards([]), 'nq-stat-value').map(text), ['0 B', '0 B']);
assert.equal(nq.billedBytes({total_bytes:1000}), 1000);
console.log('Usage display: billed account value, separate totals, future-only accounting and empty state PASS');
