import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { initializeFirestore, persistentLocalCache, collection, doc, getDoc, getDocs, setDoc, addDoc, deleteDoc,
  onSnapshot, serverTimestamp, query, limit }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig, ORG_NAME } from "./firebase-config.js";

// ---------- Firebase ----------
const fb = initializeApp(firebaseConfig);
// แคชในเครื่อง: เปิดซ้ำไม่ต้องอ่านทั้งทะเบียนใหม่ ช่วยประหยัดโควตาฟรี
let db;
try { db = initializeFirestore(fb, { localCache: persistentLocalCache() }); }
catch { db = initializeFirestore(fb, {}); }

// ---------- ผู้ใช้ (เก็บในคอลเลกชัน users ไม่ใช้ Firebase Authentication) ----------
const USER_RE = /^[a-z0-9][a-z0-9._-]{2,29}$/;
const uname = s => String(s || "").split("@")[0];
// เก็บรหัสผ่านแบบแฮช SHA-256 ไม่เก็บตัวรหัสจริง
async function hashPw(user, pw) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("appeal-register:" + user + ":" + pw));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
const SESSION_KEY = "appealRegisterUser";
const session = {
  get() { try { return localStorage.getItem(SESSION_KEY) || ""; } catch { return ""; } },
  set(u) { try { u ? localStorage.setItem(SESSION_KEY, u) : localStorage.removeItem(SESSION_KEY); } catch {} }
};

// ---------- ค่าคงที่ ----------
const STATUSES = [
  { k: "returned", t: "ส่งคืนหน่วยงาน", c: "gray" },
  { k: "pending", t: "อยู่ระหว่างนำเข้าประชุม", c: "warn" },
  { k: "met", t: "ประชุมแล้ว", c: "info" },
  { k: "notified", t: "หนังสือแจ้งผลออกแล้ว", c: "ok" }
];
const RESULTS = [
  { k: "upheld", t: "ฟังขึ้น", c: "ok" },
  { k: "rejected", t: "ฟังไม่ขึ้น", c: "bad" },
  { k: "notaccepted", t: "ไม่รับพิจารณา", c: "gray" },
  { k: "noright", t: "ใช้สิทธิอุทธรณ์ไม่ได้", c: "vio" }
];
const ROLE_TH = { admin: "ผู้ดูแล", editor: "ผู้บันทึก", viewer: "ดูอย่างเดียว", disabled: "ยกเลิกสิทธิ์แล้ว" };
const FIELDS = ["fy","seq","project","agency","docNo","docDate","appellant","deptToRegion","regionToDept",
  "office","owner","meetingNo","agendaNo","pnNo","refNo","meetingDate","statusDate","laws","summary"];
const MON = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."];

const $ = id => document.getElementById(id);
const stOf = k => STATUSES.find(s => s.k === k), rsOf = k => RESULTS.find(s => s.k === k);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function thDate(iso) { if (!iso) return ""; const [y, m, d] = String(iso).split("-").map(Number); if (!y || !m) return ""; return d + " " + MON[m - 1] + " " + String(y + 543).slice(-2); }
function currentFY() { const n = new Date(); return n.getFullYear() + 543 + (n.getMonth() >= 9 ? 1 : 0); }
function hl(s, q) { const e = esc(s); if (!q) return e; const qe = esc(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); return e.replace(new RegExp(qe, "gi"), m => `<mark class="mark">${m}</mark>`); }
function pill(o) { if (!o) return '<span class="small">—</span>'; return `<span class="pill" style="background:var(--${o.c}-soft);color:var(--${o.c})"><span class="dot" style="background:var(--${o.c})"></span>${o.t}</span>`; }
const laws = s => String(s || "").split(/[;\n]+/).map(x => x.trim()).filter(Boolean);
function toast(t) { const el = $("toast"); el.textContent = t; el.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => el.hidden = true, 2400); }
document.querySelectorAll("[data-org]").forEach(e => e.textContent = ORG_NAME);

// ---------- สถานะแอป ----------
let me = null;           // { user, name, role }
let items = [], loaded = false, unsubAppeals = null, unsubMembers = null, members = [];
const view = { fy: currentFY(), status: "", result: "", q: "" };
let editing = null;
const canEdit = () => me && (me.role === "admin" || me.role === "editor");
const isAdmin = () => me && me.role === "admin";

// ---------- ล็อกอิน ----------
function showGate(msg, mode) {
  $("app").hidden = true; $("gate").hidden = false;
  $("gateMsg").innerHTML = msg;
  $("loginForm").hidden = mode !== "login";
  $("setupForm").hidden = mode !== "setup";
  $("gateLogout").hidden = true;
  if (mode === "login") setTimeout(() => $("l_user").focus(), 30);
  if (mode === "setup") setTimeout(() => $("s_user").focus(), 30);
}
async function boot() {
  const saved = session.get();
  if (saved) {
    try {
      const s = await getDoc(doc(db, "users", saved));
      if (s.exists() && ["admin", "editor", "viewer"].includes(s.data().role)) return login(saved, s.data());
    } catch (e) { return showGate("เชื่อมต่อฐานข้อมูลไม่ได้ ตรวจอินเทอร์เน็ตหรือค่าใน firebase-config.js แล้วรีเฟรชหน้า", ""); }
    session.set("");
  }
  try {
    const any = await getDocs(query(collection(db, "users"), limit(1)));
    if (any.empty) return showGate("ยังไม่มีผู้ใช้ในระบบ สร้างบัญชี<strong>ผู้ดูแล</strong>คนแรก", "setup");
  } catch (e) { return showGate(e?.code === "permission-denied" ? "ฐานข้อมูลปฏิเสธการเข้าถึง วางกฎจาก firestore.rules ใน Firebase Console แล้วกด Publish" : "เชื่อมต่อฐานข้อมูลไม่ได้ ตรวจอินเทอร์เน็ตหรือค่าใน firebase-config.js แล้วรีเฟรชหน้า", ""); }
  showGate("เข้าสู่ระบบด้วยชื่อผู้ใช้ที่ผู้ดูแลสร้างให้", "login");
}
function login(user, data) {
  me = { user, name: data.name || "", role: data.role };
  session.set(user);
  startApp();
}
function logout() {
  unsubAppeals?.(); unsubAppeals = null; unsubMembers?.(); unsubMembers = null;
  items = []; loaded = false; me = null; closeSheets(); session.set("");
  showGate("เข้าสู่ระบบด้วยชื่อผู้ใช้ที่ผู้ดูแลสร้างให้", "login");
}
$("logoutBtn").onclick = logout;

$("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const u = $("l_user").value.trim().toLowerCase(), p = $("l_pass").value;
  const er = $("loginErr"); er.hidden = true;
  const fail = t => { er.hidden = false; er.textContent = t; };
  if (!u || !p) return fail("กรอกชื่อผู้ใช้และรหัสผ่าน");
  $("loginBtn").disabled = true;
  try {
    const s = USER_RE.test(u) ? await getDoc(doc(db, "users", u)) : null;
    if (!s?.exists() || s.data().pw !== await hashPw(u, p)) return fail("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
    if (!["admin", "editor", "viewer"].includes(s.data().role)) return fail("บัญชีนี้ถูกยกเลิกสิทธิ์ ติดต่อผู้ดูแลระบบ");
    $("l_pass").value = "";
    login(u, s.data());
  } catch (err) { fail(errText(err)); }
  finally { $("loginBtn").disabled = false; }
});

// สร้างผู้ดูแลคนแรก (แสดงเฉพาะตอนยังไม่มีผู้ใช้ในระบบ)
$("setupForm").addEventListener("submit", async e => {
  e.preventDefault();
  const u = $("s_user").value.trim().toLowerCase(), p = $("s_pass").value, p2 = $("s_pass2").value;
  const er = $("setupErr"); er.hidden = true;
  const fail = t => { er.hidden = false; er.textContent = t; };
  if (!USER_RE.test(u)) return fail("ชื่อผู้ใช้ใช้ได้เฉพาะ a–z, 0–9, จุด, ขีด ยาว 3–30 ตัว");
  if (p.length < 4) return fail("รหัสผ่านต้องมีอย่างน้อย 4 ตัว");
  if (p !== p2) return fail("รหัสผ่านสองช่องไม่ตรงกัน");
  try {
    const any = await getDocs(query(collection(db, "users"), limit(1)));
    if (!any.empty) { boot(); return; }
    const data = { name: $("s_name").value.trim(), role: "admin", pw: await hashPw(u, p), createdBy: u, createdAt: serverTimestamp() };
    await setDoc(doc(db, "users", u), data);
    login(u, data); toast("สร้างผู้ดูแลแล้ว");
  } catch (err) { fail(errText(err)); }
});

function startApp() {
  $("gate").hidden = true; $("app").hidden = false;
  $("meEmail").textContent = me.name ? `${me.name} (${me.user})` : me.user;
  $("meRole").textContent = ROLE_TH[me.role] || me.role;
  $("addBtn").hidden = !canEdit();
  $("membersBtn").hidden = !isAdmin();
  $("notice").hidden = canEdit();
  $("notice").textContent = canEdit() ? "" : "บัญชีนี้ดูทะเบียนได้อย่างเดียว ติดต่อผู้ดูแลหากต้องการบันทึกเรื่อง";
  renderAll();
  unsubAppeals = onSnapshot(collection(db, "appeals"),
    s => { items = s.docs.map(d => ({ id: d.id, ...d.data() })); loaded = true; renderAll(); },
    e => { loaded = true; $("notice").hidden = false; $("notice").textContent = "โหลดทะเบียนไม่สำเร็จ (" + e.code + ") รีเฟรชหน้าเพื่อลองใหม่"; renderAll(); });
  const order = { admin: 0, editor: 1, viewer: 2, disabled: 3 };
  // ติดตามบัญชีตัวเอง: ถ้าถูกยกเลิกสิทธิ์หรือเปลี่ยนสิทธิ์ จะมีผลทันที
  unsubMembers = onSnapshot(collection(db, "users"), s => {
    members = s.docs.map(d => ({ user: d.id, ...d.data() })).sort((a, b) => (order[a.role] ?? 9) - (order[b.role] ?? 9) || a.user.localeCompare(b.user));
    const mine = members.find(m => m.user === me?.user);
    if (!mine || !["admin", "editor", "viewer"].includes(mine.role)) { logout(); toast("บัญชีนี้ถูกยกเลิกสิทธิ์"); return; }
    if (mine.role !== me.role) { me.role = mine.role; unsubAppeals?.(); unsubMembers?.(); startApp(); return; }
    if (isAdmin()) renderMembers();
  });
}

// ---------- เปลี่ยนรหัสผ่านตัวเอง ----------
$("pwBtn").onclick = () => {
  ["p_old", "p_new", "p_new2"].forEach(i => $(i).value = ""); $("pwErr").hidden = true;
  $("pwWho").textContent = "บัญชี " + me.user;
  $("scrim").hidden = false; $("pwSheet").hidden = false; setTimeout(() => $("p_old").focus(), 30);
};
$("pwForm").addEventListener("submit", async e => {
  e.preventDefault();
  const er = $("pwErr"); er.hidden = true;
  const o = $("p_old").value, n = $("p_new").value, n2 = $("p_new2").value;
  const fail = t => { er.hidden = false; er.textContent = " " + t; };
  if (n.length < 4) return fail("รหัสผ่านใหม่ต้องมีอย่างน้อย 4 ตัว");
  if (n !== n2) return fail("รหัสผ่านใหม่สองช่องไม่ตรงกัน");
  $("pwSave").disabled = true;
  try {
    const s = await getDoc(doc(db, "users", me.user));
    if (!s.exists() || s.data().pw !== await hashPw(me.user, o)) return fail("รหัสผ่านปัจจุบันไม่ถูกต้อง");
    await setDoc(doc(db, "users", me.user), { pw: await hashPw(me.user, n) }, { merge: true });
    closeSheets(); toast("เปลี่ยนรหัสผ่านแล้ว");
  } catch (err) { fail(errText(err)); }
  finally { $("pwSave").disabled = false; }
});

// ---------- ทะเบียน ----------
const inFY = () => items.filter(i => view.fy === "all" || Number(i.fy) === view.fy);
function filtered() {
  const q = view.q.trim().toLowerCase();
  return inFY().filter(i => {
    if (view.status && i.status !== view.status) return false;
    if (view.result && i.result !== view.result) return false;
    if (q) { const hay = [i.project, i.agency, i.appellant, i.docNo, i.office, i.owner, i.laws, i.summary, i.meetingNo, i.pnNo, i.refNo].join(" ").toLowerCase(); if (!hay.includes(q)) return false; }
    return true;
  }).sort((a, b) => (b.fy - a.fy) || ((a.seq || 0) - (b.seq || 0)));
}
function renderTabs() {
  const fys = new Set(items.map(i => Number(i.fy)).filter(Boolean)); fys.add(currentFY());
  $("fyTabs").innerHTML = '<span class="fy-label">ปีงบประมาณ</span>' +
    [...fys].sort((a, b) => b - a).map(y => `<button type="button" class="tab" data-fy="${y}" aria-pressed="${view.fy === y}">${y}</button>`).join("") +
    `<button type="button" class="tab all" data-fy="all" aria-pressed="${view.fy === "all"}">ทุกปี</button>`;
}
function renderStrip() {
  const base = inFY();
  const cells = [{ k: "", t: view.fy === "all" ? "ทั้งหมดทุกปี" : "ทั้งหมดปี " + view.fy, c: "accent", n: base.length }]
    .concat(STATUSES.map(s => ({ ...s, n: base.filter(i => i.status === s.k).length })));
  $("strip").innerHTML = cells.map(c => `<button type="button" class="stat" data-st="${c.k}" aria-pressed="${view.status === c.k}"><span class="n">${c.n}</span><span class="l"><span class="dot" style="background:var(--${c.c})"></span>${c.t}</span></button>`).join("");
}
function renderRows() {
  const rows = filtered(), q = view.q.trim(), ql = q.toLowerCase();
  $("count").textContent = loaded ? `พบ ${rows.length} เรื่อง` : "";
  $("rows").innerHTML = rows.map(i => {
    const lawHit = q ? laws(i.laws).filter(x => x.toLowerCase().includes(ql)) : [];
    const sumHit = q && i.summary && i.summary.toLowerCase().includes(ql);
    return `<tr data-id="${esc(i.id)}" tabindex="0">
      <td class="c-seq seq">${view.fy === "all" ? esc(i.fy) + "/" : ""}${esc(i.seq ?? "")}</td>
      <td class="c-proj"><div class="proj">${hl(i.project, q)}</div><div class="small">${hl(i.agency, q)}${i.docNo ? ` · ${hl(i.docNo, q)}` : ""}${i.docDate ? ` ลว. ${thDate(i.docDate)}` : ""}</div>${lawHit.length ? `<div>${lawHit.map(x => `<span class="law">${hl(x, q)}</span>`).join("")}</div>` : ""}${sumHit ? `<div class="small">${hl(i.summary.slice(0, 160), q)}${i.summary.length > 160 ? "…" : ""}</div>` : ""}</td>
      <td class="c-app">${hl(i.appellant, q) || '<span class="small">—</span>'}${i.office || i.owner ? `<div class="small">${hl(i.office, q)}${i.office && i.owner ? " · " : ""}${hl(i.owner, q)}</div>` : ""}</td>
      <td class="c-st">${pill(stOf(i.status))}${i.statusDate ? `<div class="small nowrap">เมื่อ ${thDate(i.statusDate)}</div>` : ""}</td>
      <td class="c-res">${pill(rsOf(i.result))}</td>
      <td class="c-meet small nowrap">${i.meetingNo ? "ครั้งที่ " + hl(i.meetingNo, q) + (i.agendaNo ? " · เรื่องที่ " + esc(i.agendaNo) : "") : "—"}${i.meetingDate ? `<br>${thDate(i.meetingDate)}` : ""}${i.pnNo ? `<br>${hl(i.pnNo, q)}` : ""}${i.refNo ? ` · ${hl(i.refNo, q)}` : ""}</td>
    </tr>`;
  }).join("");
  const em = $("empty");
  if (!loaded) { em.hidden = false; em.innerHTML = "<span>กำลังโหลดทะเบียน…</span>"; return; }
  if (rows.length) { em.hidden = true; return; }
  em.hidden = false;
  if (!inFY().length) em.innerHTML = `<strong>ยังไม่มีเรื่องอุทธรณ์${view.fy === "all" ? "" : "ในปีงบประมาณ " + view.fy}</strong><span>กด “เพิ่มเรื่องอุทธรณ์” เพื่อลงทะเบียนเรื่องแรก ลำดับที่จะเรียงให้อัตโนมัติ</span>${canEdit() ? '<button class="btn primary" type="button" data-add>+ เพิ่มเรื่องอุทธรณ์</button>' : ""}`;
  else em.innerHTML = "<strong>ไม่พบเรื่องที่ตรงกับเงื่อนไข</strong><span>ลองเปลี่ยนคำค้น หรือเลือก “ทุกปี” เพื่อค้นแนววินิจฉัยย้อนหลัง</span>";
}
function renderLists() {
  const uniq = k => [...new Set(items.map(i => i[k]).filter(Boolean))].map(o => `<option value="${esc(o)}">`).join("");
  $("officeList").innerHTML = uniq("office"); $("agencyList").innerHTML = uniq("agency"); $("ownerList").innerHTML = uniq("owner");
}
function renderAll() { renderTabs(); renderStrip(); renderRows(); renderLists(); }

$("resF").innerHTML = '<option value="">ผลการพิจารณา: ทั้งหมด</option>' + RESULTS.map(r => `<option value="${r.k}">${r.t}</option>`).join("");
$("f_status").innerHTML = STATUSES.map(s => `<label><input type="radio" name="status" value="${s.k}" id="st_${s.k}">${s.t}</label>`).join("");
$("f_result").innerHTML = RESULTS.map(s => `<label><input type="radio" name="result" value="${s.k}" id="rs_${s.k}">${s.t}</label>`).join("") + `<label><input type="radio" name="result" value="" id="rs_none">ยังไม่มีผล</label>`;

$("fyTabs").addEventListener("click", e => { const b = e.target.closest("[data-fy]"); if (!b) return; view.fy = b.dataset.fy === "all" ? "all" : Number(b.dataset.fy); renderAll(); });
$("strip").addEventListener("click", e => { const b = e.target.closest("[data-st]"); if (!b) return; view.status = b.dataset.st; renderStrip(); renderRows(); });
let qT; $("q").addEventListener("input", e => { clearTimeout(qT); qT = setTimeout(() => { view.q = e.target.value; renderRows(); }, 120); });
$("resF").addEventListener("change", e => { view.result = e.target.value; renderRows(); });
const openRow = e => { const tr = e.target.closest("tr[data-id]"); if (tr) openSheet(items.find(i => i.id === tr.dataset.id)); };
$("rows").addEventListener("click", openRow);
$("rows").addEventListener("keydown", e => { if (e.key === "Enter") openRow(e); });
$("empty").addEventListener("click", e => { if (e.target.closest("[data-add]")) openSheet(null); });
$("addBtn").onclick = () => openSheet(null);
$("membersBtn").onclick = () => { $("scrim").hidden = false; $("memSheet").hidden = false; };
document.querySelectorAll("[data-close]").forEach(b => b.onclick = closeSheets);
$("scrim").onclick = closeSheets;
document.addEventListener("keydown", e => { if (e.key === "Escape") closeSheets(); });

// ---------- แผงบันทึก ----------
const nextSeq = fy => items.filter(i => Number(i.fy) === Number(fy)).reduce((m, i) => Math.max(m, Number(i.seq) || 0), 0) + 1;
function fmtTs(ts) { try { const d = ts.toDate(); return d.toLocaleString("th-TH", { dateStyle: "medium", timeStyle: "short" }); } catch { return ""; } }
function openSheet(rec) {
  editing = rec || null;
  $("sheetTitle").textContent = rec ? `แก้ไขเรื่องอุทธรณ์ · ปีงบ ${rec.fy}` : "เพิ่มเรื่องอุทธรณ์";
  const fy = rec ? rec.fy : (view.fy === "all" ? currentFY() : view.fy);
  FIELDS.forEach(f => $("f_" + f).value = rec ? (rec[f] ?? "") : "");
  $("f_fy").value = fy; if (!rec) $("f_seq").value = nextSeq(fy);
  document.querySelectorAll("input[name=status]").forEach(r => r.checked = rec ? r.value === rec.status : r.value === "pending");
  document.querySelectorAll("input[name=result]").forEach(r => r.checked = r.value === (rec?.result || ""));
  $("audit").textContent = rec ? [rec.createdBy && `ลงทะเบียนโดย ${uname(rec.createdBy)} ${fmtTs(rec.createdAt)}`, rec.updatedBy && `แก้ไขล่าสุดโดย ${uname(rec.updatedBy)} ${fmtTs(rec.updatedAt)}`].filter(Boolean).join(" · ") : "";
  $("formErr").hidden = true;
  $("delZone").innerHTML = rec && isAdmin() ? '<button type="button" class="btn danger" id="delBtn">ลบเรื่องนี้</button>' : "";
  const ro = !canEdit();
  $("form").querySelectorAll("input,textarea").forEach(x => x.disabled = ro);
  $("saveBtn").hidden = ro;
  $("scrim").hidden = false; $("sheet").hidden = false; $("form").scrollTop = 0;
  if (!ro) setTimeout(() => $("f_project").focus(), 30);
}
function closeSheets() { $("sheet").hidden = true; $("memSheet").hidden = true; $("pwSheet").hidden = true; $("scrim").hidden = true; editing = null; }
$("f_fy").addEventListener("change", () => { if (!editing) $("f_seq").value = nextSeq($("f_fy").value); });

function errText(e) {
  if (e?.code === "permission-denied") return "ฐานข้อมูลปฏิเสธการบันทึก ตรวจว่าวางกฎจาก firestore.rules แล้ว และกรอกข้อมูลครบ";
  if (e?.code === "resource-exhausted") return "ใช้โควตาฟรีของวันนี้หมดแล้ว ลองใหม่พรุ่งนี้";
  return "ทำรายการไม่สำเร็จ ตรวจการเชื่อมต่อแล้วลองอีกครั้ง";
}
$("delZone").addEventListener("click", async e => {
  if (e.target.id === "delBtn") { $("delZone").innerHTML = '<span class="confirm">ลบถาวร? <button type="button" class="btn danger" id="delYes">ยืนยันลบ</button><button type="button" class="btn" id="delNo">ไม่ลบ</button></span>'; return; }
  if (e.target.id === "delNo") { $("delZone").innerHTML = '<button type="button" class="btn danger" id="delBtn">ลบเรื่องนี้</button>'; return; }
  if (e.target.id === "delYes" && editing) {
    try { await deleteDoc(doc(db, "appeals", editing.id)); closeSheets(); toast("ลบเรื่องแล้ว"); }
    catch (err) { $("formErr").hidden = false; $("formErr").textContent = errText(err); }
  }
});
$("form").addEventListener("submit", async e => {
  e.preventDefault(); if (!canEdit()) return;
  const rec = {}; FIELDS.forEach(f => rec[f] = $("f_" + f).value.trim());
  rec.fy = parseInt(rec.fy, 10);
  rec.seq = rec.seq ? parseInt(rec.seq, 10) : nextSeq(rec.fy);
  rec.status = document.querySelector("input[name=status]:checked")?.value || "";
  rec.result = document.querySelector("input[name=result]:checked")?.value || "";
  if (!rec.project || !rec.fy) { $("formErr").hidden = false; $("formErr").textContent = "กรอกปีงบประมาณและชื่อโครงการก่อนบันทึก"; return; }
  // เรื่องใหม่: ระบบกำหนดเลขรันเอง / แก้ไข: ใช้เลขเดิม
  if (!editing) rec.seq = nextSeq(rec.fy);
  rec.updatedBy = me.user; rec.updatedAt = serverTimestamp();
  const btn = $("saveBtn"); btn.disabled = true;
  try {
    if (editing) {
      rec.createdBy = editing.createdBy || me.user; rec.createdAt = editing.createdAt || serverTimestamp();
      await setDoc(doc(db, "appeals", editing.id), rec);
    } else {
      rec.createdBy = me.user; rec.createdAt = serverTimestamp();
      await addDoc(collection(db, "appeals"), rec);
    }
    closeSheets(); toast("บันทึกแล้ว");
  } catch (err) { $("formErr").hidden = false; $("formErr").textContent = errText(err); }
  finally { btn.disabled = false; }
});

// ---------- ส่งออก CSV ----------
$("exportBtn").onclick = () => {
  const H = ["ปีงบประมาณ","ลำดับที่","ชื่อโครงการ","ชื่อหน่วยงาน","เลขที่หนังสือหน่วยงาน","ลงวันที่","ชื่อผู้อุทธรณ์","วันที่กรมส่งเรื่องให้เขต","วันที่เขตส่งเรื่องให้กรม","สำนักงานคลังจังหวัดที่พิจารณา","ผู้รับผิดชอบเรื่อง","นำเข้าการประชุมครั้งที่","ลำดับเรื่องในวาระ","เลขเอกสาร พณ.","เลขท้ายเรื่อง","วันที่เข้าประชุม","ผลการพิจารณา","ข้อกฎหมายที่เกี่ยวข้อง","สรุปประเด็นวินิจฉัย","สถานะ","เมื่อวันที่"];
  const rows = filtered().map(i => [i.fy, i.seq, i.project, i.agency, i.docNo, thDate(i.docDate), i.appellant, thDate(i.deptToRegion), thDate(i.regionToDept), i.office, i.owner, i.meetingNo, i.agendaNo, i.pnNo, i.refNo, thDate(i.meetingDate), rsOf(i.result)?.t || "", i.laws, i.summary, stOf(i.status)?.t || "", thDate(i.statusDate)]);
  const csv = "﻿" + [H, ...rows].map(r => r.map(v => '"' + String(v ?? "").replace(/"/g, '""') + '"').join(",")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  a.download = `ทะเบียนอุทธรณ์_${view.fy === "all" ? "ทุกปี" : "ปีงบ" + view.fy}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
};

// ---------- จัดการผู้ใช้ (ผู้ดูแล) ----------
function renderMembers() {
  $("memList").innerHTML = members.length ? members.map(m => {
    const self = m.user === me.user, off = m.role === "disabled";
    return `<div class="mem${off ? " off" : ""}" data-user="${esc(m.user)}">
      <div class="who"><div><strong>${esc(m.user)}</strong>${self ? ' <span class="small">(คุณ)</span>' : ""}${off ? ' <span class="role">ยกเลิกสิทธิ์แล้ว</span>' : ""}</div>${m.name ? `<div class="small">${esc(m.name)}</div>` : ""}</div>
      <div class="actions">${off
        ? '<button type="button" class="btn" data-restore style="padding:4px 10px">คืนสิทธิ์</button><button type="button" class="btn danger" data-remove style="padding:4px 10px">ลบบัญชี</button>'
        : `<select data-role aria-label="สิทธิ์ของ ${esc(m.user)}" ${self ? "disabled" : ""}>
          ${["admin", "editor", "viewer"].map(r => `<option value="${r}" ${m.role === r ? "selected" : ""}>${ROLE_TH[r]}</option>`).join("")}
        </select>${self ? "" : '<button type="button" class="btn" data-reset style="padding:4px 10px">ตั้งรหัสใหม่</button><button type="button" class="btn danger" data-del style="padding:4px 10px">ยกเลิกสิทธิ์</button>'}`}
      </div>
      <form class="reset-row" data-reset-form hidden><input type="text" placeholder="รหัสผ่านใหม่ (อย่างน้อย 4 ตัว)" aria-label="รหัสผ่านใหม่ของ ${esc(m.user)}" autocomplete="off"><button type="submit" class="btn primary" style="padding:4px 10px">บันทึก</button></form>
      </div>`; }).join("") : '<div class="mem small">ยังไม่มีผู้ใช้</div>';
}
const setUser = (u, data) => setDoc(doc(db, "users", u), { ...data, updatedBy: me.user, updatedAt: serverTimestamp() }, { merge: true });
function confirmTwice(b, label, confirmLabel) {
  if (b.dataset.confirm === "1") return true;
  b.dataset.confirm = "1"; b.textContent = confirmLabel;
  setTimeout(() => { b.dataset.confirm = ""; b.textContent = label; }, 4000);
  return false;
}
$("memList").addEventListener("change", async e => {
  const sel = e.target.closest("[data-role]"); if (!sel) return;
  try { await setUser(sel.closest(".mem").dataset.user, { role: sel.value }); toast("เปลี่ยนสิทธิ์แล้ว"); }
  catch (err) { toast(errText(err)); }
});
$("memList").addEventListener("click", async e => {
  const b = e.target.closest("button[data-restore],button[data-del],button[data-remove],button[data-reset]"); if (!b) return;
  const row = b.closest(".mem"), u = row.dataset.user;
  try {
    if ("reset" in b.dataset) { const f = row.querySelector("[data-reset-form]"); f.hidden = !f.hidden; if (!f.hidden) f.querySelector("input").focus(); return; }
    if ("restore" in b.dataset) { await setUser(u, { role: "editor" }); toast(`คืนสิทธิ์ ${u} แล้ว (ผู้บันทึก)`); return; }
    if ("del" in b.dataset) { if (!confirmTwice(b, "ยกเลิกสิทธิ์", "ยืนยันยกเลิก")) return; await setUser(u, { role: "disabled" }); toast(`ยกเลิกสิทธิ์ ${u} แล้ว`); return; }
    if ("remove" in b.dataset) { if (!confirmTwice(b, "ลบบัญชี", "ยืนยันลบ")) return; await deleteDoc(doc(db, "users", u)); toast(`ลบบัญชี ${u} แล้ว`); }
  } catch (err) { toast(errText(err)); }
});
$("memList").addEventListener("submit", async e => {
  const f = e.target.closest("[data-reset-form]"); if (!f) return;
  e.preventDefault();
  const u = f.closest(".mem").dataset.user, p = f.querySelector("input").value;
  if (p.length < 4) { toast("รหัสผ่านต้องมีอย่างน้อย 4 ตัว"); return; }
  try { await setUser(u, { pw: await hashPw(u, p) }); f.hidden = true; f.querySelector("input").value = ""; toast(`ตั้งรหัสผ่านใหม่ให้ ${u} แล้ว`); }
  catch (err) { toast(errText(err)); }
});
$("memForm").addEventListener("submit", async e => {
  e.preventDefault();
  const u = $("m_user").value.trim().toLowerCase(), p = $("m_pass").value;
  const er = $("memErr"); er.hidden = true;
  const fail = t => { er.hidden = false; er.textContent = " " + t; };
  if (!USER_RE.test(u)) return fail("ชื่อผู้ใช้ใช้ได้เฉพาะ a–z, 0–9, จุด, ขีด ยาว 3–30 ตัว ขึ้นต้นด้วยตัวอักษรหรือตัวเลข");
  if (p.length < 4) return fail("รหัสผ่านต้องมีอย่างน้อย 4 ตัว");
  const btn = $("memAddBtn"); btn.disabled = true;
  try {
    if ((await getDoc(doc(db, "users", u))).exists()) return fail(`มีผู้ใช้ชื่อ ${u} อยู่แล้ว`);
    await setDoc(doc(db, "users", u), { name: $("m_name").value.trim(), role: $("m_role").value, pw: await hashPw(u, p), createdBy: me.user, createdAt: serverTimestamp() });
    ["m_user", "m_pass", "m_name"].forEach(i => $(i).value = "");
    toast(`สร้างผู้ใช้ ${u} แล้ว`);
  } catch (err) { fail(errText(err)); }
  finally { btn.disabled = false; }
});

boot();
