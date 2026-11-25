#!/usr/bin/env python3
"""One-shot generator for the simplified FRP TOOL portal page.

Reads button definitions from sr.html and produces a clean, minimal
web/index.html that contains ONLY:
  * the title / brand header
  * a horizontal tabs bar (Show All / General Android / Lock Screen &
    Security / Device Settings / Download Apps)
  * the tool cards with all deep-link / download buttons

All of the following have been REMOVED:
  * the "CAPTIVE PORTAL You're connected" hero card
  * the stats grid (portal address, Wi-Fi network, files count, DNS)
  * the "Available files" card
  * the "Connection details" card
  * the old combobox/dropdown selector (replaced by tabs)

Missing icon images fall back to a clean on-theme letter tile via inline
onerror. The original /assets/... paths are preserved, so dropping the
real images into web/assets/ makes them appear with no code change.
"""
import html as ihtml
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SR = (ROOT / "sr.html").read_text(encoding="utf-8")

# ---- extract selector options ------------------------------------------------
opts = re.findall(
    r'(?s)<div class="custom-select-option[^"]*"\s+data-value="([^"]+)"[^>]*>(.*?)</div>',
    SR,
)

# ---- extract the four cards + their buttons ----------------------------------
start = SR.index('<div class="cards">')
end = SR.index('<script>', start)
region = SR[start:end]
card_parts = re.split(r'(?s)(<div class="card" id="[^"]+">)', region)
card_pairs = []
for i in range(1, len(card_parts), 2):
    card_pairs.append((card_parts[i], card_parts[i + 1]))

BTN = re.compile(
    r'(?s)<a\s+([^>]*)>\s*<div class="icon">\s*<img src="([^"]*)" alt="([^"]*)">'
    r'\s*</div>\s*<div class="label">(.*?)</div>\s*</a>'
)


def get_attr(tag: str, name: str):
    m = re.search(r'\b' + name + r'="([^"]*)"', tag)
    return m.group(1) if m else None


def seckey(raw: str) -> str:
    raw = ihtml.unescape(raw)
    return {"lock_screen_&_security": "lock_security"}.get(raw, raw)


def initial_of(label: str) -> str:
    s = ihtml.unescape(label).strip()
    for prefix in ("Open ", "Launch ", "Go to ", "Start ", "Enable ", "Add ", "Set "):
        if s.startswith(prefix) or s.startswith(prefix.lower()):
            s = s[len(prefix):]
            break
    s = s.lstrip("*#0123456789 -_.")
    ch = s[:1].upper()
    return ch if ch.isalnum() else "?"


def tile(tag: str, g2: str, _g3: str, g4: str) -> str:
    href = get_attr(tag, "href")
    target = get_attr(tag, "target")
    download = get_attr(tag, "download")
    cls = get_attr(tag, "class") or ""
    is_dl = "download-btn" in cls
    img_abs = "/" + g2.lstrip("/")
    label = ihtml.escape(ihtml.unescape(g4))
    initial = ihtml.escape(initial_of(g4))
    attrs = ' class="tile' + (" download-btn" if is_dl else "") + '"'
    attrs += ' href="%s"' % href
    if target:
        attrs += ' target="%s"' % target
    if download:
        attrs += ' download="%s"' % download
    return (
        '      <a%s>\n'
        '        <span class="tile-ic" data-initial="%s">'
        '<img class="tile-img" src="%s" alt="" onerror="iconFallback(this)"></span>\n'
        '        <span class="tile-lb">%s</span>\n'
        '      </a>' % (attrs, initial, img_abs, label)
    )


# ---- build tabs HTML ---------------------------------------------------------
tabs_html = ""
for val, text in opts:
    v = seckey(val)
    t = ihtml.escape(ihtml.unescape(text))
    active = " active" if v == "all" else ""
    tabs_html += (
        '    <button class="tab%s" data-value="%s">%s</button>\n'
        % (active, v, t)
    )

# ---- build cards HTML --------------------------------------------------------
cards_html = ""
tile_count = 0
for raw_id, content in card_pairs:
    cid = re.match(r'<div class="card" id="([^"]+)"', raw_id).group(1)
    key = seckey(cid)
    title = ihtml.escape(ihtml.unescape(
        re.search(r'(?s)<div class="card-title">(.*?)</div>', content).group(1)))
    tiles = []
    for m in BTN.finditer(content):
        tiles.append(tile(*m.groups()))
    tile_count += len(tiles)
    cards_html += (
        '  <section class="card tool-card" data-section="%s">\n'
        '    <div class="card-head"><div><h2>%s</h2>'
        '<p>Tap a shortcut to open it on the connected device</p></div></div>\n'
        '    <div class="tool-grid">\n%s\n    </div>\n  </section>\n'
        % (key, title, "\n".join(tiles))
    )

# ---- assemble full HTML ------------------------------------------------------
HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#eef2ff">
<title>FRP TOOL</title>
<style>
  :root{
    --bg:#f4f6fc; --ink:#172033; --muted:#68738b; --line:#e6eaf3;
    --card:#ffffff; --accent:#4f46e5; --accent-soft:#eef0ff;
    --mint:#0f9d76; --shadow:0 18px 50px rgba(31,42,80,.09);
    --radius:20px;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    color:var(--ink); background:var(--bg); min-height:100vh;
    -webkit-font-smoothing:antialiased; overflow-x:hidden;
  }
  .glow{position:fixed;border-radius:50%;filter:blur(70px);pointer-events:none;z-index:0}
  .glow.one{width:420px;height:420px;background:rgba(99,102,241,.18);top:-160px;right:-120px}
  .glow.two{width:360px;height:360px;background:rgba(20,184,166,.14);bottom:-180px;left:-120px}
  .shell{position:relative;z-index:1;max-width:920px;margin:0 auto;padding:22px 20px 40px}

  .topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}
  .brand{display:flex;align-items:center;gap:12px}
  .mark{
    width:44px;height:44px;border-radius:13px;display:grid;place-items:center;
    background:linear-gradient(145deg,#5b52f0,#7c74ff);color:#fff;
    box-shadow:0 8px 20px rgba(79,70,229,.32);flex:none;
  }
  .brand strong{display:block;font-size:17px;letter-spacing:.09em}
  .brand span{display:block;font-size:12px;color:var(--muted);margin-top:2px}
  .pill{
    display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;
    color:#0b7d5e;background:#e6f8f1;border:1px solid #c9eede;
    padding:8px 13px;border-radius:999px;white-space:nowrap;
  }
  .pill i{width:7px;height:7px;border-radius:50%;background:#12b886;box-shadow:0 0 0 4px rgba(18,184,134,.16)}

  /* ---- Tabs bar ---- */
  .tabs-bar{
    display:flex;gap:0;margin-bottom:18px;background:var(--card);
    border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);
    overflow:hidden;overflow-x:auto;-webkit-overflow-scrolling:touch;
    scrollbar-width:thin;
  }
  .tab{
    flex:1 0 auto;min-width:fit-content;padding:13px 18px;border:none;background:transparent;
    font-size:13.5px;font-weight:650;color:var(--muted);cursor:pointer;
    white-space:nowrap;border-bottom:3px solid transparent;
    transition:color .15s ease,background .15s ease,border-color .15s ease;
    -webkit-tap-highlight-color:transparent;
  }
  .tab:hover{color:var(--ink);background:var(--accent-soft)}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent);background:var(--accent-soft)}

  /* ---- Tool cards ---- */
  .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;margin-bottom:18px}
  .card-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}
  .card-head h2{font-size:17px;margin:0 0 5px;letter-spacing:-.01em}
  .card-head p{font-size:13px;color:var(--muted);margin:0;line-height:1.5}
  .tool-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
  @media(max-width:680px){.tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
  .tile{
    display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;
    padding:14px 8px;min-height:88px;background:var(--card);border:1px solid var(--line);
    border-radius:14px;text-decoration:none;color:var(--ink);
    transition:transform .15s ease,border-color .15s ease,box-shadow .15s ease;
  }
  .tile:hover{transform:translateY(-2px);border-color:#cfd3f7;box-shadow:var(--shadow)}
  .tile:active{border-color:var(--accent)}
  .tile-ic{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;
    overflow:hidden;background:var(--accent-soft);color:var(--accent);font-weight:800;font-size:16px}
  .tile-ic img{width:100%;height:100%;object-fit:contain}
  .tile-ic.ic-fallback{font-size:17px;letter-spacing:.02em}
  .tile-lb{font-size:11.5px;font-weight:600;text-align:center;line-height:1.25}
  .tile.disabled{opacity:.5;pointer-events:none}

  footer{text-align:center;color:#8d96aa;font-size:11.5px;margin-top:26px;line-height:1.8}

  @media(max-width:680px){
    .shell{padding:16px 14px 30px}
    .card{padding:19px}
    .tabs-bar{border-radius:12px}
    .tab{padding:11px 14px;font-size:12.5px}
  }
</style>
<script>
function iconFallback(img){
  var cell=img.parentElement;
  if(!cell || cell.classList.contains('ic-fallback')) return;
  cell.classList.add('ic-fallback');
  cell.textContent = cell.getAttribute('data-initial') || '?';
}
</script>
</head>
<body>
<div class="glow one"></div><div class="glow two"></div>

<div class="shell">
  <header class="topbar">
    <div class="brand">
      <div class="mark">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round">
          <path d="M2 8.8a15 15 0 0 1 20 0"/><path d="M5.5 12.3a10 10 0 0 1 13 0"/>
          <path d="M9 15.8a5 5 0 0 1 6 0"/><circle cx="12" cy="19.2" r="1.2" fill="currentColor" stroke="none"/>
        </svg>
      </div>
      <div><strong>FRP TOOL</strong><span>Quick access portal</span></div>
    </div>
    <span class="pill"><i></i> Connected</span>
  </header>

  <div class="tabs-bar" id="tabsBar">
""" + tabs_html + """  </div>

""" + cards_html + """
<footer>FRP TOOL · Python edition<br><span id="clock"></span></footer>
</div>

<script>
(function(){
  var tabs=document.querySelectorAll('.tab');
  tabs.forEach(function(tab){
    tab.addEventListener('click',function(){
      var v=tab.getAttribute('data-value');
      tabs.forEach(function(t){t.classList.remove('active');});
      tab.classList.add('active');
      document.querySelectorAll('.tool-card').forEach(function(c){
        c.style.display=(v==='all'||c.getAttribute('data-section')===v)?'':'none';
      });
    });
  });
})();
</script>
<script>
(function(){
  document.querySelectorAll('.tile-img').forEach(function(img){
    img.addEventListener('error',function(){iconFallback(img);});
    if(img.complete && img.naturalWidth===0){iconFallback(img);}
  });
  // Download-lock check, on demand only: one request per page load, then only
  // while a transfer is actually running (or right after a tile is tapped).
  // Nothing is polled while the page is idle or in the background.
  var btns=[].slice.call(document.querySelectorAll('.download-btn'));
  var timer=null,polls=0;
  function paint(busy){
    btns.forEach(function(b){
      if(busy){b.classList.add('disabled');}else{b.classList.remove('disabled');}
    });
  }
  function schedule(ms){clearTimeout(timer);timer=setTimeout(check,ms);}
  function check(){
    clearTimeout(timer);timer=null;
    if(document.hidden){return;}
    polls++;
    fetch('/status/download?t='+Date.now(),{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(d){
        paint(!!d.busy);
        if(d.busy&&polls<240){schedule(1500);}
      }).catch(function(){if(polls<240){schedule(4000);}});
  }
  btns.forEach(function(b){
    b.addEventListener('click',function(){polls=0;schedule(1200);});
  });
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden){polls=0;check();}
  });
  check();

  // Clock
  var c=document.getElementById('clock');
  if(c){c.textContent=new Date().toLocaleString();
    setInterval(function(){c.textContent=new Date().toLocaleString();},30000);}
})();
</script>

</body>
</html>
"""

# Don't overwrite if reading current index for reference is needed -- just write.
(ROOT / "web" / "index.html").write_text(HTML, encoding="utf-8")
print("tiles written:", tile_count)
print("options:", len(opts), "cards:", len(card_pairs))
print("has tabs:", 'class="tabs-bar"' in HTML)
print("has hero:", '<section class="hero">' in HTML)
print("has stats:", 'class="stats"' in HTML)
print("has files card:", 'id="files"' in HTML)
print("has connection details:", 'Connection details' in HTML)
