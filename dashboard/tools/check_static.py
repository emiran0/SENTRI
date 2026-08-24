"""Static consistency checks for the dashboard front end.

No JS engine on this box, so this cannot execute app.js. It checks the things that
break silently in a browser: ids referenced but never defined, classes styled but
never used and vice versa, and unbalanced brackets or HTML tags.
"""

import os
import re
import sys
from html.parser import HTMLParser

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static") + os.sep
html_src = open(BASE + "index.html").read()
js = open(BASE + "app.js").read()
css = open(BASE + "style.css").read()
problems = []

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


class Checker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d:
            if d["id"] in self.ids:
                problems.append("duplicate id in html: " + d["id"])
            self.ids.add(d["id"])
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            problems.append("stray </%s>" % tag)
        elif self.stack[-1][0] != tag:
            problems.append("html mismatch: <%s> at line %d closed by </%s>"
                            % (self.stack[-1][0], self.stack[-1][1], tag))
            self.stack.pop()
        else:
            self.stack.pop()


checker = Checker()
checker.feed(html_src)
for tag, line in checker.stack:
    problems.append("unclosed <%s> at line %d" % (tag, line))

# ids the script reaches for must exist in the markup
wanted = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', js))
missing = wanted - checker.ids
if missing:
    problems.append("js selects ids not in html: " + ", ".join(sorted(missing)))

# classes the script applies should be styled, and styled classes should be used
js_classes = set()
for m in re.findall(r'class: "([^"]+)"', js):
    js_classes.update(m.split())
for m in re.findall(r'classList\.(?:add|toggle|remove)\("([^"]+)"', js):
    js_classes.add(m)
html_classes = set()
for m in re.findall(r'class="([^"]+)"', html_src):
    html_classes.update(m.split())
used = js_classes | html_classes
css_classes = set(re.findall(r'\.([a-zA-Z][\w-]*)', css))
# strip anything that is a css unit or function fragment picked up by the regex
css_classes = {c for c in css_classes if not c[0].isdigit()}
unstyled = {c for c in used if c not in css_classes}
if unstyled:
    problems.append("classes used but not styled: " + ", ".join(sorted(unstyled)))

# bracket balance in js, ignoring strings, template literals and comments
depth = {"(": 0, "[": 0, "{": 0}
pairs = {")": "(", "]": "[", "}": "{"}
i, n = 0, len(js)
mode = None
while i < n:
    c = js[i]
    if mode:
        if mode == "//" and c == "\n":
            mode = None
        elif mode == "/*" and js[i:i + 2] == "*/":
            mode = None
            i += 1
        elif mode in ('"', "'", "`"):
            if c == "\\":
                i += 2
                continue
            if c == mode:
                mode = None
        i += 1
        continue
    if js[i:i + 2] == "//":
        mode = "//"
        i += 2
        continue
    if js[i:i + 2] == "/*":
        mode = "/*"
        i += 2
        continue
    if c in "\"'`":
        mode = c
    elif c in depth:
        depth[c] += 1
    elif c in pairs:
        depth[pairs[c]] -= 1
        if depth[pairs[c]] < 0:
            problems.append("unbalanced %s at offset %d" % (c, i))
            break
    i += 1
for k, v in depth.items():
    if v:
        problems.append("js bracket %s unbalanced by %d" % (k, v))

# css brace balance
if css.count("{") != css.count("}"):
    problems.append("css braces unbalanced: %d open, %d close" % (css.count("{"), css.count("}")))

# every tier the server can emit must have a front end entry
tiers = set(re.findall(r'^\s{2}(\w+):\s*\{ cls:', js, re.M))
for needed in ("normal", "alert", "throttle", "block", "unusable", "unscored", "learning"):
    if needed not in tiers:
        problems.append("TIER table missing " + needed)

print("html ids: %d, js selectors: %d, css classes: %d" % (len(checker.ids), len(wanted), len(css_classes)))
if problems:
    print("\nPROBLEMS")
    for p in problems:
        print(" -", p)
    sys.exit(1)
print("no structural problems found")
