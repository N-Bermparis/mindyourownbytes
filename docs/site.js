// The website's only script. Without it, every word is still on the page and every link works.
"use strict";

(function () {
  const note = document.querySelector("[data-typewriter]");
  const controls = document.querySelector(".controls");
  if (note && controls && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    typeOut(note, controls);
  }
  markCurrentSection();

  // Types the first window's note out once, like a terminal. The real text stays in place, invisible
  // until the end, so nothing moves and screen readers have all of it from the start.
  function typeOut(box, controls) {
    const area = box.querySelector(".typing-area");
    const original = area.querySelector(".motive");
    const copy = original.cloneNode(true);
    copy.classList.add("typed");
    copy.setAttribute("aria-hidden", "true");
    const lines = Array.from(copy.children);
    const texts = lines.map((line) => line.textContent);
    lines.forEach((line) => {
      line.textContent = "";
    });
    const cursor = document.createElement("span");
    cursor.className = "cursor";
    const pause = controls.querySelector('[data-action="pause"]');
    const finish = controls.querySelector('[data-action="finish"]');
    let line = 0;
    let typed = 0;
    let timer = 0;
    let paused = false;

    function step() {
      if (line >= lines.length) {
        done();
        return;
      }
      const text = texts[line];
      typed += 1;
      lines[line].textContent = text.slice(0, typed);
      lines[line].appendChild(cursor);
      const last = text[typed - 1];
      let delay = 26;
      if (typed >= text.length) {
        line += 1;
        typed = 0;
        delay = 450;
      } else if (last === ".") {
        delay = 260;
      } else if (last === ",") {
        delay = 120;
      }
      timer = window.setTimeout(step, delay);
    }

    function done() {
      window.clearTimeout(timer);
      const focusWasHere = controls.contains(document.activeElement);
      copy.remove();
      area.classList.remove("is-typing");
      controls.hidden = true;
      if (focusWasHere) {
        original.setAttribute("tabindex", "-1");
        original.focus({ preventScroll: true });
      }
    }

    pause.addEventListener("click", () => {
      paused = !paused;
      pause.setAttribute("aria-pressed", String(paused));
      pause.textContent = paused ? "Resume" : "Pause";
      if (paused) {
        window.clearTimeout(timer);
      } else {
        step();
      }
    });
    finish.addEventListener("click", done);

    area.classList.add("is-typing");
    area.appendChild(copy);
    controls.hidden = false;
    timer = window.setTimeout(step, 600);
  }

  // Underlines the section being read in the bar along the top: the one in the middle of the screen,
  // or the last one once the page can't scroll further, since it may be too short to reach the middle.
  function markCurrentSection() {
    const links = Array.from(document.querySelectorAll(".nav-links a"));
    if (!("IntersectionObserver" in window) || links.length === 0) {
      return;
    }
    const ids = links.map((link) => link.hash.slice(1));
    const strip = document.querySelector(".nav-links");
    let current = "top";
    let shown = "";

    function show() {
      const atEnd = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
      const id = atEnd ? ids[ids.length - 1] : current;
      if (id === shown) {
        return;
      }
      shown = id;
      links.forEach((link, index) => {
        if (ids[index] === id) {
          link.setAttribute("aria-current", "true");
          reveal(link);
        } else {
          link.removeAttribute("aria-current");
        }
      });
    }

    // On a narrow screen the links scroll sideways, so bring the underlined one into view.
    function reveal(link) {
      const left = link.offsetLeft - strip.offsetLeft;
      if (left < strip.scrollLeft || left + link.offsetWidth > strip.scrollLeft + strip.clientWidth) {
        strip.scrollLeft = left - 8;
      }
    }

    const watcher = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            current = entry.target.id;
          }
        }
        show();
      },
      { rootMargin: "-45% 0px -50% 0px" },
    );
    for (const id of ["top", ...ids]) {
      const section = document.getElementById(id);
      if (section) {
        watcher.observe(section);
      }
    }
    window.addEventListener("scroll", show, { passive: true });
  }
})();
