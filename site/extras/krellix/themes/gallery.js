(() => {
  const catalog = document.getElementById("theme-downloads");
  const controls = catalog.querySelector(".theme-controls");
  const query = document.getElementById("theme-query");
  const availability = document.getElementById("theme-availability");
  const nav = catalog.querySelector(".theme-collections");
  const status = catalog.querySelector(".theme-status");
  const empty = catalog.querySelector(".theme-empty");
  const normalize = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

  const groups = Array.from(nav.querySelectorAll("a"), (link) => {
    const section = document.getElementById(link.hash.slice(1));
    const style = section.querySelector("h3").textContent;
    const cards = Array.from(section.querySelectorAll(".theme-card"), (card) => ({
      card,
      text: normalize([style, card.id.slice(5), card.querySelector("h4").textContent,
        card.querySelector("p")?.textContent ?? ""].join(" ")),
    }));
    return { section, link, cards };
  });
  const total = groups.reduce((count, group) => count + group.cards.length, 0);

  function update() {
    const words = normalize(query.value).split(" ").filter(Boolean);
    let matches = 0;
    for (const { section, link, cards } of groups) {
      let visible = false;
      for (const { card, text } of cards) {
        card.hidden = (availability.value !== "" && card.dataset.availability !== availability.value)
          || !words.every((word) => text.includes(word));
        if (!card.hidden) {
          visible = true;
          matches++;
        }
      }
      section.hidden = link.hidden = !visible;
    }

    nav.hidden = matches === 0;
    empty.hidden = matches !== 0;
    const count = matches === total ? `${total} themes` : `${matches} of ${total} themes`;
    status.textContent = matches === 0 ? "No matching themes." : count;
  }

  query.addEventListener("input", update);
  availability.addEventListener("change", update);
  document.getElementById("clear-theme-filters").addEventListener("click", () => {
    query.value = "";
    availability.value = "";
    update();
    query.focus();
  });
  window.addEventListener("pageshow", update);
  update();
  controls.hidden = false;
})();
