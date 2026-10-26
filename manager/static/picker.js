// Dropdown pickers (the picker macro): choosing an option adds it as a chip, × removes it again.
document.querySelectorAll("[data-picker]").forEach(function (picker) {
  var select = picker.querySelector("[data-add]");
  var chips = picker.querySelector("[data-chips]");
  var name = select.name;
  select.removeAttribute("name");  // only the chips are posted

  function setAvailable(value, available) {
    var option = Array.prototype.find.call(select.options, function (o) { return o.value === value; });
    if (option) { option.disabled = !available; option.hidden = !available; }
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  select.addEventListener("change", function () {
    var option = select.options[select.selectedIndex];
    if (!option || !option.value) return;
    var chip = el("li", "chip");
    var input = el("input");
    input.type = "hidden"; input.name = name; input.value = option.value;
    chip.append(input, el("span", "mono", option.value));
    if (option.dataset.detail) chip.append(el("span", "chip-detail", option.dataset.detail));
    var remove = el("button", "chip-remove", "×");
    remove.type = "button"; remove.dataset.remove = ""; remove.setAttribute("aria-label", "Remove " + option.value);
    chip.append(remove);
    chips.append(chip);
    setAvailable(option.value, false);
    select.value = "";
  });

  chips.addEventListener("click", function (ev) {
    var remove = ev.target.closest("[data-remove]");
    if (!remove) return;
    var chip = remove.closest(".chip");
    setAvailable(chip.querySelector("input").value, true);
    chip.remove();
    select.focus();
  });
});
