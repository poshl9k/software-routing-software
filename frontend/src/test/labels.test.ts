import { describe, expect, it } from "vitest";
import { displayPair, displayTitle, sourceDisplayPair } from "../labels";

describe("declared item labels", () => {
  it("falls back to the technical name", () => {
    expect(displayTitle({ name: "geosite-grok" })).toBe("geosite-grok");
    expect(displayPair({ name: "geosite-grok", label: "  " })).toBe("geosite-grok");
  });

  it("shows the human title first and the tag second", () => {
    const item = { name: "geosite-grok", label: "Grok (xAI)" };
    expect(displayTitle(item)).toBe("Grok (xAI)");
    expect(displayPair(item)).toBe("Grok (xAI) · geosite-grok");
  });

  it("prefers an explicit source label over a preset title", () => {
    const preset = { name: "Grok (xAI)", rule_sets: [{ tag: "geosite-grok" }] };
    expect(sourceDisplayPair({ name: "geosite-grok" }, [preset]))
      .toBe("Grok (xAI) · geosite-grok");
    expect(sourceDisplayPair({ name: "geosite-grok", label: "Мой список" }, [preset]))
      .toBe("Мой список · geosite-grok");
  });
});
