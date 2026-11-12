import { describe, expect, it } from "vitest";

import { csvCell } from "./csvExport";

// AUDIT run-1 M11: CSV export must neutralize spreadsheet formula injection.
describe("csvCell", () => {
  it("prefixes formula-triggering cells with a single quote", () => {
    expect(csvCell("=SUM(A1:A2)")).toBe(`"'=SUM(A1:A2)"`);
    expect(csvCell("+1")).toBe(`"'+1"`);
    expect(csvCell("-2")).toBe(`"'-2"`);
    expect(csvCell("@cmd")).toBe(`"'@cmd"`);
    expect(csvCell("=cmd|'/c calc'!A1")).toBe(`"'=cmd|'/c calc'!A1"`);
  });

  it("escapes embedded double quotes", () => {
    expect(csvCell('a"b')).toBe(`"a""b"`);
  });

  it("leaves ordinary values untouched and handles null/empty", () => {
    expect(csvCell("dc01.corp.local")).toBe(`"dc01.corp.local"`);
    expect(csvCell("")).toBe(`""`);
    expect(csvCell(null)).toBe(`""`);
    expect(csvCell(undefined)).toBe(`""`);
  });
});
