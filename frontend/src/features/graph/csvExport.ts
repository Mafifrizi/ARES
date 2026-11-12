// CSV cell encoding with spreadsheet-formula-injection hardening.
// AUDIT run-1 M11: a cell beginning with =,+,-,@ (or a control character) is
// treated as an executable formula by Excel / Google Sheets when the exported
// file is opened, so a hostname like "=cmd|'/c calc'!A1" would run. Prefix such
// cells with a single quote and escape embedded double-quotes before wrapping.
export function csvCell(value: unknown): string {
  let s = value == null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  return `"${s.replace(/"/g, '""')}"`;
}
