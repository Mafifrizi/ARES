import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useSessionState } from "./dashboardUiState";

describe("dashboard session state", () => {
  it("rehydrates and persists a campaign selection without changing the storage key", () => {
    const key = "ares.dashboard.selectedCampaignId";
    sessionStorage.setItem(key, JSON.stringify("campaign-before"));

    const { result } = renderHook(() => useSessionState(key, ""));
    expect(result.current[0]).toBe("campaign-before");

    act(() => result.current[1]("campaign-after"));
    expect(sessionStorage.getItem(key)).toBe(JSON.stringify("campaign-after"));
  });
});
