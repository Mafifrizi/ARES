import { useMemo, useState } from "react";
import type { LiveWebSocketEvent } from "../../../api/types";
import {
  useDashboardUi,
  useTabParam,
} from "../dashboardUiState";
import {
  CampaignPicker,
  EmptyState,
  LiveEventCard,
  Page,
  SectionHeader,
} from "../dashboardComponents";

const VALID_TABS_LIVE = ["Stream", "Buffer"] as const;
type LiveTab = typeof VALID_TABS_LIVE[number];

export function LivePage() {
  const {
    selectedCampaignId,
    setSelectedCampaignId,
    liveCampaignId,
    setLiveCampaignId,
    liveConnected,
    setLiveConnected,
    liveEvents,
    clearLiveEvents,
    campaigns: campaignList
  } = useDashboardUi();
  const campaignId = liveCampaignId || selectedCampaignId;
  const [rawTab, setActiveTab] = useTabParam("Stream");
  const activeTab = (VALID_TABS_LIVE as readonly string[]).includes(rawTab)
    ? (rawTab as LiveTab)
    : "Stream";
  const [bufferViewScope, setBufferViewScope] = useState<"session" | "all">("session");

  const currentCampaign = useMemo(() => {
    return campaignList.find((c) => c.id === campaignId);
  }, [campaignList, campaignId]);

  // Session-isolated events for active campaign
  const sessionEvents = useMemo(() => {
    if (!campaignId) return [];
    return liveEvents.filter((event) => {
      const record = event && typeof event === "object" ? (event as Record<string, unknown>) : null;
      return record?.campaign_id === campaignId;
    });
  }, [liveEvents, campaignId]);

  // Stream uses campaign session events if a campaign is chosen, or global events if viewing all
  const scopedEvents = useMemo(() => {
    return campaignId ? sessionEvents : liveEvents;
  }, [campaignId, sessionEvents, liveEvents]);

  const streamEvents = useMemo(() => scopedEvents.slice(0, 10), [scopedEvents]);

  const displayedBufferEvents = useMemo(() => {
    if (!campaignId || bufferViewScope === "all") {
      return liveEvents;
    }
    return sessionEvents;
  }, [campaignId, bufferViewScope, liveEvents, sessionEvents]);

  return (
    <Page
      title="Live Events"
      actions={<span className={liveConnected ? "status-pill status-low" : "status-pill"}>{liveConnected ? "Listening" : "Offline"}</span>}
      tabs={["Stream", "Buffer"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Stream" && (
      <>
      <div className="panel p-4">
        <SectionHeader
          title="Campaign Event Stream"
          action={<span className="badge">{scopedEvents.length} buffered</span>}
          description="Watch selected campaign events."
        />
        <CampaignPicker
          campaigns={campaignList}
          value={campaignId}
          onChange={(id) => {
            setLiveCampaignId(id);
            setSelectedCampaignId(id);
            if (!id && liveConnected) {
              setLiveConnected(false);
            }
          }}
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button className="btn btn-primary" disabled={!campaignId || liveConnected} onClick={() => {
            if (!liveCampaignId && campaignId) {
              setLiveCampaignId(campaignId);
            }
            setLiveConnected(true);
          }}>
            {liveConnected ? "Connected" : "Connect Stream"}
          </button>
          {liveConnected && (
            <button className="btn" onClick={() => setLiveConnected(false)}>
              Disconnect
            </button>
          )}
          <span className={liveConnected ? "badge badge-low" : "badge"}>{liveConnected ? "listening" : "offline"}</span>
        </div>
      </div>
      <section className="panel p-4">
        <SectionHeader
          title="Current Stream"
          action={
            <div className="flex items-center gap-2">
              <span className="badge">{streamEvents.length} newest</span>
              {streamEvents.length > 0 && (
                <button
                  className="btn"
                  onClick={() => {
                    if (campaignId) {
                      clearLiveEvents(campaignId);
                    } else {
                      clearLiveEvents();
                    }
                  }}
                >
                  Clear Stream
                </button>
              )}
            </div>
          }
        />
        {streamEvents.length > 0 ? (
          <div className="grid gap-2">
            {streamEvents.map((event, index) => (
              <LiveEventCard
                event={event}
                index={index}
                key={(event as LiveWebSocketEvent)?.id || `${(event as LiveWebSocketEvent)?.timestamp || index}-${index}`}
                campaigns={campaignList}
              />
            ))}
          </div>
        ) : (
          <EmptyState
            text={
              !campaignId
                ? "Select a campaign session to stream events, or view global buffer."
                : liveConnected
                  ? `Connected to session '${currentCampaign?.name || campaignId}'. Waiting for incoming events...`
                  : `Session ready for '${currentCampaign?.name || campaignId}'. Click 'Connect Stream' to begin monitoring.`
            }
          />
        )}
      </section>
      </>
      )}
      {activeTab === "Buffer" && (
        <section className="panel p-4">
          <SectionHeader
            title="Buffered Events"
            action={
              <div className="flex items-center gap-2">
                {campaignId && (
                  <div className="flex items-center gap-1 rounded bg-zinc-900/80 p-0.5 border border-zinc-800 text-xs">
                    <button
                      type="button"
                      className={`px-2 py-0.5 rounded transition ${bufferViewScope === "session" ? "bg-zinc-800 text-zinc-100 font-medium" : "text-zinc-400 hover:text-zinc-200"}`}
                      onClick={() => setBufferViewScope("session")}
                    >
                      Active Session ({sessionEvents.length})
                    </button>
                    <button
                      type="button"
                      className={`px-2 py-0.5 rounded transition ${bufferViewScope === "all" ? "bg-zinc-800 text-zinc-100 font-medium" : "text-zinc-400 hover:text-zinc-200"}`}
                      onClick={() => setBufferViewScope("all")}
                    >
                      All Sessions ({liveEvents.length})
                    </button>
                  </div>
                )}
                {displayedBufferEvents.length > 0 ? (
                  <button
                    className="btn"
                    onClick={() => {
                      if (campaignId && bufferViewScope === "session") {
                        clearLiveEvents(campaignId);
                      } else {
                        clearLiveEvents();
                      }
                    }}
                  >
                    {campaignId && bufferViewScope === "session" ? "Clear Session Events" : "Clear All Events"}
                  </button>
                ) : (
                  <span className="badge">0 retained</span>
                )}
              </div>
            }
          />
          {displayedBufferEvents.length > 0 ? (
            <div className="grid gap-2">
              {displayedBufferEvents.map((event, index) => (
                <LiveEventCard
                  event={event}
                  index={index}
                  key={(event as LiveWebSocketEvent)?.id || `${(event as LiveWebSocketEvent)?.timestamp || index}-${index}`}
                  campaigns={campaignList}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              text={
                campaignId && bufferViewScope === "session"
                  ? `No events retained for session '${currentCampaign?.name || campaignId}'.`
                  : "No events retained in the buffer."
              }
            />
          )}
        </section>
      )}
    </Page>
  );
}



export default LivePage;
