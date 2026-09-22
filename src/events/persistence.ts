import { insertSecurityEvent } from "./repository";
import type { SecurityEvent } from "./types";

export const persistSecurityEventBestEffort = async (
  db: D1Database | undefined,
  event: SecurityEvent,
): Promise<void> => {
  if (!db) {
    return;
  }

  try {
    await insertSecurityEvent(db, event);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "security_event_persistence_failure",
        requestId: event.requestId,
        clientId: event.clientId,
        message: "D1 event persistence failed; request outcome preserved.",
        error: error instanceof Error ? error.message : String(error),
      }),
    );
  }
};
