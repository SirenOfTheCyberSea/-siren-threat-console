import cron from "node-cron";
import { runIngest } from "./ingest.js";

const DEFAULT_SCHEDULE = "*/30 * * * *"; // every 30 minutes

export function startScheduler() {
  const schedule = process.env.INGEST_CRON || DEFAULT_SCHEDULE;

  // Kick off an initial ingest shortly after boot, then follow the cron schedule.
  setTimeout(() => {
    runIngest().catch((err) => console.error("Initial ingest failed:", err));
  }, 2000);

  if (!cron.validate(schedule)) {
    console.warn(`Invalid INGEST_CRON "${schedule}", falling back to ${DEFAULT_SCHEDULE}`);
  }

  const task = cron.schedule(cron.validate(schedule) ? schedule : DEFAULT_SCHEDULE, () => {
    runIngest().catch((err) => console.error("Scheduled ingest failed:", err));
  });

  return task;
}
