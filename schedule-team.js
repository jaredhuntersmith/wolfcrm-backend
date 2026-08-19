const UUID_LIKE = /^[0-9a-f-]{16,64}$/i;

export class ScheduleTeamError extends Error {
  constructor(code, message, details = {}, status = 400) {
    super(message);
    this.name = "ScheduleTeamError";
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

export function normalizeAssignmentIDs(input, { field, max = 100 } = {}) {
  if (!Array.isArray(input)) throw new ScheduleTeamError("invalid_assignments", `${field || "assignment"} must be an array.`, { field });
  if (input.length > max) throw new ScheduleTeamError("invalid_assignments", `${field || "assignment"} has too many people.`, { field, max });
  const values = [];
  const seen = new Set();
  for (const raw of input) {
    if (typeof raw !== "string" || !UUID_LIKE.test(raw.trim())) {
      throw new ScheduleTeamError("invalid_assignments", `${field || "assignment"} contains an invalid user ID.`, { field });
    }
    const id = raw.trim().toLowerCase();
    if (!seen.has(id)) {
      seen.add(id);
      values.push(id);
    }
  }
  return values;
}

export function validateAssignments({ salesIDs, workerIDs, activeMemberIDs }) {
  const active = new Set((activeMemberIDs || []).map((id) => id.toLowerCase()));
  const sales_user_ids = normalizeAssignmentIDs(salesIDs, { field: "sales_user_ids", max: 2 });
  const worker_user_ids = normalizeAssignmentIDs(workerIDs, { field: "worker_user_ids", max: Math.max(1, active.size) });
  const invalid = [...sales_user_ids, ...worker_user_ids].filter((id) => !active.has(id));
  if (invalid.length) {
    throw new ScheduleTeamError(
      "invalid_assignment_users",
      "Every assigned person must be an active member of this company.",
      { user_ids: [...new Set(invalid)] }
    );
  }
  return { sales_user_ids, worker_user_ids };
}

export function validateAvailability(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ScheduleTeamError("invalid_availability", "An availability document is required.");
  }
  const enabled = raw.enabled !== false;
  if (!Array.isArray(raw.weekdays)) throw new ScheduleTeamError("invalid_availability", "Weekdays must be an array.", { field: "weekdays" });
  const weekdays = [...new Set(raw.weekdays.map(Number))].sort((a, b) => a - b);
  if (!weekdays.length || weekdays.some((day) => !Number.isInteger(day) || day < 1 || day > 7)) {
    throw new ScheduleTeamError("invalid_availability", "Choose one or more ISO weekdays from 1 through 7.", { field: "weekdays" });
  }
  const start_time = validTime(raw.start_time, "start_time");
  const end_time = validTime(raw.end_time, "end_time");
  if (timeMinutes(end_time) <= timeMinutes(start_time)) {
    throw new ScheduleTeamError("invalid_availability", "Availability end time must be after start time.", { field: "end_time" });
  }
  return { enabled, weekdays, start_time, end_time };
}

export function summarizeScheduleTeam({ events = [], availabilityByUser = {}, companyAvailability, timeZone = "UTC" } = {}) {
  const normalizedEvents = events.map(normalizeEvent).filter(Boolean);
  const unassigned_event_ids = normalizedEvents.filter((event) => !event.finished && event.workerIDs.length === 0).map((event) => event.id);
  const byWorker = new Map();
  const assigned_minutes_by_user = {};

  for (const event of normalizedEvents.filter((value) => !value.finished)) {
    const durationMinutes = Math.max(0, Math.round((event.end.getTime() - event.start.getTime()) / 60000));
    for (const workerID of event.workerIDs) {
      if (!byWorker.has(workerID)) byWorker.set(workerID, []);
      byWorker.get(workerID).push(event);
      assigned_minutes_by_user[workerID] = (assigned_minutes_by_user[workerID] || 0) + durationMinutes;
    }
  }

  const conflicts = [];
  for (const [worker_user_id, workerEvents] of byWorker) {
    workerEvents.sort((a, b) => a.start - b.start || a.end - b.end || a.id.localeCompare(b.id));
    for (let i = 0; i < workerEvents.length; i += 1) {
      for (let j = i + 1; j < workerEvents.length && workerEvents[j].start < workerEvents[i].end; j += 1) {
        if (workerEvents[j].end > workerEvents[i].start) {
          conflicts.push({ worker_user_id, event_ids: [workerEvents[i].id, workerEvents[j].id] });
        }
      }
    }
  }

  const outside_availability = [];
  for (const event of normalizedEvents.filter((value) => !value.finished)) {
    for (const workerID of event.workerIDs) {
      const profile = availabilityByUser[workerID]?.enabled === false
        ? companyAvailability
        : (availabilityByUser[workerID] || companyAvailability);
      if (profile && !eventFitsAvailability(event, profile, timeZone)) {
        outside_availability.push({ worker_user_id: workerID, event_id: event.id });
      }
    }
  }

  return {
    event_count: normalizedEvents.filter((event) => !event.finished).length,
    unassigned_event_ids,
    conflicts,
    outside_availability,
    assigned_minutes_by_user
  };
}

function validTime(value, field) {
  const text = (value || "").toString().trim();
  if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(text)) {
    throw new ScheduleTeamError("invalid_availability", `${field} must use 24-hour HH:mm format.`, { field });
  }
  return text;
}

function timeMinutes(value) {
  const [hour, minute] = value.split(":").map(Number);
  return hour * 60 + minute;
}

function normalizeEvent(raw) {
  const start = new Date(raw.start ?? raw.start_at);
  const end = new Date(raw.end ?? raw.end_at);
  if (!raw.id || !Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start) return null;
  return {
    id: raw.id.toString(),
    start,
    end,
    workerIDs: Array.isArray(raw.worker_user_ids) ? [...new Set(raw.worker_user_ids.filter((id) => typeof id === "string"))] : [],
    finished: Boolean(raw.finished_at)
  };
}

function zonedParts(date, timeZone) {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23"
  });
  const values = Object.fromEntries(formatter.formatToParts(date).filter((part) => part.type !== "literal").map((part) => [part.type, Number(part.value)]));
  const jsWeekday = new Date(Date.UTC(values.year, values.month - 1, values.day)).getUTCDay();
  return { ...values, isoWeekday: ((jsWeekday + 6) % 7) + 1, minutes: values.hour * 60 + values.minute };
}

function eventFitsAvailability(event, profile, timeZone) {
  const start = zonedParts(event.start, timeZone);
  const end = zonedParts(event.end, timeZone);
  const sameDay = start.year === end.year && start.month === end.month && start.day === end.day;
  return sameDay
    && Array.isArray(profile.weekdays)
    && profile.weekdays.map(Number).includes(start.isoWeekday)
    && start.minutes >= timeMinutes(profile.start_time)
    && end.minutes <= timeMinutes(profile.end_time);
}

