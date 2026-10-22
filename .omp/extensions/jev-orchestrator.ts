/**
 * KMS Jev skill-routing hook — before_agent_start.
 *
 * Suggests which existing `.github/skills/*\/SKILL.md` best matches the
 * current prompt, via one TypeSafe (Jev) choice request. Fail-open: any
 * missing key, timeout, network error, or parse failure makes this a no-op.
 * Never forces skill execution; only injects a hint into model context.
 *
 * Env:
 *   TYPESAFE_API_KEY   (required — unset disables this hook entirely)
 *   TYPESAFE_API_URL   (optional, default https://api.typesafe.ai)
 *   TYPESAFE_MODEL     (optional, default jev-latest)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

const API_URL = process.env.TYPESAFE_API_URL || "https://api.typesafe.ai";
const MODEL = process.env.TYPESAFE_MODEL || "jev-latest";
const ROW = /^\|[^|]*\|\s*`\/([a-z0-9-]+)[^`]*`\s*\|\s*(.+?)\s*\|\s*$/;

type Roster = Record<string, string>;

let cachedRoster: Roster | undefined;
let cachedRosterCwd: string | undefined;

function loadRoster(cwd: string): Roster | undefined {
  if (cachedRoster && cachedRosterCwd === cwd) return cachedRoster;
  const readmePath = path.join(cwd, ".github", "skills", "README.md");
  let text: string;
  try {
    text = fs.readFileSync(readmePath, "utf8");
  } catch {
    return undefined;
  }
  const roster: Roster = {};
  for (const line of text.split("\n")) {
    const m = ROW.exec(line);
    if (m) roster[m[1]] = m[2];
  }
  if (Object.keys(roster).length < 2) return undefined;
  cachedRoster = roster;
  cachedRosterCwd = cwd;
  return roster;
}

interface ChoiceAnswer {
  type: "choice";
  choice: string;
  confidence: number;
}

async function routeToSkill(
  prompt: string,
  roster: Roster,
): Promise<{ choice: string; confidence: number } | undefined> {
  const key = process.env.TYPESAFE_API_KEY;
  if (!key) return undefined;
  const criteria: Record<string, string> = {
    ...roster,
    none: "No existing skill clearly matches; handle as a normal request.",
  };
  const body = {
    state: { prompt },
    model: MODEL,
    questions: {
      route: {
        type: "choice" as const,
        instructions:
          'Which existing KMS repository skill, if any, best matches this request? Pick "none" if nothing fits.',
        criteria,
      },
    },
  };
  try {
    const res = await fetch(`${API_URL}/v1/systemone`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(2500),
    });
    if (!res.ok) return undefined;
    const parsed = (await res.json()) as { answers?: { route?: ChoiceAnswer } };
    const answer = parsed.answers?.route;
    if (!answer || answer.type !== "choice") return undefined;
    return { choice: answer.choice, confidence: answer.confidence };
  } catch {
    return undefined;
  }
}

export default function jevOrchestrator(pi: ExtensionAPI): void {
  pi.on("before_agent_start", async (event: { prompt?: string }, ctx: ExtensionContext) => {
    if (!event.prompt) return;
    const roster = loadRoster(ctx.cwd);
    if (!roster) return;
    const result = await routeToSkill(event.prompt, roster);
    if (!result || result.choice === "none") return;
    const description = roster[result.choice];
    if (!description) return;
    if (result.confidence > 0.85) {
      return {
        message: {
          customType: "jev-orchestrator-hint",
          display: false,
          content: `Likely matching skill: /${result.choice} (${description}). Confidence ${result.confidence.toFixed(2)} — prefer following .github/skills/${result.choice}/SKILL.md for this request unless it clearly does not apply.`,
        },
      };
    }
    if (result.confidence >= 0.6) {
      return {
        message: {
          customType: "jev-orchestrator-hint",
          display: false,
          content: `Possible matching skill: /${result.choice} (${description}). Confidence ${result.confidence.toFixed(2)} — consider confirming with the user before following .github/skills/${result.choice}/SKILL.md.`,
        },
      };
    }
    return;
  });
}
