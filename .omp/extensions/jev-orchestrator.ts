/**
 * KMS skill-routing hook — before_agent_start.
 *
 * 1. Deterministic: prompts matching a trigger in `.github/copilot-instructions.md`
 *    § Automatic skill routing get that skill's SKILL.md body injected (max 3 skills).
 * 2. Fallback: otherwise, suggests which existing `.github/skills/*\/SKILL.md` best
 *    matches the prompt via one TypeSafe (Jev) choice request. Fail-open: any missing
 *    key, timeout, network error, or parse failure makes this a no-op. Only injects a
 *    hint into model context.
 *
 * Env (Jev fallback only):
 *   TYPESAFE_API_KEY   (required — unset disables the fallback)
 *   TYPESAFE_API_URL   (optional, default https://api.typesafe.ai)
 *   TYPESAFE_MODEL     (optional, default jev-latest)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

const API_URL = process.env.TYPESAFE_API_URL || "https://api.typesafe.ai";
const MODEL = process.env.TYPESAFE_MODEL || "jev-latest";
const ROW = /^\|[^|]*\|\s*`\/([a-z0-9-]+)[^`]*`\s*\|\s*(.+?)\s*\|\s*$/;
const ROUTE_ROW = /^\|\s*`\/([a-z0-9-]+)`\s*\|\s*`(.+)`\s*\|\s*$/;
const ROUTING_HEADING = "## Automatic skill routing";
const MAX_AUTORUN_SKILLS = 3;

interface Trigger {
  skill: string;
  pattern: string;
  regex: RegExp;
}

function loadTriggers(cwd: string): Trigger[] {
  let text: string;
  try {
    text = fs.readFileSync(path.join(cwd, ".github", "copilot-instructions.md"), "utf8");
  } catch {
    return [];
  }
  const lines = text.split("\n");
  const start = lines.findIndex(l => l.trim() === ROUTING_HEADING);
  if (start < 0) return [];
  const triggers: Trigger[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("## ")) break;
    const m = ROUTE_ROW.exec(line);
    if (!m) continue;
    const pattern = m[2].replaceAll("\\|", "|");
    try {
      triggers.push({ skill: m[1], pattern, regex: new RegExp(pattern, "i") });
    } catch {
      // invalid regex: skip the row (check_ai_docs.py C7 reports it)
    }
  }
  return triggers;
}

function skillBody(cwd: string, name: string): string | undefined {
  try {
    const text = fs.readFileSync(path.join(cwd, ".github", "skills", name, "SKILL.md"), "utf8");
    return text.replace(/^---\n[\s\S]*?\n---\n/, "");
  } catch {
    return undefined;
  }
}

function autorunMessage(cwd: string, prompt: string): string | undefined {
  const seen = new Set<string>();
  const sections: string[] = [];
  for (const t of loadTriggers(cwd)) {
    if (sections.length >= MAX_AUTORUN_SKILLS) break;
    if (seen.has(t.skill) || !t.regex.test(prompt)) continue;
    seen.add(t.skill);
    const body = skillBody(cwd, t.skill);
    if (body === undefined) continue;
    sections.push(
      `\n\n## /${t.skill} (trigger: \`${t.pattern}\`)\n[Skill directory: .github/skills/${t.skill}]\n\n${body}`,
    );
  }
  if (sections.length === 0) return undefined;
  return (
    "Auto-selected skill(s) from .github/copilot-instructions.md § Automatic skill routing. " +
    "Apply each to the part of the request matching its trigger; user instructions and " +
    "plan-mode restrictions still take precedence." +
    sections.join("")
  );
}

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
  pi.on("before_agent_start", async (event: { prompt?: string; reason?: string }, ctx: ExtensionContext) => {
    const prompt = event.prompt;
    if (event.reason === "revive" || !prompt) return;
    // Explicit `/command` or `/skill:<name>` invocation (its expansion embeds the skill directory).
    if (prompt.trimStart().startsWith("/") || prompt.includes("[Skill directory: ")) return;
    const content = autorunMessage(ctx.cwd, prompt);
    if (content) {
      return { message: { customType: "kms-skill-autorun", display: false, content } };
    }
    const roster = loadRoster(ctx.cwd);
    if (!roster) return;
    const result = await routeToSkill(prompt, roster);
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
