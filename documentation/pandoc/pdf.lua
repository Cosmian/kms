-- Pandoc Lua filter for the KMS documentation PDF.
--
-- 1. Renders `.admonition` fenced divs (produced by combine.py) as coloured
--    tcolorbox callouts.
-- 2. Shrinks over-wide images to fit the text block, never upscaling.

local COLORS = {
  note      = { frame = "admon-note-frame",      back = "admon-note-back" },
  warning   = { frame = "admon-warning-frame",   back = "admon-warning-back" },
  important = { frame = "admon-important-frame", back = "admon-important-back" },
  info      = { frame = "admon-info-frame",      back = "admon-info-back" },
  tip       = { frame = "admon-tip-frame",       back = "admon-tip-back" },
}

local function tex_escape(s)
  return (s:gsub("([#%%$_{}~^\\&])", "\\%1"))
end

function Div(el)
  if el.classes:includes("admonition") then
    local atype = el.attributes["type"] or "note"
    local title = el.attributes["title"] or ""
    local c = COLORS[atype] or COLORS.note
    local label = atype:gsub("^%l", string.upper)
    -- Avoid "Warning: Warning" when the title already carries the label.
    local tl, ll = title:lower(), label:lower()
    local box_title
    if title == "" then
      box_title = label
    elseif tl == ll or tl:match("^" .. ll .. "%s*:") then
      box_title = title
    else
      box_title = label .. ": " .. title
    end
    local opts = string.format(
      "breakable, enhanced, colback=%s, colframe=%s, boxrule=0.6pt, arc=2mm, "
        .. "left=6pt, right=6pt, top=6pt, bottom=6pt, coltitle=white, "
        .. "colbacktitle=%s, fonttitle=\\sffamily\\small\\bfseries",
      c.back, c.frame, c.frame)
    el.content:insert(1, pandoc.RawBlock("latex",
      "\\begin{tcolorbox}[" .. opts .. ", title={" .. tex_escape(box_title) .. "}]"))
    el.content:insert(pandoc.RawBlock("latex", "\\end{tcolorbox}"))
    return el.content
  end
  return nil
end
