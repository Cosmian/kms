---
name: 'Database Tables Documentation'
description: 'Keep documentation/docs/configuration/database/tables.md in sync with SQL schema changes in crate/server_database'
applyTo: 'crate/server_database/src/stores/sql/*.sql'
---

# Database table documentation sync rules

Whenever you add, remove, or modify a `CREATE TABLE` statement in any `.sql` file under
`crate/server_database/src/stores/sql/`, you **must** update
`documentation/docs/configuration/database/tables.md` in the same commit.

## Normative source

The canonical table definitions live in:

| File | Used by |
|---|---|
| `query.sql` | SQLite and PostgreSQL |
| `query_mysql.sql` | MySQL, MariaDB, Percona |

Both files must stay consistent with each other for tables they both define.

## What to update in `tables.md`

### When a table is **added**

1. Add a row to the overview table at the top.
2. Update the table count in the overview sentence (e.g. "consists of five tables").
3. Add a new `## \`table_name\`` section documenting every column (name, type, description)
   and any backend-specific differences (e.g. MySQL AUTO_INCREMENT `id` column).
4. Update the "Links between tables" section if the new table references or is referenced by
   another table.
5. Add the table to the Mermaid ER diagram if it participates in a logical relationship.

### When a table is **removed**

1. Remove its row from the overview table.
2. Update the table count.
3. Remove its `## \`table_name\`` section entirely.
4. Remove any mention of it from the "Links between tables" section.
5. Remove it from the Mermaid diagram if present.

### When a column is **added or removed**

1. Update the column table in the `## \`table_name\`` section.
2. Note any backend-specific differences (nullable, type overrides, extra indexes).

### When an **index** is added or removed

1. Update the index table in the relevant `##` section.

## Style rules

- Column types should match the normative `.sql` source exactly.
  List backend variants inline (e.g. `VARCHAR` (PG/SQLite) / `LONGTEXT` (MySQL)).
- Keep the Mermaid ER diagram in sync with the overview table — it must never show
  a table that does not exist, and must not omit a table that participates in a relationship.
- Use consistent Markdown table formatting: `| Column | Type | Description |`.
- Do **not** copy raw SQL into the docs. Describe the schema in prose and table form.

## Checklist (run after every `.sql` change)

- [ ] Did you add a `CREATE TABLE`?  → Add to overview + add `## \`name\`` section.
- [ ] Did you drop / remove a `CREATE TABLE`?  → Remove from overview + remove `## \`name\`` section.
- [ ] Did you change column types or add/remove columns?  → Update the column table.
- [ ] Did you add or remove an index?  → Update the index table.
- [ ] Is the Mermaid diagram still accurate?
- [ ] Is the table count in the overview sentence correct?
- [ ] Is the "Links between tables" section still accurate?
