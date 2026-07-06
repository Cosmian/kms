# cosmian-kms-last-tester-v4

The **Final** quality gate for Cosmian KMS pull requests befor being merged.

**It assumes all unit, integration, and E2E tests are already green upstream.**

Its job is to find behavioral inconsistencies, implicit contract changes, and edge-case interactions that automated pipelines don't have an oracle for by actually running the changed feature against a live KMS instance.

**Only run this at fully developed features, it's not meant to run on broken code. Token usage is high, so be careful.**

## Prerequisites

For UI testing, install the [Chrome DevTools MCP server](https://github.com/mcp/io.github.ChromeDevTools/chrome-devtools-mcp): the skill uses it to interact with the KMS Web UI in a live browser session.

A live KMS server must also be reachable before any test scenario can execute. The skill will either detect one or start one for you. It's usually better to start the server instead of letting the agent figure it out **especially if the new feature introduces new configurations**. Running as "read-to-use" server is a better practice that saves tokens, computing power, and time. The most cummon server that the skill will be using is the one ran using this command :

```bash
pnpm -C ui build && cargo run -p cosmian_kms_server --features non-fips -- -c test_data/configs/server/no_auth.toml
```

### External systems:

If the KMS has to interact with other systems: a HSM, another server, another KMS, it is almost mandatory to instanciate them in advance and prompt him with maximum info. Otherwise, hallucinations _can_ happen because a skill can't figure out how to use external systems (red the AWS prompt)

## Sample prompts

#### _Example: PR that introduces AWS BYOK_

> You are the last testing gate. In this PR, I added an API, Cli commands and an AI that lets us communicate with an Amazon KMS (or AWS KMS) and perform the BYOK flow as per the docs joint in this chat. I have made the AWS KMS available at adress=... port=... and the Cosmian KMS at=... . Read the diffs and perform the tests

#### _Example: A simple UI button_

> I introduced a UI button that lets users change the layout colors in this PR. Test this.

Even such a triavial prompt is proven to work, but the more context the less the randomness.

## Workflow at a glance

![Skill workflow](kms_workflow_blocks_simple.png)

## References

- James Whittaker — [Exploratory Software Testing](https://www.oreilly.com/library/view/exploratory-software-testing/9780321647931/) (2009)
- James Whittaker — [ACC framework (Google)](https://testing.googleblog.com/2011/10/google-test-analytics-now-in-open-source.html)
- [SFDIPOT heuristic](https://www.satisfice.com/download/heuristic-test-strategy-model) (Satisfice / RST)
- Michael Bolton & James Bach — [Rapid Software Testing](https://www.rapidsoftwaretesting.com/)
