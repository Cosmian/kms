# Contributing to Cosmian KMS

Please note: We take Cosmian KMS's security and our users' trust very seriously. If you believe you have found a
security issue in Cosmian KMS, please responsibly disclose by contacting us at
[tech@cosmian.com](mailto:tech@cosmian.com).

First: if you're unsure or afraid of anything, just ask or submit the issue or pull request anyways. You won't be
yelled at for giving it your best effort. The worst that can happen is that you'll be politely asked to change
something. We appreciate any sort of contributions, and don't want a wall of rules to get in the way of that.

That said, if you want to ensure that a pull request is likely to be merged, talk to us! You can find out our thoughts
and ensure that your contribution won't clash or be obviated by Cosmian KMS's normal direction. A great way to do this
is via [GitHub Issues](https://github.com/Cosmian/kms/issues) or [GitHub Discussions](https://github.com/Cosmian/kms/discussions).

## Issues

This section will cover what we're looking for in terms of reporting issues.

By addressing all the points we're looking for, it raises the chances we can quickly merge or address your contributions.

### Reporting an Issue

• Make sure you test against the latest released version. It is possible we already fixed the bug you're experiencing.
Even better is if you can test against the `develop` branch, as bugs are regularly fixed but new versions are only
released periodically.

• Provide steps to reproduce the issue, and if possible include the expected results as well as the actual results.
Please provide text, not screen shots!

• If you are seeing an internal Cosmian KMS error (a status code of 5xx), please be sure to post relevant parts of
(or the entire) Cosmian KMS log, as often these errors are logged on the server but not reported to the user.

• If you experienced a panic, please create a [gist](https://gist.github.com/) of the entire generated crash log for
us to look at. Double check no sensitive items were in the log.

• Respond as promptly as possible to any questions made by the Cosmian KMS team to your issue.

### Issue Lifecycle

1. The issue is reported.

2. The issue is verified and categorized by a Cosmian KMS collaborator. Categorization is done via tags. For example,
   bugs are marked as "bugs".

3. Unless it is critical, the issue may be left for a period of time (sometimes many weeks), giving outside
   contributors -- maybe you!? -- a chance to address the issue.

4. The issue is addressed in a pull request or commit. The issue will be referenced in the commit message so that the
   code that fixes it is clearly linked.

5. The issue is closed.

6. Issues that are not reproducible and/or not gotten responses for a long time are stale issues. In order to provide
   faster responses and better engagement with the community, we strive to keep the issue tracker clean and the issue
   count low. In this regard, our current policy is to close stale issues after 30 days.

Closed issues will still be indexed and available for future viewers. If users feel that the issue is still relevant,
we encourage reopening them.

## Pull Requests

When submitting a PR you should reference an existing issue. If no issue already exists, please create one. This can be
skipped for trivial PRs like fixing typos.

Creating an issue in advance of working on the PR can help to avoid duplication of effort, e.g. maybe we know of
existing related work. Or it may be that we can provide guidance that will help with your approach.

Your pull request should have a description of what it accomplishes, how it does so, and why you chose the approach you
did. PRs should include unit tests that validate correctness and the existing tests must pass. Follow-up work to fix
tests does not need a fresh issue filed.

Someone will do a first pass review on your PR making sure it follows the guidelines in this document. If it doesn't
we'll mark the PR incomplete and ask you to follow up on the missing requirements.

### Changelog Entries

Please include a file within your PR named `changelog/#.txt`, where `#` is your pull request ID. There are many
examples under [changelog](changelog), but the general format is:

CATEGORY is one of `🚀 Features`, `🐛 Bug Fixes`, `📚 Documentation`, `🧪 Testing`, `⚙️ Miscellaneous Tasks`, or
`🚜 Refactor`. Your PR is almost certain to be one of `🐛 Bug Fixes` or `🚀 Features`, but don't worry too much about
getting it exactly right, we'll tell you if a change is needed.

To determine the relevant component, consult [CHANGELOG](CHANGELOG.md) and pick whichever one you see that seems the
closest match.

You do not need to include the link at the end of the summary that appears in CHANGELOG.md, those are generated
automatically by the changelog-building process.

### Cosmian KMS UI

How you contribute to the UI depends on what you want to contribute. If that is a new feature, please submit an
informational issue first. That issue should include a short description of the proposed feature, the use case, the
approach you're taking, and the tests that would be written. A mockup is optional but encouraged.

Bug fixes are welcome in PRs but existing tests must pass and updated logic should be handled in new tests. You needn't
submit an issue first to fix bugs.

Keep in mind that the UI should be consistent with other areas of Cosmian KMS. The UI should be user-centered,
informative, and include edge cases and errors— including accommodations for users who may not have permissions to view
or interact with your feature. If you are not comfortable with UI design, a Cosmian designer can take a look at your
work— just be aware that this might mean it will add some time to the PR process.

Finally, in your code, try to avoid logic-heavy templates (when possible, calculate values in the .js file instead of
.hbs) and web framework anti-patterns. And most of all, if you have any questions, please ask!

## Setting up Rust to work on Cosmian KMS

If you have never worked with Rust before, you will have to complete the following steps:

1. Install Rust using [rustup](https://rustup.rs/)
2. Install the required stable toolchain: `rustup toolchain install 1.90.0`
3. Install required components: `rustup component add rustfmt clippy --toolchain 1.90.0`
4. Build the project: `cargo build --release`

For detailed development setup including Nix-based reproducible builds, please refer to the [README](README.md) and
the build instructions in [.github/copilot-instructions.md](.github/copilot-instructions.md).

## Testing

Before submitting a pull request, please ensure that:

• All existing tests pass: `cargo test`
• Your code is properly formatted: `cargo fmt --check`
• Your code passes clippy lints: `cargo clippy --workspace --all-targets --all-features`
• If you've added new functionality, include appropriate unit and/or integration tests

For database-specific testing, you may need to set up local database instances. See the testing section in the
[build instructions](.github/copilot-instructions.md) for more details.

## Contributor License Agreement

We require that all contributors sign our Contributor License Agreement ("CLA") before we can accept the contribution.

[Learn more about the CLA and sign it here](CLA.md)

## Code of Conduct

This project adheres to the principles of respectful and inclusive collaboration. We expect all contributors to:

• Be respectful and constructive in discussions
• Focus on the technical aspects of contributions
• Help maintain a welcoming environment for all contributors
• Report any behavior that violates these principles to [tech@cosmian.com](mailto:tech@cosmian.com)

## Getting Help

If you need help with your contribution:

• Check the [documentation](documentation/) for technical guides
• Search existing [issues](https://github.com/Cosmian/kms/issues) for similar problems
• Open a new issue with the "question" label
• Contact us at [tech@cosmian.com](mailto:tech@cosmian.com) for general inquiries

Thank you for contributing to Cosmian KMS!
