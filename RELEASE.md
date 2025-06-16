# Release

## Table of contents

- [Release](#release)
    - [Table of contents](#table-of-contents)
    - [Step by step](#step-by-step)

## Step by step

To proceed a new release, please follow the steps below:

0. Pre-requisites installation:
   1. Install git-flow: <https://skoch.github.io/Git-Workflow/>
   2. Install git-cliff:

    ```sh
    cargo install git-cliff
    ```

1. Create new release branch with git-flow:

    ```sh
    git checkout main
    git pull
    git checkout develop
    git pull
    git flow init
    git flow release start X.Y.Z
    ```

2. Update the version X.Y.Z almost everywhere:

    ```sh
    bash .github/scripts/release.sh <old_version> <new_version>
    ```

3. Commit the changes:

    ```sh
    git commit -m "build: release X.Y.Z"
    git push
    ```

    Make sure the CI pipeline is green.

4. Finish the release with git-flow:

    ```sh
    git flow release finish X.Y.Z --push
    ```

5. Do not forget to update GitHub CHANGELOG in <https://github.com/Cosmian/kms/releases/tag/X.Y.Z> (copy paste from CHANGELOG.md)
