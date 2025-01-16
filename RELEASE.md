# Release

## Table of contents

- [Release](#release)
    - [Table of contents](#table-of-contents)
    - [Step by step](#step-by-step)

## Step by step

To proceed a new release, please follow the steps below:

0. Install git-flow: <https://skoch.github.io/Git-Workflow/>

1. Create new release branch with git-flow:

    ```sh
    git checkout main
    git pull
    git checkout develop
    git pull
    git flow init
    git flow release start X.Y.Z
    ```

2. Install git-cliff to update automatically the [CHANGELOG.md](CHANGELOG.md).

    ```sh
    cargo install git-cliff
    git cliff -p CHANGELOG.md -u -t X.Y.Z
    ```

    Update the links of pull requests. For example, replace (#349) by ([#349](https://github.com/Cosmian/kms/pull/349)).

3. Update the version X.Y.Z almost everywhere:

   - Update in Cargo.toml
   - In Dockerfile and Dockerfile.fips
   - In README.md
   - In documentation folder

   Except:

   - Cargo.lock
   - CHANGELOG.md

4. Update the Cargo.lock file and commit

    ```sh
    cargo build
    git commit -m "build: release X.Y.Z"
    git push
    ```

    Make sure the CI pipeline is green.

5. Finish the release with git-flow:

    ```sh
    git flow release finish X.Y.Z --push
    ```
