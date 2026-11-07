# Releasing promptwall-agent to PyPI

The package publishes as **`promptwall-agent`**. The name `promptwall` on PyPI belongs to an
unrelated project. Users still write `import promptwall` and run the `promptwall` command.

Publishing uses **trusted publishing**: PyPI trusts this repository's `publish.yml` workflow
through GitHub's short-lived OIDC token, so there is no API token to create, store or leak.

## One-time setup

1. **PyPI:** log in at <https://pypi.org>, then go to Account → **Publishing** → add a pending
   **GitHub** publisher:

   | Field | Value |
   |---|---|
   | PyPI project name | `promptwall-agent` |
   | Owner | `Abhigyanv23` |
   | Repository | `promptwall` |
   | Workflow | `publish.yml` |
   | Environment | `pypi` |

   A pending publisher does **not** reserve the name. Publish soon after adding it.
2. **TestPyPI** (optional rehearsal): do the same at <https://test.pypi.org> (a separate
   account), with environment `testpypi`.
3. **GitHub:** go to the repository's Settings → **Environments** and create `pypi` (and
   `testpypi`). Optionally add yourself as a required reviewer on `pypi`, so every release waits
   for one click.

## Every release

1. Bump the version in **both** `pyproject.toml` and `promptwall/__init__.py`.
   `tests/test_version.py` fails if they differ.
2. Push and wait for CI to pass.
3. Optional: Actions → **Publish** → *Run workflow* uploads to TestPyPI. Check it with
   `pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ promptwall-agent`.
4. On GitHub, go to Releases → **Draft a new release**, create the tag `v<version>` (for example
   `v0.3.0`), write notes and **Publish release**. The workflow builds, checks that the tag matches
   the version, and uploads to PyPI.

A version can be uploaded to PyPI only once. To fix a broken release, bump the version.