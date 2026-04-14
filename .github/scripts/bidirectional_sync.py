def add_local_repo_files(repo_path: Path):
    state_file = repo_path / STATE_FILE
    if state_file.exists():
        run(["git", "add", "--", STATE_FILE], cwd=repo_path)

    for p in sorted(repo_path.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_file():
            continue
        if p.name in SURGE_SKIP or p.name in CLASH_SKIP:
            continue

        suffix = p.suffix.lower()
        if suffix in SURGE_ALLOWED_SUFFIXES or suffix in CLASH_ALLOWED_SUFFIXES or suffix == "":
            run(["git", "add", "--", p.name], cwd=repo_path)

    run(["git", "add", "-u"], cwd=repo_path)


def commit_if_needed(repo_path: Path, message: str):
    run(["git", "config", "user.name", "github-actions[bot]"], cwd=repo_path)
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=repo_path)

    # 先把当前改动存起来，再 rebase，最后恢复改动
    stash_result = subprocess.run(
        ["git", "stash", "push", "-u", "-m", "autosync-temp-stash"],
        cwd=repo_path,
        text=True,
        capture_output=True,
    )

    had_stash = "No local changes to save" not in stash_result.stdout

    run(["git", "pull", "--rebase"], cwd=repo_path)

    if had_stash:
        pop_result = subprocess.run(
            ["git", "stash", "pop"],
            cwd=repo_path,
            text=True,
            capture_output=True,
        )
        if pop_result.returncode != 0:
            raise RuntimeError(
                "git stash pop failed:\n"
                + pop_result.stdout
                + "\n"
                + pop_result.stderr
            )

    if repo_path.resolve() == Path(".").resolve():
        add_local_repo_files(repo_path)
    else:
        run(["git", "add", "-A"], cwd=repo_path)

    status = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo_path)
    if status.returncode == 0:
        return False

    run(["git", "commit", "-m", message], cwd=repo_path)
    run(["git", "push"], cwd=repo_path)
    return True
