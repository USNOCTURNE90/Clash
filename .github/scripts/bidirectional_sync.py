name: Bidirectional Sync

on:
  push:
    branches:
      - main
    paths-ignore:
      - ".github/workflows/**"
      - ".github/scripts/**"
  workflow_dispatch:

concurrency:
  group: bidirectional-sync-clash
  cancel-in-progress: true

jobs:
  sync:
    if: ${{ github.event_name == 'workflow_dispatch' || !contains(github.event.head_commit.message, '[AUTO_SYNC]') }}
    runs-on: ubuntu-latest

    steps:
      - name: Checkout current repo
        uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run bidirectional sync
        env:
          CURRENT_REPO: USNOCTURNE90/Clash
          TARGET_REPO: USNOCTURNE90/Surge
          TARGET_BRANCH: Surge
          SOURCE_TYPE: clash
          GITHUB_TOKEN: ${{ secrets.PAT }}
        run: python .github/scripts/bidirectional_sync.py
