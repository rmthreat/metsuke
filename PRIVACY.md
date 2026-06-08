# Privacy Policy - Metsuke Interview Guard

_Last updated: 2026-06-06_

Metsuke Interview Guard ("the extension") is a read-only safety tool for developers
reviewing source code on GitHub, GitLab, and Bitbucket. This policy explains exactly
what the extension does and does not do with your data.

## Summary

**The extension does not collect, store, transmit, or sell any personal data.**
All analysis runs locally in your browser. There are no accounts, no tracking, no
analytics, and no telemetry.

## Data we collect

None. The extension does not collect or transmit any of the following: personally
identifiable information, health information, financial or payment information,
authentication information, personal communications, location, web history, user
activity, or website content.

## Network requests

The extension makes exactly one kind of network request: when you are viewing a file
or repository page on GitHub, GitLab, or Bitbucket, its background service worker
fetches the **raw source of the file you are already viewing** (or a small, fixed set
of well-known configuration files for the repository you are on), from the **same
code host you are already browsing**. This is necessary because the rendered page
often hides code off-screen, and accurate analysis needs the true source.

No third-party servers are contacted. The fetched source is analyzed in memory and is
never uploaded, logged, or persisted.

## Data stored on your device

The extension stores only two small preferences using `chrome.storage.sync`, so they
follow your Chrome profile:

1. The global **on/off switch**.
2. Your **trusted-repository allowlist** (repositories you chose to silence).

No page content, source code, or analysis results are stored.

## "Copy for your trusted AI" feature

When you click this optional button, the extension copies a short text summary of the
detected signals to your **clipboard** only. Nothing is sent anywhere automatically -
you decide whether and where to paste it. If you paste it into a third-party AI
service, that service's own privacy policy applies to what you paste.

## Remote code

The extension uses **no remote code**. All detection rules and logic are bundled in
the package. There are no external scripts, no remotely-hosted modules, and no
evaluation of remote strings.

## Permissions

- `storage` - remembers your on/off switch and trusted-repository list (above).
- Host access to `github.com`, `gitlab.com`, `bitbucket.org`,
  `raw.githubusercontent.com` - runs the local analyzer on the page you are viewing
  and fetches the raw source of that file for accurate analysis.

## Changes to this policy

If this policy changes, the updated version will be published at this same URL with a
new "Last updated" date.

## Contact

Questions about this policy can be raised as an issue on the project's repository.
