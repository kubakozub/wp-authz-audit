# wp-authz-audit

Find the WordPress plugin code an attacker can reach, and check whether anything
is guarding it.

A mid-sized plugin is tens of thousands of lines. The code an unauthenticated
request can actually reach is usually a couple of dozen callbacks. This turns
"read the plugin" into "read these twenty functions, starting with these three".

```console
$ wp-authz-audit audit advanced-custom-fields
# advanced-custom-fields@6.8.6 — 34 entry points

MEDIUM  CWE-862  [unauth]  Unauthenticated handler reads request data
        includes/validation.php:39  ajax_nopriv wp_ajax_nopriv_acf/validate_save_post
          - wp_ajax_nopriv_acf/validate_save_post is reachable with no credentials
...
```

Offline after the download, no dependencies, Python 3.9+ standard library only.
It never talks to a site under test — only to wordpress.org, and only to fetch
public release archives.

## Why another WordPress scanner

It is not a scanner, and the pattern layer is deliberately the least interesting
part. Semgrep, PHPCS/WordPressCS, and the official Plugin Check already match
patterns, and WordPress.org now runs Plugin Check on every plugin update, so the
greppable defects are increasingly filtered at the source.

What none of them do is answer the question an access-control bug actually asks:
**which guard dominates this sink, and who can reach it?** Taint engines model
where input flows; missing authorization is an *absence* property. PHPCS has no
capability sniff at all — its entire Security category is escaping, nonces,
redirects and input validation.

Two consequences drive the whole design:

**A nonce is not authorization.** `check_ajax_referer()` proves the request was
intended by the user who sent it. That is CSRF defence. A subscriber can
legitimately obtain nonces — plugins hand them to the browser through
`wp_localize_script`. A handler whose only guard is a nonce is unauthorized, and
it reads as *clean* to WordPressCS's NonceVerification sniff.

**A primitive capability is not an ownership check.** `current_user_can(
'edit_posts')` is held by every Contributor. `current_user_can('edit_post',
$id)` runs `map_meta_cap()` against that specific object. A handler that takes
an object id from the request, checks only the primitive form, and writes to
that object is CWE-863 — and it passes anything that merely looks for
`current_user_can`.

## What it finds

| | |
|---|---|
| CWE-862 | Handler reachable without credentials that changes state |
| CWE-862 | Handler reachable by any logged-in user with no capability check |
| CWE-862 | REST route with a missing or `__return_true` permission_callback that writes |
| CWE-862 | REST-exposed meta key with a permissive `auth_callback` |
| CWE-863 | Primitive capability guarding a write to a request-supplied object |

Every finding carries a **required privilege** — `unauth`, `subscriber`,
`contributor`, `author`, `editor`, `admin` — because that is what decides
whether a program will pay for it. Findings needing an editor or administrator
are downranked; the Wordfence program excludes them outright.

### The hook everyone gets wrong

`admin_init` sounds administrative. Both `wp-admin/admin-ajax.php` and
`wp-admin/admin-post.php` fire `do_action('admin_init')` **before** they branch
on `is_user_logged_in()`. An `admin_init` handler that reads `$_GET` and acts on
it is reachable by an anonymous request. Same trap: `is_admin()` is true for
every request to admin-ajax.php, including unauthenticated ones.

## The mode that actually saves time

```console
$ wp-authz-audit diff advanced-custom-fields
# advanced-custom-fields: 6.8.5 -> 6.8.6

new_entry_point        ajax wp_ajax_acf/email_opt_in_banner/state -> ajax_set_state
    includes/admin/admin-email-opt-in-banner.php:57
      - wp_ajax_acf/email_opt_in_banner/state does not exist in the older release
      - state-changing calls: update_option

2 regression(s) to review
```

That release changed hundreds of lines. Reviewing changed *lines* buries you in
refactors, translations and asset churn. Comparing the entry-point **graph**
between releases reports only four things:

- `new_entry_point` — a hook that did not exist before
- `permission_weakened` — a REST permission_callback moved toward permissive
- `guard_removed` — a capability check that is gone
- `sink_added` — a new state-changing call in an already-unguarded handler

Everything else is silence, and the silence is the point. New vulnerabilities
live in new code, so this is where to look first on every release.

## Commands

```bash
wp-authz-audit map   <slug|path>          # every entry point (triage view)
wp-authz-audit audit <slug|path>          # ranked findings
wp-authz-audit diff  <slug>               # guard-set regression, previous -> latest
wp-authz-audit watch --count 30           # recently updated plugins, ranked by findings
```

A target is a local directory, a wordpress.org slug, or `slug@version`. Releases
are cached under `~/.cache/wp-authz-audit`, so re-runs are offline and
reproducible.

```bash
wp-authz-audit audit better-search-replace@1.4.4 --unauth-only
wp-authz-audit diff advanced-custom-fields --from 6.1.5 --to 6.1.6
wp-authz-audit audit ./my-plugin --json | jq '.findings[] | select(.required_privilege=="unauth")'
```

`audit` exits 1 when anything high-severity is present, so it drops into CI.

Downloads use `?nostats=1`, which is what the official directory slurper does, so
browsing a plugin's history does not inflate its author's download counters.
Release ZIPs are compared rather than SVN trees, because what ships to users is
decided by the `Stable Tag:` line in trunk/readme.txt, and SVN lets an author
modify an existing tag after release.

## What it cannot see

An audit tool that oversells itself is worse than none, so these are stated
rather than discovered later:

- **Dynamic dispatch.** WordPress leans on `call_user_func()` with string names
  and interpolated hook names (`wp_ajax_{$action}`). Those resolve at runtime
  and are invisible here. Expect false negatives.
- **Guard chains deeper than two levels.** A capability check wrapped in a
  helper is followed across files, up to depth 2. Deeper chains are missed.
- **Laundered object ids.** `update_post_meta($_POST['id'], …)` is flagged;
  the same value passed through several local variables first is not.
- **Conditional guards.** A check inside one branch is treated as covering the
  handler. Path-sensitivity is not modelled.
- **This is not a PHP parser.** Comments and strings are blanked before matching,
  so a capability named in a docblock never counts as a guard — but unusual
  syntax can still confuse it.

**A finding is a candidate, not a vulnerability.** The tool says "nothing here
guards this"; only you can say what an attacker gains by reaching it. A clean
run means "I found nothing", never "this plugin is safe".

That distinction is not theoretical. Running this against ACF 6.8.6 produced a
`register_meta` finding on `_acf_changed` — a boolean flag ACF uses to detect
whether fields changed. The pattern is real; the impact is nil. The tool now
says so in the output rather than ranking it critical.

## Verification against real code

Development was driven by running against shipping plugins, not only fixtures.
The cross-file guard resolution exists because the first version reported two
critical findings on ACF's AJAX handlers — both wrong. They were guarded by
`acf_current_user_can_admin()`, a plugin-defined wrapper around
`current_user_can()` living in another file. A same-file-only analyser calls
correct code critical, which is the failure that gets a tool muted on day one.
That case is now `tests/fixtures/wrapped_guard.php` and a regression test.

## Responsible use

This analyses public source code offline. It sends nothing to any WordPress
site. Use it inside a program's scope, report through the program, and confirm
impact before you file — an unverified report costs a triager's time and your
signal.

```bash
python3 -m unittest discover -s tests
```

## License

MIT — see [LICENSE](LICENSE).
