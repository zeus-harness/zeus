# Organization IM Studio

IM Studio is organization-scoped and independent of Workspace and Agent execution Sessions. Open `/organizations/<organization-id>/im` from the Studio navigation. Business resources remain in Business Studio; configuration entry points are collected in Management Terminal.

## Available behavior

- Organization directory with prefix search and cursor pagination.
- Direct conversations deduplicated by the two participants; groups of up to 50 members.
- Persistent plain-text messages, replies, member mentions, unread counts and paginated history.
- Group owners can rename the group and add organization members. Members can leave; ownership transfers to a remaining member.
- Added or rejoining members only see messages from their latest join onward.
- The visible page synchronizes every three seconds, retries after transient failures and resumes after returning to the tab. This version uses polling, not push delivery.
- A client-generated request UUID makes identical message retries idempotent. A changed payload with the same UUID is rejected.

## Access boundaries

Every request requires an active human organization membership and an active conversation membership. Organization ownership and platform support grants do not grant access to other people's conversations. Tables enforce RLS; writes use narrowly scoped database functions. Creating or joining an IM conversation grants no Workspace, Workflow, tool or model permission.

Sender names and organization identities are captured server-side with each message. This release only permits members of the same organization. Cross-organization invitations and externally verified identity presentation are not enabled yet. Agent participation, business-resource cards, attachments and calls are also outside this initial release.

## Verification

`apps/zeus-api/tests/im_postgres.rs` exercises concurrent idempotent sends, sequence allocation, direct-pair deduplication, membership revocation, organization separation, support-grant rejection and join-history restrictions using isolated PostgreSQL and the HTTP database role.

Run `scripts/container e2e test-db` for isolated database coverage. Web checks, tests and build use the standard `pnpm` commands. These checks establish local implementation behavior, not production load or availability guarantees.

Local acceptance (2026-09-18): deployed to port 3000; 136 Rust tests, 273 Web tests, Clippy, Svelte checks/autofixer and Web production build passed. All 10 isolated PostgreSQL test groups passed. Browser checks covered the organization IM entry, conversation form, four-module navigation, management-to-Agent configuration link and a 390px viewport, with no captured browser warnings/errors. The daily test organization had only one member, so multi-user sending was verified by the isolated database tests, not by two live browser sessions. Screenshot evidence is kept locally under `.zeus/evidence/im-studio/` and is not committed.
