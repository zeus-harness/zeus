-- Phase E: complete the WorkItem collaboration boundary.

alter table work_items
  add constraint work_items_title_length
    check (length(btrim(title)) between 1 and 500),
  add constraint work_items_description_length
    check (length(description) <= 50000),
  add constraint work_items_source_kind_length
    check (source_kind is null or length(btrim(source_kind)) between 1 and 64),
  add constraint work_items_external_reference_length
    check (external_reference is null or length(btrim(external_reference)) between 1 and 2048),
  add constraint work_items_idempotency_key_length
    check (idempotency_key is null or length(btrim(idempotency_key)) between 1 and 255);

create index work_items_status_list_idx
  on work_items (organization_id, workspace_id, status, created_at desc, id desc);
create index work_items_assignee_list_idx
  on work_items (organization_id, workspace_id, assignee_user_id, created_at desc, id desc)
  where assignee_user_id is not null;
create index work_items_active_priority_idx
  on work_items (organization_id, workspace_id, priority, updated_at desc, id desc)
  where status in ('open', 'in_progress', 'blocked');

create table work_item_external_references (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  work_item_id uuid not null references work_items(id),
  source_kind text not null,
  external_reference text not null,
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  unique (work_item_id, source_kind, external_reference),
  check (length(btrim(source_kind)) between 1 and 64),
  check (source_kind = lower(source_kind)),
  check (source_kind ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  check (length(btrim(external_reference)) between 1 and 2048)
);
create index work_item_external_references_organization_id_idx
  on work_item_external_references (organization_id);
create index work_item_external_references_workspace_id_idx
  on work_item_external_references (workspace_id);
create index work_item_external_references_work_item_id_idx
  on work_item_external_references (work_item_id, created_at, id);
create index work_item_external_references_created_by_idx
  on work_item_external_references (created_by);

alter table work_item_external_references enable row level security;
alter table work_item_external_references force row level security;
create policy workspace_isolation on work_item_external_references
  using (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  )
  with check (
    organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id())
  );

create trigger work_item_external_references_append_only
before update or delete on work_item_external_references
for each row execute function zeus_private.reject_mutation();

alter table attachments
  add constraint attachments_file_name_length
    check (length(btrim(file_name)) between 1 and 255 and file_name !~ E'[\\r\\n]'),
  add constraint attachments_content_type_length
    check (length(btrim(content_type)) between 1 and 255 and content_type !~ E'[\\r\\n]'),
  add constraint attachments_sha256_length
    check (octet_length(sha256) = 32);

create trigger attachments_append_only
before update or delete on attachments
for each row execute function zeus_private.reject_mutation();

grant select, insert on table public.work_item_external_references to zeus_http;
revoke update, delete on table public.work_item_external_references from zeus_http;
revoke update, delete on table public.attachments from zeus_http;
