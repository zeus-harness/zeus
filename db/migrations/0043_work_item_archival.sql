-- A business goal outlives individual attempts. Archival requires human evidence.
alter table work_items add column archived_at timestamptz;

create table work_item_archives (
  id uuid primary key default uuidv7(),
  organization_id uuid not null references organizations(id),
  workspace_id uuid not null references workspaces(id),
  work_item_id uuid not null unique references work_items(id),
  run_id uuid not null references runs(id),
  review_id uuid not null references work_item_reviews(id),
  workflow_version_id uuid not null references workflow_versions(id),
  work_item_revision bigint not null check (work_item_revision > 0),
  resolution_summary text not null check (length(btrim(resolution_summary)) between 1 and 4000),
  archived_by uuid not null references users(id),
  created_at timestamptz not null default clock_timestamp()
);
create index work_item_archives_org_idx on work_item_archives(organization_id);
create index work_item_archives_workspace_idx on work_item_archives(workspace_id);
create index work_item_archives_run_idx on work_item_archives(run_id);
create index work_item_archives_review_idx on work_item_archives(review_id);
create index work_item_archives_version_idx on work_item_archives(workflow_version_id);
create index work_item_archives_actor_idx on work_item_archives(archived_by);
alter table work_item_archives enable row level security;
alter table work_item_archives force row level security;
create policy workspace_isolation on work_item_archives
  using (organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id()))
  with check (organization_id = (select zeus_private.current_organization_id())
    and workspace_id = (select zeus_private.current_workspace_id()));
create trigger work_item_archives_append_only before update or delete on work_item_archives
  for each row execute function zeus_private.reject_mutation();
grant select, insert on work_item_archives to zeus_http;

-- Serialize new attempts with archival, including retries and child runs inserted by Runtime.
-- The lock also prevents a queued attempt from racing the final acceptance check.
create function zeus_private.guard_archived_work_item_run() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
declare archived timestamptz;
begin
  if new.work_item_id is null then return new; end if;
  select archived_at into archived from work_items
    where id=new.work_item_id and organization_id=new.organization_id and workspace_id=new.workspace_id
    for update;
  if not found then raise foreign_key_violation; end if;
  if archived is not null then
    raise exception using errcode='ZX003', message='work item is archived';
  end if;
  return new;
end $$;
create trigger runs_guard_archived_item before insert on runs
  for each row execute function zeus_private.guard_archived_work_item_run();

create function zeus_private.guard_archived_work_item() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
  if old.archived_at is not null then
    raise exception using errcode='ZX003', message='work item is archived';
  end if;
  if new.archived_at is not null and (new.status <> 'completed' or not exists (
    select 1 from work_item_archives a where a.work_item_id=new.id
      and a.organization_id=new.organization_id and a.workspace_id=new.workspace_id
  )) then raise check_violation; end if;
  return new;
end $$;
create trigger work_items_guard_archived before update on work_items
  for each row execute function zeus_private.guard_archived_work_item();
revoke all on function zeus_private.guard_archived_work_item_run(),zeus_private.guard_archived_work_item() from public;

-- Chat readers receive a link, never the Workspace's goal, input or execution trace.
drop function zeus_private.im_agent_calls(uuid);
create function zeus_private.im_agent_calls(conv uuid)
returns table(run_id uuid,agent_member_id uuid,source_message_id uuid,workspace_id uuid,status text,work_item_id uuid)
language sql stable security definer set search_path=pg_catalog,public as $$
 select l.run_id,l.agent_member_id,l.source_message_id,r.workspace_id,r.status,r.work_item_id
 from im_agent_runs l join runs r on r.id=l.run_id join im_messages m on m.id=l.source_message_id
 where l.conversation_id=conv and zeus_private.im_visible(conv,m.sequence)
 order by l.created_at desc,l.run_id desc limit 50
$$;
revoke all on function zeus_private.im_agent_calls(uuid) from public;
grant execute on function zeus_private.im_agent_calls(uuid) to zeus_http;
