-- Conversation identities are separate from immutable execution configuration versions.
create table im_agent_members (
 id uuid primary key default uuidv7(), organization_id uuid not null references organizations(id),
 conversation_id uuid not null, workspace_id uuid not null references workspaces(id),
 workflow_version_id uuid not null references workflow_versions(id),
 display_name text not null, added_by uuid not null references users(id),
 joined_sequence bigint not null, joined_at timestamptz not null default clock_timestamp(), left_at timestamptz,
 foreign key(conversation_id,organization_id) references im_conversations(id,organization_id),
 unique(id,conversation_id)
);
create index im_agent_members_org_idx on im_agent_members(organization_id);
create index im_agent_members_workspace_idx on im_agent_members(workspace_id);
create index im_agent_members_version_idx on im_agent_members(workflow_version_id);
create index im_agent_members_actor_idx on im_agent_members(added_by);
create unique index im_agent_members_active_idx on im_agent_members(conversation_id,workflow_version_id) where left_at is null;

create table im_agent_runs (
 run_id uuid primary key references runs(id), organization_id uuid not null references organizations(id),
 conversation_id uuid not null, agent_member_id uuid not null,
 source_message_id uuid not null, requested_by uuid not null references users(id),
 created_at timestamptz not null default clock_timestamp(),
 foreign key(conversation_id,organization_id) references im_conversations(id,organization_id),
 foreign key(agent_member_id,conversation_id) references im_agent_members(id,conversation_id),
 foreign key(source_message_id,conversation_id) references im_messages(id,conversation_id),
 unique(agent_member_id,source_message_id)
);
create index im_agent_runs_org_idx on im_agent_runs(organization_id);
create index im_agent_runs_conversation_idx on im_agent_runs(conversation_id,created_at desc,run_id desc);
create index im_agent_runs_source_idx on im_agent_runs(source_message_id,conversation_id);
create index im_agent_runs_requester_idx on im_agent_runs(requested_by);

alter table im_messages alter column sender_id drop not null;
alter table im_messages add column sender_agent_id uuid;
alter table im_messages add column agent_run_id uuid references im_agent_runs(run_id);
alter table im_messages add constraint im_message_agent_fk foreign key(sender_agent_id,conversation_id) references im_agent_members(id,conversation_id);
alter table im_messages add constraint im_message_sender_kind check (
 (sender_id is not null and sender_agent_id is null and agent_run_id is null) or
 (sender_id is null and sender_agent_id is not null and agent_run_id is not null)
);
create index im_messages_agent_idx on im_messages(sender_agent_id,conversation_id);
create unique index im_messages_agent_run_idx on im_messages(agent_run_id) where agent_run_id is not null;

alter table im_agent_members enable row level security;
alter table im_agent_members force row level security;
alter table im_agent_runs enable row level security;
alter table im_agent_runs force row level security;
create policy im_agent_members_read on im_agent_members for select using(zeus_private.im_visible(conversation_id));
create policy im_agent_runs_read on im_agent_runs for select using (
 exists(select 1 from im_messages m where m.id=source_message_id and m.conversation_id=im_agent_runs.conversation_id)
);
grant select on im_agent_members,im_agent_runs to zeus_http;

-- A later joiner must not learn an earlier private prompt through the Agent's reply.
create function zeus_private.im_agent_result_visible(run uuid) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
 select exists(select 1 from im_agent_runs r join im_messages m on m.id=r.source_message_id
 where r.run_id=run and zeus_private.im_visible(r.conversation_id,m.sequence))
$$;
drop policy im_message_read on im_messages;
create policy im_message_read on im_messages for select using(
 zeus_private.im_visible(conversation_id,sequence) and
 (agent_run_id is null or zeus_private.im_agent_result_visible(agent_run_id))
);

create function zeus_private.im_add_agent(conv uuid, version uuid) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare c im_conversations; v workflow_versions; result uuid; actor uuid:=zeus_private.current_user_id(); agent_name text;
begin
 select * into c from im_conversations where id=conv for update;
 if not found or c.kind<>'group' or not zeus_private.im_visible(conv) or not exists(
 select 1 from im_members where conversation_id=conv and user_id=actor and role='owner' and left_at is null
 ) then raise insufficient_privilege; end if;
 select wv.* into v from workflow_versions wv join workflows w on w.id=wv.workflow_id
 join agents a on a.id=(select agent_id from agent_versions where id=wv.agent_version_id)
 where wv.id=version and wv.organization_id=c.organization_id and w.active_version_id=version and w.archived_at is null and a.archived_at is null;
 if not found or v.workspace_id is distinct from zeus_private.current_workspace_id() or not exists(
 select 1 from workspace_memberships where workspace_id=v.workspace_id and user_id=actor and status='active' and role in ('owner','builder','operator')
 ) then raise insufficient_privilege; end if;
 select id into result from im_agent_members where conversation_id=conv and workflow_version_id=version and left_at is null;
 if found then return result; end if;
 if (select count(*) from im_agent_members where conversation_id=conv and left_at is null)>=8 then raise invalid_parameter_value; end if;
 select a.name into agent_name from agents a join agent_versions av on av.agent_id=a.id where av.id=v.agent_version_id;
 insert into im_agent_members(organization_id,conversation_id,workspace_id,workflow_version_id,display_name,added_by,joined_sequence)
 values(c.organization_id,conv,v.workspace_id,version,agent_name,actor,c.last_sequence+1) returning id into result;
 insert into audit_events(organization_id,workspace_id,actor_kind,actor_id,action,target_type,target_id,metadata)
 values(c.organization_id,v.workspace_id,'user',actor,'im.agent_added','im_conversation',conv,jsonb_build_object('agent_member_id',result,'workflow_version_id',version));
 return result;
end $$;
create function zeus_private.im_remove_agent(conv uuid, member uuid) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare actor uuid:=zeus_private.current_user_id(); org uuid;
begin
 select organization_id into org from im_conversations where id=conv for update;
 if not zeus_private.im_visible(conv) or not exists(select 1 from im_members where conversation_id=conv and user_id=actor and role='owner' and left_at is null) then raise insufficient_privilege; end if;
 update im_agent_members set left_at=clock_timestamp() where id=member and conversation_id=conv and left_at is null;
 insert into audit_events(organization_id,actor_kind,actor_id,action,target_type,target_id,metadata)
 values(org,'user',actor,'im.agent_removed','im_conversation',conv,jsonb_build_object('agent_member_id',member));
end $$;

create function zeus_private.im_link_agent_run(member uuid, source uuid, run uuid) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare a im_agent_members; m im_messages; actor uuid:=zeus_private.current_user_id();
begin
 select * into a from im_agent_members where id=member and left_at is null;
 if not found then raise insufficient_privilege; end if;
 perform 1 from im_conversations where id=a.conversation_id for update;
 select * into m from im_messages where id=source and conversation_id=a.conversation_id;
 if not found or m.sender_id is null or m.sequence<a.joined_sequence or not zeus_private.im_visible(a.conversation_id,m.sequence)
 or a.workspace_id is distinct from zeus_private.current_workspace_id()
 or not exists(select 1 from workspace_memberships where workspace_id=a.workspace_id and user_id=actor and status='active' and role in ('owner','builder','operator'))
 or not exists(select 1 from runs where id=run and created_by=actor and organization_id=a.organization_id and workspace_id=a.workspace_id and workflow_version_id=a.workflow_version_id and status='queued')
 then raise insufficient_privilege; end if;
 insert into im_agent_runs(run_id,organization_id,conversation_id,agent_member_id,source_message_id,requested_by)
 values(run,a.organization_id,a.conversation_id,member,source,actor);
end $$;

-- The terminal reply commits with the durable Run transition, including after a restart.
create function zeus_private.im_deliver_agent_result() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
declare link im_agent_runs; a im_agent_members; seq bigint; body text;
begin
 if new.status not in ('succeeded','failed','canceled') or old.status=new.status then return new; end if;
 select * into link from im_agent_runs where run_id=new.id;
 if not found then return new; end if;
 perform 1 from im_conversations where id=link.conversation_id for update;
 select * into a from im_agent_members where id=link.agent_member_id and left_at is null;
 if not found or not exists(select 1 from im_members where conversation_id=link.conversation_id and user_id=link.requested_by and left_at is null)
 or not exists(select 1 from organization_memberships m join organizations o on o.id=m.organization_id join users u on u.id=m.user_id where m.organization_id=link.organization_id and m.user_id=link.requested_by and m.status='active' and o.status='active' and u.status='active')
 or not exists(select 1 from workspace_memberships where workspace_id=new.workspace_id and user_id=link.requested_by and status='active' and role in ('owner','builder','operator')) then return new; end if;
 body:=case new.status when 'succeeded' then coalesce(nullif(new.output->>'content',''),'执行已完成，请在运行详情查看结果。') when 'canceled' then '本次调用已取消。' else '本次调用失败，请由发起人在运行详情查看原因。' end;
 update im_conversations set last_sequence=last_sequence+1,updated_at=clock_timestamp() where id=link.conversation_id returning last_sequence into seq;
 insert into im_messages(organization_id,conversation_id,sequence,sender_agent_id,agent_run_id,sender_organization_id,sender_name,organization_name,content,reply_to,request_id)
 select link.organization_id,link.conversation_id,seq,a.id,new.id,link.organization_id,a.display_name,o.name,left(body,10000),link.source_message_id,new.id from organizations o where o.id=link.organization_id;
 return new;
end $$;
create trigger im_agent_result after update of status on runs for each row execute function zeus_private.im_deliver_agent_result();
revoke all on function zeus_private.im_agent_result_visible(uuid),zeus_private.im_add_agent(uuid,uuid),zeus_private.im_remove_agent(uuid,uuid),zeus_private.im_link_agent_run(uuid,uuid,uuid),zeus_private.im_deliver_agent_result() from public;
grant execute on function zeus_private.im_agent_result_visible(uuid),zeus_private.im_add_agent(uuid,uuid),zeus_private.im_remove_agent(uuid,uuid),zeus_private.im_link_agent_run(uuid,uuid,uuid) to zeus_http;
create function zeus_private.im_agent_calls(conv uuid) returns table(run_id uuid,agent_member_id uuid,source_message_id uuid,workspace_id uuid,status text)
language sql stable security definer set search_path=pg_catalog,public as $$
 select l.run_id,l.agent_member_id,l.source_message_id,r.workspace_id,r.status from im_agent_runs l
 join runs r on r.id=l.run_id join im_messages m on m.id=l.source_message_id
 where l.conversation_id=conv and zeus_private.im_visible(conv,m.sequence)
 order by l.created_at desc,l.run_id desc limit 50
$$;
revoke all on function zeus_private.im_agent_calls(uuid) from public;
grant execute on function zeus_private.im_agent_calls(uuid) to zeus_http;
create function zeus_private.im_lock_conversation(conv uuid) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
 perform 1 from im_conversations where id=conv for update;
 if not found or not zeus_private.im_visible(conv) then raise insufficient_privilege; end if;
 return conv;
end $$;
revoke all on function zeus_private.im_lock_conversation(uuid) from public;
grant execute on function zeus_private.im_lock_conversation(uuid) to zeus_http;
