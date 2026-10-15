create table im_conversations (
 id uuid primary key default uuidv7(), organization_id uuid not null references organizations(id),
 kind text not null check(kind in ('direct','group')), title text not null check(length(title) between 1 and 160),
 created_by uuid not null references users(id), request_id uuid not null, creation_input jsonb not null, direct_key text, last_sequence bigint not null default 0,
 created_at timestamptz not null default clock_timestamp(), updated_at timestamptz not null default clock_timestamp(),
 unique(id,organization_id), unique(organization_id,direct_key), unique(organization_id,created_by,request_id)
);
create index im_conversations_org_idx on im_conversations(organization_id,created_at desc,id desc);
create index im_conversations_creator_idx on im_conversations(created_by);
create table im_members (
 conversation_id uuid not null, organization_id uuid not null references organizations(id), user_id uuid not null references users(id),
 role text not null check(role in ('owner','member')), joined_sequence bigint not null default 1,
 last_read_sequence bigint not null default 0, joined_at timestamptz not null default clock_timestamp(), left_at timestamptz,
 primary key(conversation_id,user_id), foreign key(conversation_id,organization_id) references im_conversations(id,organization_id)
);
create index im_members_org_idx on im_members(organization_id);
create index im_members_user_idx on im_members(user_id,organization_id,conversation_id) where left_at is null;
create table im_messages (
 id uuid primary key default uuidv7(), organization_id uuid not null references organizations(id), conversation_id uuid not null,
 sequence bigint not null, sender_id uuid not null references users(id), sender_organization_id uuid not null references organizations(id),
 sender_name text not null, organization_name text not null, content text not null check(length(content) between 1 and 10000),
 reply_to uuid, mentions uuid[] not null default '{}', request_id uuid not null,
 created_at timestamptz not null default clock_timestamp(),
 foreign key(conversation_id,organization_id) references im_conversations(id,organization_id),
 unique(conversation_id,sequence), unique(conversation_id,sender_id,request_id), unique(id,conversation_id),
 foreign key(reply_to,conversation_id) references im_messages(id,conversation_id),
 check(sender_organization_id=organization_id)
);
create index im_messages_org_idx on im_messages(organization_id);
create index im_messages_history_idx on im_messages(conversation_id,created_at desc,id desc);
create index im_messages_sender_idx on im_messages(sender_id);
create index im_messages_sender_org_idx on im_messages(sender_organization_id);
create index im_messages_reply_idx on im_messages(reply_to,conversation_id);

create function zeus_private.im_active_member(org uuid, actor uuid) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
 select coalesce(org=zeus_private.current_organization_id(),false) and coalesce(actor=zeus_private.current_user_id(),false)
 and coalesce(current_setting('zeus.tenant_access_grant_id',true),'')=''
 and exists(select 1 from organization_memberships m join users u on u.id=m.user_id join organizations o on o.id=m.organization_id
 where m.organization_id=org and m.user_id=actor and m.status='active' and u.status='active' and o.status='active')
$$;
create function zeus_private.im_visible(conv uuid, minimum_sequence bigint default null) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
 select exists(select 1 from im_members m where m.conversation_id=conv and m.user_id=zeus_private.current_user_id()
 and m.left_at is null and zeus_private.im_active_member(m.organization_id,m.user_id)
 and (minimum_sequence is null or minimum_sequence>=m.joined_sequence))
$$;
alter table im_conversations enable row level security;
alter table im_conversations force row level security;
alter table im_members enable row level security;
alter table im_members force row level security;
alter table im_messages enable row level security;
alter table im_messages force row level security;
create policy im_conversation_read on im_conversations for select using(zeus_private.im_visible(id));
create policy im_members_read on im_members for select using(zeus_private.im_visible(conversation_id));
create policy im_message_read on im_messages for select using(zeus_private.im_visible(conversation_id,sequence));
grant select on im_conversations,im_members,im_messages to zeus_http;

create function zeus_private.im_create(org uuid, conversation_kind text, conversation_title text, participants uuid[], request_id uuid) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare actor uuid:=zeus_private.current_user_id(); result uuid; member_id uuid; pair text;
begin
 if not zeus_private.im_active_member(org,actor) then raise insufficient_privilege; end if;
 if conversation_kind not in ('direct','group') or length(trim(conversation_title)) not between 1 and 160
 or cardinality(participants) not between 1 and 49 or actor=any(participants)
 or (select count(distinct p) from unnest(participants) p)<>cardinality(participants)
 or (conversation_kind='direct' and cardinality(participants)<>1) then raise invalid_parameter_value; end if;
 foreach member_id in array participants loop
  if not exists(select 1 from organization_memberships m join users u on u.id=m.user_id where m.organization_id=org and m.user_id=member_id and m.status='active' and u.status='active') then raise insufficient_privilege; end if;
 end loop;
 if conversation_kind='direct' then pair:=least(actor::text,participants[1]::text)||':'||greatest(actor::text,participants[1]::text); end if;
 -- An advisory transaction lock serializes duplicate direct conversations and retries.
 perform pg_advisory_xact_lock(hashtextextended(org::text||coalesce(pair,request_id::text),0));
 select c.id into result from im_conversations c where c.organization_id=org and ((pair is not null and c.direct_key=pair) or (c.request_id=im_create.request_id and c.created_by=actor));
 if result is not null then
  if not exists(select 1 from im_conversations c where c.id=result and c.kind=conversation_kind)
    or not zeus_private.im_visible(result) then raise insufficient_privilege; end if;
  if pair is null and not exists(select 1 from im_conversations c where c.id=result and c.creation_input=jsonb_build_object('title',trim(conversation_title),'participants',participants)) then raise invalid_parameter_value; end if;
  return result;
 end if;
 insert into im_conversations(organization_id,kind,title,created_by,direct_key,request_id,creation_input) values(org,conversation_kind,trim(conversation_title),actor,pair,request_id,jsonb_build_object('title',trim(conversation_title),'participants',participants)) returning id into result;
 insert into im_members(conversation_id,organization_id,user_id,role) values(result,org,actor,'owner');
 foreach member_id in array participants loop
  insert into im_members(conversation_id,organization_id,user_id,role) values(result,org,member_id,'member');
 end loop;
 return result;
end $$;
create function zeus_private.im_change(conv uuid, operation text, value text, target uuid) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare actor uuid:=zeus_private.current_user_id(); c im_conversations;
begin
 select * into c from im_conversations where id=conv for update;
 if not found or not zeus_private.im_visible(conv) then raise insufficient_privilege; end if;
 if operation='read' then
  if value !~ '^[0-9]{1,18}$' then raise invalid_parameter_value; end if;
  update im_members set last_read_sequence=greatest(last_read_sequence,least(value::bigint,c.last_sequence)) where conversation_id=conv and user_id=actor;
  return;
 end if;
 if c.kind<>'group' then raise invalid_parameter_value; end if;
 if operation='leave' then
  if exists(select 1 from im_members where conversation_id=conv and user_id=actor and role='owner') then
   select user_id into target from im_members where conversation_id=conv and user_id<>actor and left_at is null order by joined_at,user_id limit 1;
   if target is not null then update im_members set role='owner' where conversation_id=conv and user_id=target; end if;
  end if;
  update im_members set left_at=clock_timestamp(),role='member' where conversation_id=conv and user_id=actor;
 elsif exists(select 1 from im_members where conversation_id=conv and user_id=actor and role='owner') then
  if operation='rename' and length(trim(value)) between 1 and 160 then
   update im_conversations set title=trim(value),updated_at=clock_timestamp() where id=conv;
  elsif operation='add' then
   if (select count(*) from im_members where conversation_id=conv and left_at is null)>=50 then raise invalid_parameter_value; end if;
   if not exists(select 1 from organization_memberships m join users u on u.id=m.user_id where m.organization_id=c.organization_id and m.user_id=target and m.status='active' and u.status='active') then raise insufficient_privilege; end if;
   insert into im_members(conversation_id,organization_id,user_id,role,joined_sequence,last_read_sequence)
    values(conv,c.organization_id,target,'member',c.last_sequence+1,c.last_sequence)
    on conflict(conversation_id,user_id) do update set left_at=null,joined_at=clock_timestamp(),joined_sequence=c.last_sequence+1,last_read_sequence=c.last_sequence
    where im_members.left_at is not null;
  else raise invalid_parameter_value; end if;
 else raise insufficient_privilege; end if;
 insert into audit_events(organization_id,actor_kind,actor_id,action,target_type,target_id,metadata)
 values(c.organization_id,'user',actor,'im.'||operation,'im_conversation',conv,jsonb_build_object('member_id',target));
end $$;
create function zeus_private.im_send(conv uuid, request_id uuid, body text, reply uuid, mentioned uuid[]) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare actor uuid:=zeus_private.current_user_id(); c im_conversations; prior im_messages; result uuid; seq bigint;
begin
 select * into c from im_conversations where id=conv for update;
 if not found or not zeus_private.im_visible(conv) then raise insufficient_privilege; end if;
 select * into prior from im_messages m where m.conversation_id=conv and m.sender_id=actor and m.request_id=im_send.request_id;
 if found then
  if prior.content<>trim(body) or prior.reply_to is distinct from reply or prior.mentions<>mentioned then raise invalid_parameter_value; end if;
  return prior.id;
 end if;
 if length(trim(body)) not between 1 and 10000 or cardinality(mentioned)>50 then raise invalid_parameter_value; end if;
 if reply is not null and not exists(select 1 from im_messages where id=reply and conversation_id=conv and zeus_private.im_visible(conv,sequence)) then raise insufficient_privilege; end if;
 if exists(select 1 from unnest(mentioned) u where not exists(select 1 from im_members m where m.conversation_id=conv and m.user_id=u and m.left_at is null)) then raise insufficient_privilege; end if;
 update im_conversations set last_sequence=last_sequence+1,updated_at=clock_timestamp() where id=conv returning last_sequence into seq;
 insert into im_messages(organization_id,conversation_id,sequence,sender_id,sender_organization_id,sender_name,organization_name,content,reply_to,mentions,request_id)
 select c.organization_id,conv,seq,actor,c.organization_id,u.display_name,o.name,trim(body),reply,mentioned,request_id from users u cross join organizations o where u.id=actor and o.id=c.organization_id returning id into result;
 return result;
end $$;
revoke all on function zeus_private.im_active_member(uuid,uuid),zeus_private.im_visible(uuid,bigint),zeus_private.im_create(uuid,text,text,uuid[],uuid),zeus_private.im_change(uuid,text,text,uuid),zeus_private.im_send(uuid,uuid,text,uuid,uuid[]) from public;
grant execute on function zeus_private.im_active_member(uuid,uuid),zeus_private.im_visible(uuid,bigint),zeus_private.im_create(uuid,text,text,uuid[],uuid),zeus_private.im_change(uuid,text,text,uuid),zeus_private.im_send(uuid,uuid,text,uuid,uuid[]) to zeus_http;
create function zeus_private.im_people(org uuid, search text, after_id uuid) returns table(id uuid, display_name text)
language sql stable security definer set search_path=pg_catalog,public as $$
 select u.id,u.display_name from organization_memberships m join users u on u.id=m.user_id
 where zeus_private.im_active_member(org,zeus_private.current_user_id()) and m.organization_id=org
 and m.status='active' and u.status='active' and (after_id is null or u.id>after_id)
 and (search='' or starts_with(lower(u.display_name),lower(search))) order by u.id limit 51
$$;
create function zeus_private.im_participants(conv uuid) returns table(id uuid, display_name text, organization_id uuid, role text)
language sql stable security definer set search_path=pg_catalog,public as $$
 select u.id,u.display_name,m.organization_id,m.role from im_members m join users u on u.id=m.user_id
 where m.conversation_id=conv and m.left_at is null and zeus_private.im_visible(conv) order by m.joined_at,u.id
$$;
revoke all on function zeus_private.im_people(uuid,text,uuid),zeus_private.im_participants(uuid) from public;
grant execute on function zeus_private.im_people(uuid,text,uuid),zeus_private.im_participants(uuid) to zeus_http;
