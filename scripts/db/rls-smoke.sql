\set ON_ERROR_STOP on

begin;

insert into organizations (id, slug, name) values
  ('01911111-1111-7111-8111-111111111111', 'tenant-one', 'Tenant One'),
  ('01922222-2222-7222-8222-222222222222', 'tenant-two', 'Tenant Two');

insert into workspaces (id, organization_id, slug, name) values
  ('01911111-1111-7111-8111-111111111112', '01911111-1111-7111-8111-111111111111', 'workspace-one', 'Workspace One'),
  ('01922222-2222-7222-8222-222222222223', '01922222-2222-7222-8222-222222222222', 'workspace-two', 'Workspace Two');

set local role zeus_http;
select set_config('zeus.organization_id', '01911111-1111-7111-8111-111111111111', true);
select set_config('zeus.workspace_id', '01911111-1111-7111-8111-111111111112', true);

do $$
begin
  if (select count(*) from organizations) <> 1 then
    raise exception 'organization RLS failed';
  end if;
  if (select count(*) from workspaces) <> 1 then
    raise exception 'workspace RLS failed';
  end if;
  if exists (
    select 1 from workspaces where id = '01922222-2222-7222-8222-222222222223'
  ) then
    raise exception 'cross-tenant workspace was visible';
  end if;
end
$$;

reset role;
rollback;
