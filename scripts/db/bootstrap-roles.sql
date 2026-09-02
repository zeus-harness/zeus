\set ON_ERROR_STOP on

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'zeus_http') then
    create role zeus_http nologin nosuperuser nocreatedb nocreaterole noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'zeus_runtime') then
    create role zeus_runtime nologin nosuperuser nocreatedb nocreaterole noinherit bypassrls;
  end if;
end
$$;

revoke all on schema public from public;
grant usage on schema public to zeus_http, zeus_runtime;

do $$
begin
  if exists (select 1 from pg_namespace where nspname = 'zeus_private') then
    execute 'grant usage on schema zeus_private to zeus_http, zeus_runtime';
  end if;
end
$$;

alter default privileges in schema public grant select, insert, update on tables to zeus_http;
alter default privileges in schema public grant usage, select on sequences to zeus_http;
