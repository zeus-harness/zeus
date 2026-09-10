do $$
begin
  if exists (select 1 from pg_roles where rolname = 'zeus_runtime') then
    execute 'grant insert on table public.audit_events to zeus_runtime';
    execute 'grant select on table public.run_usage to zeus_runtime';
  end if;
end
$$;
