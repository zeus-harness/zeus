\set ON_ERROR_STOP on

begin;

do $$
#variable_conflict use_variable
declare
  organization_id uuid := uuidv7();
  workspace_id uuid := uuidv7();
  user_id uuid := uuidv7();
  connection_id uuid := uuidv7();
  model_profile_id uuid := uuidv7();
  agent_id uuid := uuidv7();
  agent_version_id uuid := uuidv7();
  workflow_id uuid := uuidv7();
  workflow_version_id uuid := uuidv7();
  capability_id uuid := uuidv7();
  work_item_id uuid := uuidv7();
  source_session_id uuid := uuidv7();
  source_run_id uuid := uuidv7();
  source_event_id uuid;
  candidate_id uuid := uuidv7();
  experience_id uuid := uuidv7();
  parent_session_id uuid := uuidv7();
  child_session_id uuid := uuidv7();
  parent_run_id uuid := uuidv7();
  child_run_id uuid := uuidv7();
  parent_two_session_id uuid := uuidv7();
  child_two_session_id uuid := uuidv7();
  parent_two_id uuid := uuidv7();
  child_two_id uuid := uuidv7();
  parent_three_session_id uuid := uuidv7();
  child_three_session_id uuid := uuidv7();
  parent_three_id uuid := uuidv7();
  child_three_id uuid := uuidv7();
  tool_call_id uuid := uuidv7();
  canceled boolean;
  committed boolean;
  observed text;
  observed_count bigint;
begin
  insert into organizations (id, slug, name)
  values (organization_id, 'efg-' || replace(organization_id::text, '-', ''), 'EFG smoke');
  insert into workspaces (id, organization_id, slug, name)
  values (workspace_id, organization_id, 'efg-' || replace(workspace_id::text, '-', ''), 'EFG smoke');
  insert into users (id, email, display_name)
  values (user_id, replace(user_id::text, '-', '') || '@example.test', 'EFG reviewer');
  insert into organization_memberships (organization_id, user_id, role)
  values (organization_id, user_id, 'owner');
  insert into workspace_memberships (organization_id, workspace_id, user_id, role)
  values (organization_id, workspace_id, user_id, 'admin');

  insert into connections (
    id, organization_id, workspace_id, name, provider_kind, configuration
  ) values (
    connection_id, organization_id, workspace_id, 'EFG model', 'openai_compatible', '{}'::jsonb
  );
  insert into model_profiles (
    id, organization_id, workspace_id, connection_id, name, base_url, model
  ) values (
    model_profile_id, organization_id, workspace_id, connection_id,
    'EFG model', 'https://models.example.test/v1', 'test-model'
  );
  insert into agents (id, organization_id, workspace_id, name)
  values (agent_id, organization_id, workspace_id, 'EFG agent');
  insert into agent_versions (
    id, organization_id, workspace_id, agent_id, version_number, instructions
  ) values (
    agent_version_id, organization_id, workspace_id, agent_id, 1, 'Follow policy.'
  );
  insert into workflows (id, organization_id, workspace_id, name)
  values (workflow_id, organization_id, workspace_id, 'EFG workflow');
  insert into capability_definitions (
    id, organization_id, registry_key, display_name, description,
    input_schema, output_schema, idempotency_mode, risk_level, executor_key
  ) values (
    capability_id, organization_id, 'zeus.child-run', 'Child Run', 'Starts a bounded child Run',
    '{}'::jsonb, '{}'::jsonb, 'required', 'medium', 'builtin.child_run'
  );
  insert into workspace_capabilities (organization_id, workspace_id, capability_id)
  values (organization_id, workspace_id, capability_id);
  insert into workflow_versions (
    id, organization_id, workspace_id, workflow_id, version_number,
    agent_version_id, model_profile_id, input_schema, output_schema,
    capability_policy, token_budget
  ) values (
    workflow_version_id, organization_id, workspace_id, workflow_id, 1,
    agent_version_id, model_profile_id, '{}'::jsonb, '{}'::jsonb,
    jsonb_build_object('allowed', jsonb_build_array('zeus.child-run')), 1000
  );

  insert into work_items (
    id, organization_id, workspace_id, title, description, created_by
  ) values (
    work_item_id, organization_id, workspace_id, 'Investigate invoice', 'Reproduce and explain.', user_id
  );
  insert into work_item_external_references (
    organization_id, workspace_id, work_item_id, source_kind, external_reference, created_by
  ) values (
    organization_id, workspace_id, work_item_id, 'ticket', 'TICKET-42', user_id
  );
  insert into attachments (
    organization_id, workspace_id, work_item_id, file_name, content_type,
    sha256, size_bytes, data, created_by
  ) values (
    organization_id, workspace_id, work_item_id, 'evidence.txt', 'text/plain',
    decode(repeat('00', 32), 'hex'), 1, decode('78', 'hex'), user_id
  );
  begin
    update work_item_external_references set external_reference = 'TICKET-43'
    where work_item_id = work_item_id;
    raise exception 'external references accepted an update';
  exception when sqlstate '55000' then
    null;
  end;

  insert into sessions (id, organization_id, workspace_id, work_item_id, title)
  values (source_session_id, organization_id, workspace_id, work_item_id, 'Source Run');
  insert into runs (
    id, organization_id, workspace_id, workflow_version_id, work_item_id,
    session_id, status, idempotency_key, finished_at
  ) values (
    source_run_id, organization_id, workspace_id, workflow_version_id, work_item_id,
    source_session_id, 'succeeded', 'efg-source-' || source_run_id::text, now()
  );
  select event_id into source_event_id
  from zeus_private.append_run_event(
    source_run_id,
    'model.final',
    jsonb_build_object('output', jsonb_build_object('content', 'Use invoice id with billing search'))
  );
  insert into experience_candidates (
    id, organization_id, workspace_id, source_run_id, proposed_scope,
    title, content, tags, evidence, status, reviewed_by, reviewed_at
  ) values (
    candidate_id, organization_id, workspace_id, source_run_id, 'workspace',
    'Invoice lookup', 'Use the invoice id when searching billing records.', array['billing'],
    jsonb_build_array(jsonb_build_object('event_kind', 'run_event', 'event_id', source_event_id)),
    'approved', user_id, now()
  );
  insert into experience_entries (
    id, organization_id, workspace_id, candidate_id, scope, version_number,
    title, content, tags, evidence, published_by
  ) values (
    experience_id, organization_id, workspace_id, candidate_id, 'workspace', 1,
    'Invoice lookup', 'Use the invoice id when searching billing records.', array['billing'],
    jsonb_build_array(jsonb_build_object('event_kind', 'run_event', 'event_id', source_event_id)),
    user_id
  );
  select count(*) into observed_count
  from experience_entries
  where id = experience_id and search_vector @@ plainto_tsquery('simple', 'invoice billing');
  if observed_count <> 1 then
    raise exception 'published experience is not searchable';
  end if;
  insert into run_experience_injections (
    organization_id, workspace_id, run_id, experience_entry_id,
    experience_version, rank, query_sha256
  ) values (
    organization_id, workspace_id, source_run_id, experience_id,
    1, 1.0, decode(repeat('11', 32), 'hex')
  );
  insert into experience_entry_withdrawals (
    organization_id, workspace_id, experience_entry_id, reason, withdrawn_by
  ) values (
    organization_id, workspace_id, experience_id, 'Superseded by a corrected procedure.', user_id
  );
  begin
    update experience_entries set title = 'mutated' where id = experience_id;
    raise exception 'published experience accepted an update';
  exception when sqlstate '55000' then
    null;
  end;

  insert into sessions (id, organization_id, workspace_id, title)
  values
    (parent_session_id, organization_id, workspace_id, 'Parent'),
    (child_session_id, organization_id, workspace_id, 'Child');
  insert into runs (
    id, organization_id, workspace_id, workflow_version_id, session_id,
    status, idempotency_key, depth, token_budget_override, max_runtime_seconds_override
  ) values
    (parent_run_id, organization_id, workspace_id, workflow_version_id, parent_session_id,
     'waiting_child', 'efg-parent-' || parent_run_id::text, 0, 1000, 900),
    (child_run_id, organization_id, workspace_id, workflow_version_id, child_session_id,
     'queued', 'efg-child-' || child_run_id::text, 1, 200, 120);
  update runs set parent_run_id = parent_run_id, root_run_id = parent_run_id
  where id = child_run_id;
  insert into run_links (organization_id, workspace_id, parent_run_id, child_run_id, relation)
  values (organization_id, workspace_id, parent_run_id, child_run_id, 'child');
  insert into tool_calls (
    id, organization_id, workspace_id, run_id, session_id, capability_id,
    call_key, idempotency_key, fence_token, status, input, child_run_id
  ) values (
    tool_call_id, organization_id, workspace_id, parent_run_id, parent_session_id, capability_id,
    'child-1', 'efg-tool-' || tool_call_id::text, 1, 'waiting_child', '{}'::jsonb, child_run_id
  );
  update runs set status = 'succeeded', output = '{"ok":true}'::jsonb, finished_at = now()
  where id = child_run_id;
  select status into observed from runs where id = parent_run_id;
  if observed <> 'queued' then
    raise exception 'terminal child did not wake parent: %', observed;
  end if;

  insert into sessions (id, organization_id, workspace_id, title)
  values
    (parent_two_session_id, organization_id, workspace_id, 'Parent cancel'),
    (child_two_session_id, organization_id, workspace_id, 'Child cancel');
  insert into runs (
    id, organization_id, workspace_id, workflow_version_id, session_id,
    status, idempotency_key, depth, token_budget_override, max_runtime_seconds_override,
    parent_run_id, root_run_id
  ) values
    (parent_two_id, organization_id, workspace_id, workflow_version_id, parent_two_session_id,
     'waiting_child', 'efg-parent-two-' || parent_two_id::text, 0, 1000, 900, null, null),
    (child_two_id, organization_id, workspace_id, workflow_version_id, child_two_session_id,
     'queued', 'efg-child-two-' || child_two_id::text, 1, 200, 120, parent_two_id, parent_two_id);
  insert into run_links (organization_id, workspace_id, parent_run_id, child_run_id, relation)
  values (organization_id, workspace_id, parent_two_id, child_two_id, 'child');
  insert into tool_calls (
    organization_id, workspace_id, run_id, session_id, capability_id,
    call_key, idempotency_key, fence_token, status, input, child_run_id
  ) values (
    organization_id, workspace_id, parent_two_id, parent_two_session_id, capability_id,
    'child-cancel', 'efg-tool-cancel-' || parent_two_id::text, 1,
    'waiting_child', '{}'::jsonb, child_two_id
  );
  select zeus_private.request_run_cancel(parent_two_id, 'system', null, 'smoke test')
  into canceled;
  if not canceled then
    raise exception 'parent cancellation was rejected';
  end if;
  select status into observed from runs where id = child_two_id;
  if observed <> 'canceled' then
    raise exception 'parent cancellation did not reach child: %', observed;
  end if;

  insert into sessions (id, organization_id, workspace_id, title)
  values
    (parent_three_session_id, organization_id, workspace_id, 'Parent race'),
    (child_three_session_id, organization_id, workspace_id, 'Child race');
  insert into runs (
    id, organization_id, workspace_id, workflow_version_id, session_id,
    status, idempotency_key, lease_owner, lease_expires_at, fence_token,
    attempt_count, depth, token_budget_override, max_runtime_seconds_override,
    parent_run_id, root_run_id
  ) values
    (parent_three_id, organization_id, workspace_id, workflow_version_id, parent_three_session_id,
     'running', 'efg-parent-three-' || parent_three_id::text, 'node-a', now() + interval '1 minute',
     1, 1, 0, 1000, 900, null, null),
    (child_three_id, organization_id, workspace_id, workflow_version_id, child_three_session_id,
     'succeeded', 'efg-child-three-' || child_three_id::text, null, null,
     0, 0, 1, 200, 120, parent_three_id, parent_three_id);
  insert into run_attempts (
    organization_id, workspace_id, run_id, attempt_number, lease_owner, fence_token
  ) values (organization_id, workspace_id, parent_three_id, 1, 'node-a', 1);
  insert into run_links (organization_id, workspace_id, parent_run_id, child_run_id, relation)
  values (organization_id, workspace_id, parent_three_id, child_three_id, 'child');
  insert into tool_calls (
    organization_id, workspace_id, run_id, session_id, capability_id,
    call_key, idempotency_key, fence_token, status, input, child_run_id
  ) values (
    organization_id, workspace_id, parent_three_id, parent_three_session_id, capability_id,
    'child-race', 'efg-tool-race-' || parent_three_id::text, 1,
    'waiting_child', '{}'::jsonb, child_three_id
  );
  select zeus_private.finish_run(
    parent_three_id, 'node-a', 1, 'waiting_child', null, null, null
  ) into committed;
  if not committed then
    raise exception 'parent race finish was rejected';
  end if;
  select status into observed from runs where id = parent_three_id;
  if observed <> 'queued' then
    raise exception 'fast child race left parent asleep: %', observed;
  end if;
end
$$;

rollback;
