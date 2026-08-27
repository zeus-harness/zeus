CREATE INDEX session_events_reply_context_idx
    ON session_events(session_id, sequence DESC, turn_id)
    WHERE event_kind = 'assistant_message' AND turn_id IS NOT NULL;
