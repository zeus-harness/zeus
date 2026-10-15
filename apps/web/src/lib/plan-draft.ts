/** Presentation-only extraction. The user reviews the result before any resource is created. */
export function planDraft(text: string): { title: string; description: string } {
  let fenced = false;
  const kept: string[] = [];
  let heading = '';
  for (const line of text.trim().split('\n')) {
    if (/^\s*(```|~~~)/u.test(line)) fenced = !fenced;
    if (!fenced) {
      const match = /^#{1,6}\s+(.+?)(?:\s+#+)?$/u.exec(line);
      if (!heading && match) heading = match[1];
      // Remove only known conversational wrappers, never requirements or code.
      if (/^(事实：.*以下为讨论用建议，未创建工作项、未执行工具。|以上仅为建议计划；草稿需你确认后由界面独立按钮创建，对话本身不构成执行授权。)\s*$/u.test(line)) continue;
    }
    kept.push(line);
  }
  const description = kept.join('\n').trim() || text.trim();
  const title = heading || description.split(/[\n。！？!?]/u)[0];
  const points = [...title];
  return { title: points.slice(0, 48).join('') + (points.length > 48 ? '…' : ''), description };
}

export function discussionSource(workspace: string, item: { source_kind?: string | null; external_reference?: string | null }): string | null {
  return item.source_kind === 'studio_discussion' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(item.external_reference ?? '')
    ? `/${workspace}/studio?discuss=1&run=${item.external_reference}` : null;
}
