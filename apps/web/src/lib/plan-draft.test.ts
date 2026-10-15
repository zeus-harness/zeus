import { describe, expect, it } from 'vitest';
import { discussionSource, planDraft } from './plan-draft';

describe('discussion plan conversion', () => {
  it('uses the actual heading and retains requirements, tables and unresolved questions', () => {
    const text = '事实：你已确认两条反馈属于同一用户旅程。以下为讨论用建议，未创建工作项、未执行工具。\n\n## 登录到审批体验\n\n目标：减少跳转\n\n| 改进 | 验收 |\n| --- | --- |\n| 入口 | 首屏可见 |\n\n以上仅为建议计划；草稿需你确认后由界面独立按钮创建，对话本身不构成执行授权。\n关键澄清：由谁验收？';
    const draft = planDraft(text);
    expect(draft.title).toBe('登录到审批体验');
    expect(draft.description).toContain('| 入口 | 首屏可见 |');
    expect(draft.description).toContain('关键澄清：由谁验收？');
    expect(draft.description).not.toContain('未创建工作项');
  });
  it('does not extract headings or discard instructions inside code', () => {
    expect(planDraft('```sh\n# keep this comment\n```\n## 实际标题').title).toBe('实际标题');
    expect(planDraft('目标：不要创建工作项，只分析风险').description).toBe('目标：不要创建工作项，只分析风险');
  });
  it('does not turn arbitrary external references into links', () => {
    expect(discussionSource('workspace', { source_kind: 'studio_discussion', external_reference: 'https://evil.test' })).toBeNull();
  });
});
