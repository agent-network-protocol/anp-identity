import React from 'react';

export function IdentityCard({ identity, handle, origin }: { identity: string; handle?: string | null; origin: string }) {
  return <div className="card">
    <span className="sub">本次演示身份</span>
    <p><span className="sub">Handle</span><br /><code>{handle ?? '未提供'}</code></p>
    <p><span className="sub">DID</span><br /><code>{identity}</code></p>
    <span className="sub">POST {origin}/hello</span>
  </div>;
}
