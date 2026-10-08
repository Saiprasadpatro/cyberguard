import React, { useEffect, useState } from 'react';
import AppShell from '../components/AppShell';
import { PageHeader } from '../components/ui';
import RiskBadge from '../components/RiskBadge';
import api from '../api/api';

export default function Admin() {
  const [tab, setTab] = useState('threats');
  const [users, setUsers] = useState([]);
  const [threats, setThreats] = useState([]);
  const [error, setError] = useState('');

  const loadUsers = () => api.get('/admin/users').then((r) => setUsers(r.data.users)).catch((e) => setError(e.response?.data?.error || 'Failed'));
  const loadThreats = () => api.get('/admin/threats').then((r) => setThreats(r.data.threats)).catch((e) => setError(e.response?.data?.error || 'Failed'));

  useEffect(() => { loadUsers(); loadThreats(); }, []);

  const toggleActive = async (u) => {
    await api.patch(`/admin/users/${u.id}/active`, { isActive: !u.isActive });
    loadUsers();
  };

  const changeRole = async (u, role) => {
    await api.patch(`/admin/users/${u.id}/role`, { role });
    loadUsers();
  };

  const updateThreatStatus = async (t, status) => {
    await api.patch(`/admin/threats/${t.id}/status`, { status });
    loadThreats();
  };

  return (
    <AppShell>
      <PageHeader eyebrow="Workspace · Administration" title="Admin console" art="admin"
        subtitle="Manage users and roles, and move threats through their lifecycle: open, investigating, mitigated or false positive." />
      {error && <div className="cg-panel cg-error" style={{ marginTop: 0 }}>{error}</div>}

      <div className="cg-tabs">
        <button className={`cg-tab${tab === 'threats' ? ' active' : ''}`} onClick={() => setTab('threats')}>Threats</button>
        <button className={`cg-tab${tab === 'users' ? ' active' : ''}`} onClick={() => setTab('users')}>Users</button>
      </div>

      {tab === 'threats' && (
        <div className="cg-panel">
          <div className="cg-table-wrap"><table className="cg-table">
            <thead>
              <tr><th>Category</th><th>Risk</th><th>Status</th><th>Detected</th><th>Recommended action</th><th>Update</th></tr>
            </thead>
            <tbody>
              {threats.map((t) => (
                <tr key={t.id}>
                  <td className="cg-mono">{t.category}</td>
                  <td><RiskBadge level={t.riskLevel} /></td>
                  <td>{t.status}</td>
                  <td className="cg-mono" style={{ fontSize: 12 }}>{new Date(t.createdAt).toLocaleString()}</td>
                  <td style={{ maxWidth: 260 }}>{t.recommendedAction}</td>
                  <td>
                    <select className="form-select form-select-sm" value={t.status} onChange={(e) => updateThreatStatus(t, e.target.value)}>
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="mitigated">Mitigated</option>
                      <option value="false_positive">False positive</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}

      {tab === 'users' && (
        <div className="cg-panel">
          <div className="cg-table-wrap"><table className="cg-table">
            <thead>
              <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th></th></tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.fullName}</td>
                  <td className="cg-mono" style={{ fontSize: 12.5 }}>{u.email}</td>
                  <td>
                    <select className="form-select form-select-sm" value={u.role} onChange={(e) => changeRole(u, e.target.value)}>
                      <option value="user">user</option>
                      <option value="soc_analyst">soc_analyst</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>{u.isActive ? 'Active' : 'Deactivated'}</td>
                  <td className="cg-mono" style={{ fontSize: 12 }}>{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '—'}</td>
                  <td>
                    <button className="cg-btn-outline" onClick={() => toggleActive(u)}>
                      {u.isActive ? 'Deactivate' : 'Activate'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}
    </AppShell>
  );
}
