import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { JudgeModal } from '../judge/JudgeModal';

export const AppShell: React.FC = () => {
  const [isJudgeModalOpen, setIsJudgeModalOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-page text-navy-900 print:h-auto print:w-auto print:overflow-visible print:bg-white">
      <div className="print:hidden">
        <Header />
      </div>
      <div className="flex flex-1 overflow-hidden min-h-0 print:overflow-visible print:block">
        <Sidebar
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
          className="print:hidden"
        />
        <main className="flex-1 overflow-y-auto p-6 bg-slate-50 transition-all duration-300 print:overflow-visible print:p-0 print:bg-white print:m-0">
          <Outlet />
        </main>
      </div>
      <div className="print:hidden">
        <JudgeModal
          isOpen={isJudgeModalOpen}
          onClose={() => setIsJudgeModalOpen(false)}
        />
      </div>
    </div>
  );
};
