import { Outlet } from "react-router-dom";
import Sidebar from "@/components/navigation/Sidebar";
import AppHeader from "@/components/common/AppHeader";

export default function AppLayout() {
  return (
    <div className="flex min-h-screen w-full bg-gray-50">
      <Sidebar />
      {/* Main column must allow children to shrink, and contain overflow */}
      <main className="pl-16 flex flex-col flex-1 min-h-0 overflow-hidden">
        {/* Header shouldn't flex-grow; keep it fixed-height in the flow */}
        <div className="shrink-0">
          <AppHeader
            modelOnline={true}
            notificationsCount={3}
            onExport={() => {
              // hook export handler here
            }}
          />
        </div>

        {/* This is the true viewport area under the header */}
        <div className="flex-1 min-h-0 overflow-hidden p-2  bg-[linear-gradient(to_bottom,_#0a0a0a,_#032e30)]">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
