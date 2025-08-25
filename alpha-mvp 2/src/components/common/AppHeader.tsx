import { Bell, Search } from "lucide-react";

interface AppHeaderProps {
  modelOnline?: boolean;           // true = green, false = red
  notificationsCount?: number;     // optional badge
  onExport?: () => void;
}


export default function AppHeader({
  modelOnline = true,
  notificationsCount = 0,
}: AppHeaderProps) {
  return (
    <header
      className="sticky top-0 z-30 h-14  bg-[#05090d] "
    >
      <div className="h-full px-4 border-b border-white/10 flex items-center justify-between">
        {/* Left area (optional page title placeholder) */}
        <div className="text-sm font-medium text-gray-700">
          <div className="relative w-full">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
                <Search className="w-4 h-4" />
              </span>
              <input
                value={''}
                onChange={()=>{}}
                placeholder="Search alerts…"
                className="w-[32vw] pl-9 pr-3 h-9 text-sm rounded-md bg-white/5 text-gray-200 placeholder:text-gray-400 border border-white/10 focus:outline-none focus:ring-2 focus:ring-white/20"
              />
            </div>
        </div>

        {/* Right cluster */}
        <div className="flex items-center gap-7">
          {/* AI model status */}
          <div className="flex items-center gap-2 text-sm">
            <span
              className={`inline-block w-2 h-2 rounded-full ${
                modelOnline ? "bg-green-500" : "bg-red-500"
              }`}
              aria-hidden="true"
            />
            <span className={`font-roboto font-medium ${modelOnline ? "text-green-600" : "text-red-600"}`}>
              AI Model {modelOnline ? "Online" : "Offline"}
            </span>
          </div>

          {/* Notifications */}
          <button
            aria-label="Notifications"
            className="relative inline-flex items-center justify-center w-10 h-10 rounded-md text-gray-600"
          >
            <Bell className="w-4 h-4" />
            {notificationsCount > 0 && (
              <span className="absolute -top-1 -right-1 min-w-[1.1rem] px-1 h-5 rounded-full bg-red-500 text-white text-[10px] leading-5 text-center">
                {notificationsCount > 99 ? "99+" : notificationsCount}
              </span>
            )}
          </button>


          {/* User*/}
          <div className="flex flex-col justify-end items-end">
            <span className="text-white font-bebas text-base">
            Khushi Pandey
          </span>
          <span className="text-[12px] font-roboto text-white/70">
            Junior Analyst
          </span>
          </div>
          
        </div>
      </div>
    </header>
  );
}
