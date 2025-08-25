"use client";

import React from "react";
import { CustomButton } from "./CustomButton";

export const Header: React.FC = () => {
  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-[linear-gradient(to_bottom,_#0a0a0a,_#032e30)]/80 ">
      <div className="max-w-7xl mx-auto flex items-center justify-between px-8 py-4">
        {/* Logo - Just text, no navigation */}
        <div className="text-2xl font-bold text-white tracking-wide">
          Alpha
        </div>

        {/* Navigation + Buttons */}
        <div className="flex space-x-6 pl-20">
          <CustomButton
            title="Product"
            onClick={() => {}}
            className="text-white hover:text-[#388e94] transition-colors"
          />
          <CustomButton
            title="Company"
            onClick={() => {}}
            className="text-white hover:text-[#388e94] transition-colors"
          />
          <CustomButton
            title="Resources"
            onClick={() => {}}
            className="text-white hover:text-[#388e94] transition-colors"
          />
          <CustomButton
            title="Blog"
            onClick={() => {}}
            className="text-white hover:text-[#388e94] transition-colors"
          />
          </div>
        <div className="space-x-4">
          {/* Action Buttons */}
          <CustomButton
  title="Login"
  onClick={() => {}}
  className="px-4 py-2 text-white border border-[#032e30] bg-transparent hover:bg-[#032e30] transition-colors rounded-2xl"
/>
<CustomButton
  title="Request Demo"
  onClick={() => {}}
  className="px-4 py-2 rounded-lg text-white border border-[#032e30] bg-transparent hover:bg-[#032e30] transition-colors"
/>
        </div>
      </div>
    </header>
  );
};
