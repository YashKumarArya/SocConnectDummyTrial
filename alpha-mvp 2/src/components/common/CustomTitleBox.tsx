import React from "react";

interface CurvedContainerProps {
  title: string;
  className?: string;
  titleClassName?: string;
  children: React.ReactNode;
}

export const CustomTitleBox=({title,className,titleClassName,children}:CurvedContainerProps)=>{
  return (
    <div
      className={`rounded-2xl shadow-md p-4 bg-[hsl(0,0%,8%)]/80 text-slate-200  ${className}`}
    >
      <h3 className={`text-left font-semibold mb-1 text-slate-300 text-sm font-rubik ${titleClassName}`}>
        {title}
      </h3>
      <div>{children}</div>
    </div>
  );
};

