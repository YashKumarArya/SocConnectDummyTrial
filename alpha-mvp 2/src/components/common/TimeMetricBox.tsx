interface CurvedBoxProps {
  title: string;
  value: string;
  className?: string;
  titleClassName?: string;
  valueClassName?: string;
  link?: string; // optional link
}

export const TimeMetricBox=({title,value,className,titleClassName,valueClassName,link,}:CurvedBoxProps)=>{
  const content = (
    <div
      className={`flex flex-col items-center justify-center rounded-2xl shadow-md p-4 ${className}`}
    >
      <h3 className={`text-center font-semibold ${titleClassName}`}>
        {title}
      </h3>
      <p className={`text-center mt-2 ${valueClassName}`}>{value}</p>
    </div>
  );

  return link ? (
    <a href={link} className="block">
      {content}
    </a>
  ) : (
    content
  );
};

