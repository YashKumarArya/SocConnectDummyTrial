
interface CustomButtonProps {
  title: string;
  onClick?: () => void;
  type?: "button" | "submit" | "reset";
  className?: string; 
}

export const CustomButton = ({
  title,
  onClick,
  type = "button",
  className = "",
}: CustomButtonProps) => {
  return (
    <button
      type={type}
      onClick={onClick}
      className={`${className} px-4 py-2 transition-colors duration-200 `}
    >
      {title}
    </button>
  );
};
