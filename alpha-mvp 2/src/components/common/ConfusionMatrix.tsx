
interface ConfusionMatrixProps {
  truePositive?: number;
  falseNegative?: number;
  falsePositive?: number;
  trueNegative?: number;
}

export const ConfusionMatrix = ({
  truePositive,
  falseNegative,
  falsePositive,
  trueNegative,
}: ConfusionMatrixProps) => {
  const items = [
    { label: "True Positive", value: truePositive },
    { label: "False Negative", value: falseNegative },
    { label: "False Positive", value: falsePositive },
    { label: "True Negative", value: trueNegative },
  ];

  return (
    <div className=" flex items-center justify-center">
      <div className="grid grid-cols-2 gap-2 py-1  w-full max-w-md">
        {items.map((item, index) => (
          <div
            key={index}
            className="flex flex-col items-center justify-center bg-white/10 p-1 rounded-lg"
          >
            <span className="text-lg font-smooch font-bold">{item.value}</span>
            <span className="text-[0.6rem] font-roboto font-bold text-gray-300">{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
