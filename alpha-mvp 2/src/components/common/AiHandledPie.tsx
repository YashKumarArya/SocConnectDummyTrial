"use client";

import React from "react";
import {
  Chart as ChartJS,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  type ChartOptions,
} from "chart.js";
import { Pie } from "react-chartjs-2";

ChartJS.register(Title, Tooltip, Legend, ArcElement);

interface ChartProps {
  labels: string[];
  data: number[];
  title?: string; // not shown (box already has a title)
  backgroundColors?: string[];
  borderColors?: string[];
  className?: string;
}

const AiHandledPie: React.FC<ChartProps> = ({
  labels,
  data,
  title = "AI Handled vs Escalated",
  backgroundColors = [
    "rgba(75, 192, 192, 0.6)",
    "rgba(255, 99, 132, 0.6)",
    "rgba(255, 206, 86, 0.6)",
    "rgba(54, 162, 235, 0.6)",
  ],
  borderColors = [
    "rgba(75, 192, 192, 1)",
    "rgba(255, 99, 132, 1)",
    "rgba(255, 206, 86, 1)",
    "rgba(54, 162, 235, 1)",
  ],
  className = "",
}) => {
  // ---- Internal layout controls (tweak here to match your 3-box row) ----
  const WRAPPER_HEIGHT = 100;     // keeps the box height stable like ConfusionMatrix
  const CANVAS_WIDTH = 360;       // enough width for legend (left) + pie (right)
  const RADIUS = "100%";           // pie size inside the canvas
  const MAINTAIN_ASPECT_RATIO = false;
  const PADDING = 8;
  // ----------------------------------------------------------------------

  const chartData = {
    labels,
    datasets: [
      {
        label: title,
        data,
        backgroundColor: backgroundColors,
        borderColor: borderColors,
        borderWidth: 1,
        radius: RADIUS as any,
        hoverOffset: 15,
      },
    ],
  };

  const options: ChartOptions<"pie"> = {
    responsive: true,
    maintainAspectRatio: MAINTAIN_ASPECT_RATIO,
    devicePixelRatio: 2,
    plugins: {
      legend: {
        display: true,
        position: "left",
        align: "center",
        labels: {
          usePointStyle: true,
          boxWidth: 10,
          boxHeight: 10,
          padding: 12,
        },
      },
      title: {
        display: false, // you already show the title via CustomTitleBox
        text: title,
      },
      tooltip: { enabled: true },
    },
    layout: { padding: PADDING },
  };

  return (
    <div
      className={`w-full h-full flex items-center justify-center ${className}`}
      style={{ minHeight: WRAPPER_HEIGHT }}
    >
      {/* Center the canvas (which contains legend on the left + pie on the right) */}
      <div
        className="relative mx-auto"
        style={{ width: CANVAS_WIDTH, height: WRAPPER_HEIGHT }}
      >
        <Pie data={chartData} options={options} />
      </div>
    </div>
  );
};

export default AiHandledPie;
