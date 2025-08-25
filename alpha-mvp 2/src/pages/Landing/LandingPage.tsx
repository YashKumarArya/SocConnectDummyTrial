// LandingPage.tsx
import React from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Mail,
  Laptop,
  Server,
  Database,
  Globe,
  AlertTriangle,
  BarChart3,
  Workflow,
  Users,
  FileText,
} from "lucide-react";
import { CustomButton } from "@/components/common/CustomButton";



export const LandingPage = () => {
  const navigate = useNavigate();



  const attackSteps = [
    { id: "phishing", label: "Phishing Email", icon: Mail },
    { id: "endpoint", label: "Endpoint Compromise", icon: Laptop },
    { id: "lateral", label: "Lateral Movement", icon: Server },
    { id: "data", label: "Data Exfiltration", icon: Database },
    { id: "external", label: "External C&C", icon: Globe },
  ];

  const featureSteps: Array<{
    id: string;
    title: string;
    description: string;
    icon: React.ComponentType<any>;
  }> = [
    {
      id: "unified-threat",
      title: "Unified Threat Overview",
      description:
        "Get complete visibility into threat landscape — by severity, source, and impact across all your security tools and endpoints.",
      icon: Shield,
    },
    {
      id: "alert-triage",
      title: "AI-Powered Alert Triage",
      description:
        "Automatically classify and prioritize alerts using advanced AI scoring for true positives, false positives, and escalation paths.",
      icon: AlertTriangle,
    },
    {
      id: "tactical-analytics",
      title: "Real-Time Tactical Analytics",
      description:
        "Track attacker behavior patterns, analyze file execution paths, and correlate process execution across your infrastructure.",
      icon: BarChart3,
    },
    {
      id: "automated-playbooks",
      title: "Automated Response Playbooks",
      description:
        "Instantly isolate compromised devices, block malicious hashes, and notify security teams with predefined automated playbooks.",
      icon: Workflow,
    },
    {
      id: "user-entity",
      title: "User Entity Behavior Analytics",
      description:
        "Correlate security alerts back to specific users, domains, and asset movement patterns for comprehensive threat context.",
      icon: Users,
    },
    {
      id: "compliance",
      title: "Compliance & Audit Reporting",
      description:
        "Generate audit-ready compliance reports automatically mapped to ISO 27001, NIST Framework, SOC 2, and industry standards.",
      icon: FileText,
    },
  ];

  return (
    <main>
      {/* ===== HERO SECTION (has its own gradient) ===== */}
      <section className="bg-[linear-gradient(to_bottom,_#0a0a0a,_#032e30)]">
        {/* Add top padding so gradient continues behind the sticky Header */}
        <div className="pt-2 pb-16 px-4">
          <div className="container mx-auto">
            <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 items-center max-w-7xl mx-auto">
              {/* Left: Content */}
              <div className="space-y-6 lg:pr-8">
                <div>
                  <h1 className="text-4xl lg:text-5xl font-bold leading-tight mb-3">
                    <span className="bg-clip-text font-roboto text-transparent bg-gradient-to-r from-white to-gray-300">
                      Agentic AI SOC Platform
                    </span>
                  </h1>

                  <p className="text-lg   text-gray-300 mb-6 leading-relaxed">
                    Advanced AI agents detect, analyze, and neutralize cyber threats in real-time with zero human intervention.
                  </p>
                </div>

                {/* Feature bullets */}
                <div className="space-y-3">
                  {[
                    "AI-powered threat correlation across all vectors",
                    "Sub-second response time with automated remediation",
                    "Deep behavioral analysis and anomaly detection",
                    "Predictive threat intelligence and risk scoring",
                  ].map((feature, i) => (
                    <div key={i} className="flex items-center text-sm text-gray-200">
                      <span className="mr-3">-</span>
                      <span>{feature}</span>
                    </div>
                  ))}
                </div>

                {/* CTA */}
                <div className="flex flex-col sm:flex-row gap-3 pt-4">
                 <CustomButton
                   title="Access the Dashboard"
                   onClick={() => navigate('/app/dashboard')}
                   className="px-4 py-2 rounded-lg text-white border border-[#032e30] bg-transparent hover:bg-[#032e30] transition-colors"
                 />
                </div>

                {/* Quick stats (static) */}
                <div className="grid grid-cols-3 gap-4 pt-6">
                  <div className="text-center">
                    <div className="text-xl font-bold text-[hsl(210,40%,75%)]">99.7%</div>
                    <div className="text-xs text-gray-400">Threat Detection</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold text-[hsl(210,40%,75%)]">0.3s</div>
                    <div className="text-xs text-gray-400">Response Time</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold text-green-400">Zero</div>
                    <div className="text-xs text-gray-400">False Positives</div>
                  </div>
                </div>
              </div>

              {/* Right: Static “attack map” with icons + placeholder image */}
              <div className="relative">
                <div className="rounded-2xl p-6 border border-white/10 relative overflow-hidden">
                  {/* Replace with your real image asset */}
                  <img
                    src="/images/attack-path-placeholder.jpg"
                    alt="Attack Path Overview"
                    className="w-full h-96 object-cover rounded-xl"
                  />

                  Legend row with Lucide icons
                  <div className="mt-4 grid grid-cols-5 gap-2 text-center">
                    {attackSteps.map((step) => {
                      const Icon = step.icon;
                      return (
                        <div key={step.id} className="flex flex-col items-center">
                          <div className="w-8 h-8 rounded-full border border-white/20 flex items-center justify-center">
                            <Icon className="w-4 h-4 text-gray-300" />
                          </div>
                          <div className="text-xs text-gray-300 mt-2">{step.label}</div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Center badge */}
                  <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
                    <div className="w-16 h-16 rounded-full flex items-center justify-center border border-white/20">
                      <Shield className="w-8 h-8 text-white" />
                    </div>
                  </div>

                  {/* Status (static) */}
                  <div className="mt-4">
                    <div className="rounded-lg p-3 border border-white/10">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-300">Monitoring Network</span>
                        <div className="flex items-center space-x-2 text-green-400">
                          <div className="w-2 h-2 rounded-full bg-green-400"></div>
                          <span className="font-medium">Secure</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>{/* /card */}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===== FEATURES SECTION (full block uses the same gradient, independently) ===== */}
      <section className="bg-[linear-gradient(to_bottom,_#0a0a0a,_#032e30)]">
        <div className="py-20">
          <div className="container mx-auto max-w-7xl px-6 mb-16">
            <div className="text-center">
              <h2 className="text-4xl lg:text-5xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-300">
                AI-Powered Security Operations
              </h2>
              <p className="text-gray-300 text-xl max-w-3xl mx-auto">
                Experience next-generation cybersecurity with our intelligent SOC platform
              </p>
            </div>
          </div>

          <div className="space-y-24">
            {featureSteps.map((step, index) => {
              const IconComponent = step.icon;
              return (
                <div key={step.id} className="container mx-auto max-w-7xl px-6">
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                    {/* Text */}
                    <div className="flex flex-col justify-center space-y-6">
                      <div className="flex items-center space-x-4">
                        <IconComponent className="w-10 h-10 text-[hsl(210,40%,75%)]" />
                        <span className="text-sm text-[hsl(210,40%,75%)] font-mono px-3 py-1 rounded-full border border-white/10">
                          {String(index + 1).padStart(2, "0")} / {String(featureSteps.length).padStart(2, "0")}
                        </span>
                      </div>

                      <h3 className="text-3xl lg:text-4xl font-bold text-white">
                        {step.title}
                      </h3>

                      <p className="text-gray-300 text-lg leading-relaxed">
                        {step.description}
                      </p>

                      <div className="pt-2">
                        <CustomButton
                          title="Learn More"
                          onClick={() => {}}
                          className="px-5 py-2 text-sm"
                        />
                      </div>
                    </div>

                    {/* Visual: static image placeholder */}
                    <div className="w-full h-96 lg:h-[520px]">
                      <img
                        src={
                          index % 2 === 0
                            ? "/images/cyber-dashboard-1.jpg"
                            : "/images/cyber-dashboard-2.jpg"
                        }
                        alt={`${step.title} preview`}
                        className="w-full h-full object-cover rounded-2xl border border-white/10"
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </main>
  );
};

export default LandingPage;
