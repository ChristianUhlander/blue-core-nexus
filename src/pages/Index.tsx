import { ModelConfiguration as ModelConfigComponent } from "@/components/ModelConfiguration";
import { ModelConfiguration } from "@/types/modelConfig";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { EnhancedAgenticPentestInterface } from "@/components/EnhancedAgenticPentestInterface";

const Index = () => {
  const [showConfig, setShowConfig] = useState(true);
  const [models, setModels] = useState<ModelConfiguration[]>([]);

  const handleModelsSaved = (savedModels: ModelConfiguration[]) => {
    setModels(savedModels);
    setShowConfig(false);
  };

  if (showConfig) {
    return (
      <div className="min-h-screen bg-background p-8">
        <ModelConfigComponent onSave={handleModelsSaved} initialModels={models} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="p-4 border-b bg-card flex items-center justify-between">
        <h1 className="text-2xl font-bold">OWASP Automated Pentest</h1>
        <Button variant="outline" onClick={() => setShowConfig(true)}>
          Configure Models
        </Button>
      </div>
      <EnhancedAgenticPentestInterface configuredModels={models} />
    </div>
  );
};

export default Index;
