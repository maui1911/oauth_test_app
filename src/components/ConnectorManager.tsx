import { useState, useEffect } from 'react';
import { PerformanceService, Connector } from '../services/performanceService';

interface ConnectorFormProps {
  connector?: Connector;
  onSave: () => void;
  onCancel: () => void;
}

function ConnectorForm({ connector, onSave, onCancel }: ConnectorFormProps) {
  const [name, setName] = useState(connector?.name || '');
  const [url, setUrl] = useState(connector?.url || '');
  const [description, setDescription] = useState(connector?.description || '');
  const [error, setError] = useState<string | null>(null);
  
  const performanceService = PerformanceService.getInstance();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    if (!url.trim()) {
      setError('URL is required');
      return;
    }

    try {
      new URL(url); // Validate URL format
    } catch {
      setError('Invalid URL format');
      return;
    }

    if (connector) {
      performanceService.updateConnector(connector.id, { name, url, description });
    } else {
      performanceService.addConnector({ name, url, description });
    }

    onSave();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4 bg-white p-4 rounded-md shadow">
      {error && (
        <div className="p-3 bg-red-50 text-red-700 rounded-md">
          {error}
        </div>
      )}
      <div>
        <label className="block text-sm font-medium text-gray-700">Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          placeholder="API Connector Name"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700">URL</label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          placeholder="https://api.example.com/resource"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700">Description (Optional)</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          placeholder="Brief description of this connector"
          rows={3}
        />
      </div>
      <div className="flex justify-end space-x-2">
        <button
          type="button"
          onClick={onCancel}
          className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
        >
          Cancel
        </button>
        <button
          type="submit"
          className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
        >
          {connector ? 'Update Connector' : 'Add Connector'}
        </button>
      </div>
    </form>
  );
}

export function ConnectorManager() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [selectedConnector, setSelectedConnector] = useState<Connector | null>(null);
  const [isFormOpen, setIsFormOpen] = useState(false);
  
  const performanceService = PerformanceService.getInstance();

  // Load connectors on component mount
  useEffect(() => {
    loadConnectors();
  }, []);

  const loadConnectors = () => {
    setConnectors(performanceService.getConnectors());
  };

  const handleAddConnector = () => {
    setSelectedConnector(null);
    setIsFormOpen(true);
  };

  const handleEditConnector = (connector: Connector) => {
    setSelectedConnector(connector);
    setIsFormOpen(true);
  };

  const handleDeleteConnector = (id: string) => {
    if (window.confirm('Are you sure you want to delete this connector?')) {
      performanceService.deleteConnector(id);
      loadConnectors();
    }
  };

  const handleFormSave = () => {
    setIsFormOpen(false);
    loadConnectors();
  };

  const handleFormCancel = () => {
    setIsFormOpen(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-medium text-gray-900">API Connectors</h2>
        <button
          onClick={handleAddConnector}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          Add Connector
        </button>
      </div>

      {isFormOpen && (
        <ConnectorForm
          connector={selectedConnector || undefined}
          onSave={handleFormSave}
          onCancel={handleFormCancel}
        />
      )}

      {connectors.length === 0 ? (
        <div className="p-4 bg-gray-50 text-gray-500 rounded-md text-center">
          No connectors added yet. Add a connector to start testing performance.
        </div>
      ) : (
        <div className="space-y-2">
          {connectors.map((connector) => (
            <div key={connector.id} className="bg-gray-50 p-4 rounded-md">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-md font-medium text-gray-900">{connector.name}</h3>
                  <p className="text-sm text-gray-500 break-all">{connector.url}</p>
                  {connector.description && (
                    <p className="text-sm text-gray-600 mt-1">{connector.description}</p>
                  )}
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleEditConnector(connector)}
                    className="text-sm bg-blue-100 text-blue-700 px-3 py-1 rounded-md hover:bg-blue-200"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDeleteConnector(connector.id)}
                    className="text-sm bg-red-100 text-red-700 px-3 py-1 rounded-md hover:bg-red-200"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}