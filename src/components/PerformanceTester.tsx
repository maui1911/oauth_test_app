import { useState, useEffect } from 'react';
import { PerformanceService, Connector, PerformanceResult } from '../services/performanceService';

export function PerformanceTester() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [results, setResults] = useState<PerformanceResult[]>([]);
  const [selectedConnectorId, setSelectedConnectorId] = useState<string | 'all'>('all');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const performanceService = PerformanceService.getInstance();

  // Load data on component mount
  useEffect(() => {
    loadData();
  }, []);

  const loadData = () => {
    const connectorList = performanceService.getConnectors();
    setConnectors(connectorList);
    
    // Load results for selected connector or all results
    const resultsList = performanceService.getResults(
      selectedConnectorId !== 'all' ? { connectorId: selectedConnectorId } : undefined
    );
    setResults(resultsList);
  };

  const handleConnectorChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const value = e.target.value;
    setSelectedConnectorId(value);
    
    // Update results based on selection
    const resultsList = performanceService.getResults(
      value !== 'all' ? { connectorId: value } : undefined
    );
    setResults(resultsList);
  };

  const handleTestConnector = async (connectorId: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await performanceService.testConnector(connectorId);
      loadData(); // Reload data to show new results
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to test connector');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestAllConnectors = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      await performanceService.testAllConnectors();
      loadData(); // Reload data to show new results
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to test connectors');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearResults = () => {
    if (selectedConnectorId !== 'all') {
      performanceService.clearResults(selectedConnectorId);
    } else {
      performanceService.clearResults();
    }
    loadData();
  };

  const formatTime = (timestamp: number): string => {
    return new Date(timestamp).toLocaleString();
  };

  const formatDuration = (duration: number): string => {
    if (duration < 1) {
      return '<1 ms';
    }
    if (duration < 1000) {
      return `${Math.round(duration)} ms`;
    }
    return `${(duration / 1000).toFixed(2)} s`;
  };

  const getConnectorName = (connectorId: string): string => {
    const connector = connectors.find(c => c.id === connectorId);
    return connector?.name || 'Unknown Connector';
  };

  const getStatusClass = (result: PerformanceResult): string => {
    if (!result.success) {
      return 'bg-red-100 text-red-800';
    }
    if (result.duration < 500) {
      return 'bg-green-100 text-green-800';
    }
    if (result.duration < 1000) {
      return 'bg-yellow-100 text-yellow-800';
    }
    return 'bg-orange-100 text-orange-800';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-medium text-gray-900">Performance Testing</h2>
        <div className="flex space-x-2">
          <select
            value={selectedConnectorId}
            onChange={handleConnectorChange}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            disabled={isLoading}
          >
            <option value="all">All Connectors</option>
            {connectors.map(connector => (
              <option key={connector.id} value={connector.id}>
                {connector.name}
              </option>
            ))}
          </select>
          <button
            onClick={handleTestAllConnectors}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
            disabled={isLoading || connectors.length === 0}
          >
            Test All
          </button>
          <button
            onClick={handleClearResults}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 disabled:opacity-50"
            disabled={isLoading || results.length === 0}
          >
            Clear Results
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-50 text-red-700 rounded-md">
          {error}
        </div>
      )}

      {connectors.length === 0 ? (
        <div className="p-4 bg-gray-50 text-gray-500 rounded-md text-center">
          No connectors available. Add connectors to start testing performance.
        </div>
      ) : (
        <div className="space-y-4">
          {selectedConnectorId === 'all' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {connectors.map(connector => (
                <div key={connector.id} className="bg-gray-50 p-4 rounded-md shadow-sm">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-md font-medium text-gray-900">{connector.name}</h3>
                    <button
                      onClick={() => handleTestConnector(connector.id)}
                      className="text-sm bg-blue-100 text-blue-700 px-3 py-1 rounded-md hover:bg-blue-200 disabled:opacity-50"
                      disabled={isLoading}
                    >
                      Test
                    </button>
                  </div>
                  <p className="text-sm text-gray-500 break-all mb-2">{connector.url}</p>
                  {connector.description && (
                    <p className="text-sm text-gray-600 mb-3">{connector.description}</p>
                  )}
                  
                  {/* Display latest result for this connector if exists */}
                  {performanceService.getResults({ connectorId: connector.id, limit: 1 }).map(result => (
                    <div 
                      key={result.timestamp} 
                      className={`text-sm p-2 rounded-md mt-2 ${getStatusClass(result)}`}
                    >
                      <div className="flex justify-between">
                        <span>Duration: {formatDuration(result.duration)}</span>
                        <span>{result.success ? 'Success' : 'Failed'}</span>
                      </div>
                      <div className="text-xs mt-1">
                        {formatTime(result.timestamp)}
                      </div>
                      {result.error && (
                        <div className="text-xs mt-1 text-red-700">
                          {result.error}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* Results table */}
          {results.length > 0 ? (
            <div className="mt-6">
              <h3 className="text-md font-medium text-gray-900 mb-2">Test Results</h3>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Connector
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Timestamp
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Duration
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Details
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {results.map((result) => (
                      <tr key={`${result.connectorId}-${result.timestamp}`}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {getConnectorName(result.connectorId)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatTime(result.timestamp)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatDuration(result.duration)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            result.success 
                              ? 'bg-green-100 text-green-800' 
                              : 'bg-red-100 text-red-800'
                          }`}>
                            {result.success ? 'Success' : 'Failed'}
                            {result.statusCode && ` (${result.statusCode})`}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {result.error && (
                            <span className="text-red-600">{result.error}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-4 bg-gray-50 text-gray-500 rounded-md text-center">
              No test results yet. Run tests to see results here.
            </div>
          )}
        </div>
      )}
    </div>
  );
}