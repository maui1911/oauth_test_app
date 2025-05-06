import { OAuthService } from './oauthService';

export interface Connector {
  id: string;
  name: string;
  url: string;
  description?: string;
}

export interface PerformanceResult {
  connectorId: string;
  timestamp: number;
  duration: number; // in milliseconds
  success: boolean;
  error?: string;
  statusCode?: number;
}

export class PerformanceService {
  private static instance: PerformanceService;
  private connectors: Connector[] = [];
  private results: PerformanceResult[] = [];
  private oauthService: OAuthService;

  private constructor() {
    this.oauthService = OAuthService.getInstance();
    this.loadFromLocalStorage();
  }

  public static getInstance(): PerformanceService {
    if (!PerformanceService.instance) {
      PerformanceService.instance = new PerformanceService();
    }
    return PerformanceService.instance;
  }

  private loadFromLocalStorage(): void {
    const storedConnectors = localStorage.getItem('performance_connectors');
    const storedResults = localStorage.getItem('performance_results');
    
    if (storedConnectors) {
      this.connectors = JSON.parse(storedConnectors);
    }
    
    if (storedResults) {
      this.results = JSON.parse(storedResults);
    }
  }

  private saveToLocalStorage(): void {
    localStorage.setItem('performance_connectors', JSON.stringify(this.connectors));
    localStorage.setItem('performance_results', JSON.stringify(this.results));
  }

  public getConnectors(): Connector[] {
    return [...this.connectors];
  }

  public getConnectorById(id: string): Connector | undefined {
    return this.connectors.find(connector => connector.id === id);
  }

  public addConnector(connector: Omit<Connector, 'id'>): Connector {
    const newConnector = {
      ...connector,
      id: this.generateId()
    };

    this.connectors.push(newConnector);
    this.saveToLocalStorage();
    return newConnector;
  }

  public updateConnector(id: string, updates: Partial<Omit<Connector, 'id'>>): Connector | null {
    const index = this.connectors.findIndex(c => c.id === id);
    if (index === -1) return null;

    this.connectors[index] = { ...this.connectors[index], ...updates };
    this.saveToLocalStorage();
    return this.connectors[index];
  }

  public deleteConnector(id: string): boolean {
    const initialLength = this.connectors.length;
    this.connectors = this.connectors.filter(c => c.id !== id);
    
    // Also delete related results
    this.results = this.results.filter(r => r.connectorId !== id);
    
    this.saveToLocalStorage();
    return this.connectors.length < initialLength;
  }

  public getResults(filters?: { connectorId?: string, limit?: number }): PerformanceResult[] {
    let filteredResults = [...this.results];
    
    if (filters?.connectorId) {
      filteredResults = filteredResults.filter(r => r.connectorId === filters.connectorId);
    }
    
    // Sort by timestamp (newest first)
    filteredResults.sort((a, b) => b.timestamp - a.timestamp);
    
    if (filters?.limit) {
      filteredResults = filteredResults.slice(0, filters.limit);
    }
    
    return filteredResults;
  }

  public async testConnector(connectorId: string): Promise<PerformanceResult> {
    const connector = this.getConnectorById(connectorId);
    if (!connector) {
      throw new Error(`Connector with id ${connectorId} not found`);
    }

    const accessToken = this.oauthService.getAccessToken();
    if (!accessToken) {
      throw new Error('No access token available. Please authenticate first.');
    }

    const result: PerformanceResult = {
      connectorId,
      timestamp: Date.now(),
      duration: 0,
      success: false
    };

    try {
      const startTime = performance.now();
      
      const response = await fetch('/api/proxy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({ url: connector.url })
      });
      
      const endTime = performance.now();
      result.duration = endTime - startTime;
      result.statusCode = response.status;
      result.success = response.ok;
      
      if (!response.ok) {
        result.error = `HTTP Error: ${response.status} ${response.statusText}`;
      }
    } catch (error) {
      const endTime = performance.now();
      result.duration = endTime - performance.now();
      result.success = false;
      result.error = error instanceof Error ? error.message : 'Unknown error';
    }

    this.results.push(result);
    this.saveToLocalStorage();
    return result;
  }

  public async testAllConnectors(): Promise<PerformanceResult[]> {
    const results: PerformanceResult[] = [];
    
    for (const connector of this.connectors) {
      try {
        const result = await this.testConnector(connector.id);
        results.push(result);
      } catch (error) {
        results.push({
          connectorId: connector.id,
          timestamp: Date.now(),
          duration: 0,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
    
    return results;
  }

  public clearResults(connectorId?: string): void {
    if (connectorId) {
      this.results = this.results.filter(r => r.connectorId !== connectorId);
    } else {
      this.results = [];
    }
    this.saveToLocalStorage();
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }
}